//! The sampler: every `sample()` call takes a snapshot and computes rates
//! (CPU %, I/O in bytes/s) relative to the previous snapshot.

use std::collections::HashMap;
use std::io;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

use crate::handle::ProcHandle;
use crate::nt::{ProcessQuery, RawProc};
use crate::system::{self, CpuTimes, Memory};

/// A unique process key: PID + creation time (PIDs are reused in Windows).
pub type ProcKey = (u32, i64);

/// A key that came from outside (from the window, from an agent): the creation time is brought to the same precision
/// as in the samples (see `nt::js_safe`) — in JSON from JavaScript it arrives in a different notation.
pub fn norm_key(k: ProcKey) -> ProcKey {
    (k.0, crate::nt::js_safe(k.1))
}

/// The string key “PID:creation time” in the same notation JavaScript produces (`String(number)`).
pub fn key_str(k: ProcKey) -> String {
    format!("{}:{}", k.0, k.1 as f64)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcStat {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: i64,
    /// CPU load in percent of the whole machine (as in the Windows Task Manager).
    pub cpu: f32,
    /// Total CPU time spent, ms.
    pub cpu_time_ms: u64,
    /// The private working set, bytes (“Memory” in the Windows Task Manager).
    pub mem: u64,
    pub working_set: u64,
    pub private_bytes: u64,
    /// Read and write (disk, network through file APIs, pipes), bytes/s.
    pub io_read_bps: f64,
    pub io_write_bps: f64,
    pub threads: u32,
    pub handles: u32,
    pub session: u32,
    pub base_priority: i32,
    #[serde(default)]
    pub suspended: bool,
    /// GPU load, % (the busiest engine); filled in by the engine.
    #[serde(default)]
    pub gpu: f32,
    /// Dedicated video memory, bytes.
    #[serde(default)]
    pub gpu_mem: u64,
    /// Load per GPU (key — as in `GpuStat::key`), only where it is non-zero:
    /// one program may draw on the integrated GPU and compute on the discrete one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpu_by: Vec<GpuShare>,
    /// Network traffic of the process, bytes/s (only with administrator rights, otherwise 0).
    #[serde(default)]
    pub net_rx_bps: f64,
    #[serde(default)]
    pub net_tx_bps: f64,
    /// The same traffic by adapter (key — as in `NetStat::key`; empty — adapter unknown):
    /// a program through a VPN and the VPN client itself, encrypting its traffic for Wi-Fi, are on different adapters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net_by: Vec<NetShare>,
    /// The process was born after the previous sample (its CPU is all the time since it started).
    #[serde(default)]
    pub born: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GpuShare {
    pub key: String,
    pub util: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetShare {
    pub key: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

impl ProcStat {
    pub fn key(&self) -> ProcKey {
        (self.pid, self.create_time)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemStat {
    pub cpu: f32,
    pub logical_cpus: u32,
    pub memory: Memory,
    pub processes: usize,
    pub threads: u64,
    pub handles: u64,
    pub uptime_ms: u64,
    /// CPU of short-lived processes that were born and exited between samples and are not visible
    /// in the list (git, grep, sh from scripts): machine load minus the sum over visible processes,
    /// over those that exited during the interval and over interrupts with DPC.
    /// The engine hands it to the apps that start such processes (`AppStat::short_cpu`);
    /// here is the remainder that cannot be attributed to anyone.
    #[serde(default)]
    pub unseen_cpu: f32,
    /// How many processes are started per second (noticed alive), smoothed.
    #[serde(default)]
    pub spawn_rate: f32,
    /// CPU load from hardware interrupt handling, % — belongs to no process;
    /// also visible as a pseudo-process row in the list.
    #[serde(default)]
    pub interrupt_cpu: f32,
    /// The same for deferred procedure calls (DPC).
    #[serde(default)]
    pub dpc_cpu: f32,
    /// CPU is computed from processor cycles (as in System Informer), not from timer ticks.
    #[serde(default)]
    pub by_cycles: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    /// Sample time, Unix ms.
    pub at_ms: u64,
    /// The interval since the previous sample, ms (0 — the first sample, rates not computed yet).
    pub interval_ms: f64,
    pub system: SystemStat,
    pub procs: Vec<ProcStat>,
    /// Processes that exited during the interval, with the CPU of their last moments — read through
    /// the held handle. They are no longer in `procs`; the engine attributes this CPU to their apps.
    #[serde(default)]
    pub exited: Vec<ProcStat>,
}

/// Pseudo-processes, as in System Informer: interrupts and DPC. PIDs outside the range of real ones.
pub const INTERRUPTS_PID: u32 = u32::MAX - 2;
pub const DPC_PID: u32 = u32::MAX - 1;

pub fn is_pseudo(pid: u32) -> bool {
    pid == INTERRUPTS_PID || pid == DPC_PID
}

#[derive(Clone)]
struct Prev {
    cpu_time: i64,
    cycles: u64,
    io_read: u64,
    io_write: u64,
    /// For the row of an exited process.
    name: String,
    ppid: u32,
    mem: u64,
}

/// Read and write counters: disk from the process record extension, otherwise the general I/O.
fn io_of(r: &RawProc) -> (u64, u64) {
    r.disk.unwrap_or((r.io_read, r.io_write))
}

/// Processor counters of the previous sample.
#[derive(Clone, Copy)]
struct Cpu {
    times: CpuTimes,
    perf: Option<crate::nt::CpuPerf>,
    idle_cycles: Option<u64>,
    sys_cycles: Option<u64>,
}

pub struct Sampler {
    query: ProcessQuery,
    raw: Vec<RawProc>,
    prev: HashMap<ProcKey, Prev>,
    /// Handles of live processes: after a process exits, its final CPU time can still be read
    /// through the handle (System Informer does this).
    handles: HashMap<ProcKey, ProcHandle>,
    prev_at: Option<Instant>,
    prev_cpu: Option<Cpu>,
    /// The time of the previous sample (FILETIME): whoever was created later was born between samples.
    prev_ft: i64,
    ncpu: u32,
    /// Processor groups: with several of them classes 83 and 108 do not see all processors — compute by time.
    groups: u16,
    /// Processes that cannot be opened (no rights): do not retry every second.
    denied: std::collections::HashSet<ProcKey>,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

/// The final CPU time (100 ns) and cycles of a process — works after it exits too.
fn final_counters(h: &ProcHandle) -> Option<(i64, u64)> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    use windows_sys::Win32::System::WindowsProgramming::QueryProcessCycleTime;
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    if unsafe { GetProcessTimes(h.raw(), &mut c, &mut e, &mut k, &mut u) } == 0 {
        return None;
    }
    let ft = |f: FILETIME| ((f.dwHighDateTime as i64) << 32) | f.dwLowDateTime as i64;
    let mut cycles = 0u64;
    if unsafe { QueryProcessCycleTime(h.raw(), &mut cycles) } == 0 {
        return None;
    }
    Some((ft(k) + ft(u), cycles))
}

/// Increments of one process over the interval.
struct Delta {
    cycles: u64,
    time: i64,
    rd: f64,
    wr: f64,
    born: bool,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            query: ProcessQuery::default(),
            raw: Vec::with_capacity(512),
            prev: HashMap::with_capacity(512),
            handles: HashMap::with_capacity(512),
            prev_at: None,
            prev_cpu: None,
            prev_ft: i64::MAX,
            ncpu: system::logical_cpus(),
            groups: unsafe { windows_sys::Win32::System::Threading::GetActiveProcessorGroupCount() },
            denied: std::collections::HashSet::new(),
        }
    }

    pub fn sample(&mut self) -> io::Result<Frame> {
        let now = Instant::now();
        let cpu_now = Cpu {
            times: system::cpu_times(),
            perf: crate::nt::cpu_perf(self.ncpu),
            idle_cycles: crate::nt::idle_cycles(self.ncpu),
            sys_cycles: crate::nt::system_cycles(self.ncpu),
        };
        let ft_now = system::filetime_now();
        self.query.snapshot(&mut self.raw)?;

        let dt = self.prev_at.map(|p| now.duration_since(p).as_secs_f64()).unwrap_or(0.0);
        // CPU time in 100 ns available to all cores over the interval
        let cpu_budget = dt * 1e7 * self.ncpu as f64;

        // 1. increments of live processes: cycles, time, disk
        let mut deltas = Vec::with_capacity(self.raw.len());
        let mut next = HashMap::with_capacity(self.raw.len());
        for r in &self.raw {
            let key = (r.pid, r.create_time);
            let prev = self.prev.get(&key);
            let (rd_now, wr_now) = io_of(r);
            let born = prev.is_none() && dt > 0.0 && r.create_time >= self.prev_ft;
            deltas.push(match prev {
                Some(p) if dt > 0.0 => Delta {
                    cycles: r.cycle_time.saturating_sub(p.cycles),
                    time: (r.cpu_time - p.cpu_time).max(0),
                    rd: rd_now.saturating_sub(p.io_read) as f64 / dt,
                    wr: wr_now.saturating_sub(p.io_write) as f64 / dt,
                    born,
                },
                // born between samples: all its CPU time was spent in this interval
                // (previously the first sample gave 0 — a build of a hundred short javac and git runs was invisible)
                None if born => Delta { cycles: r.cycle_time, time: r.cpu_time.max(0), rd: rd_now as f64 / dt, wr: wr_now as f64 / dt, born },
                _ => Delta { cycles: 0, time: 0, rd: 0.0, wr: 0.0, born },
            });
            next.insert(key, Prev { cpu_time: r.cpu_time, cycles: r.cycle_time, io_read: rd_now, io_write: wr_now, name: r.name.clone(), ppid: r.ppid, mem: r.ws_private });
            if r.pid != 0 && r.pid != 4 && !self.handles.contains_key(&key) && !self.denied.contains(&key) {
                match ProcHandle::open(r.pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(r.create_time)) {
                    Ok(h) => {
                        self.handles.insert(key, h);
                    }
                    Err(_) => {
                        self.denied.insert(key);
                    }
                }
            }
        }

        // 2. exited during the interval: the final value by handle minus the previous sample
        let mut gone: Vec<(&Prev, ProcKey, u64, i64)> = Vec::new();
        for (key, p) in &self.prev {
            if next.contains_key(key) {
                continue;
            }
            if let Some((time, cycles)) = self.handles.get(key).and_then(final_counters) {
                gone.push((p, *key, cycles.saturating_sub(p.cycles), (time - p.cpu_time).max(0)));
            }
        }

        // 3. the denominator by cycles — the sum of increments of all processes (including exited ones), idle
        //    and interrupts with DPC: System Informer’s method, it does not break when processes exit
        let prev_cpu = self.prev_cpu;
        let cyc = prev_cpu.and_then(|p| {
            let idle = cpu_now.idle_cycles?.checked_sub(p.idle_cycles?)?;
            let sys = cpu_now.sys_cycles?.checked_sub(p.sys_cycles?)?;
            // PID 0 (“System Idle Process”) in class 5 carries the same idle cycles as class 83 —
            // take them once, from class 83 (otherwise the denominator = busy + 2 × idle)
            let procs: u64 = self.raw.iter().zip(&deltas).filter(|(r, _)| r.pid != 0).map(|(_, d)| d.cycles).sum::<u64>() + gone.iter().map(|g| g.2).sum::<u64>();
            let total = procs + idle + sys;
            // on virtual machines without a cycle counter idle = 0 — then by time;
            // the same with several processor groups (more than 64 logical)
            (dt > 0.0 && idle > 0 && total > 0 && self.groups <= 1).then_some((total as f64, idle as f64, sys as f64))
        });
        let share = |cycles: u64, time: i64| -> f32 {
            let v = match cyc {
                Some((total, _, _)) => cycles as f64 / total * 100.0,
                None if cpu_budget > 0.0 => time as f64 / cpu_budget * 100.0,
                None => 0.0,
            };
            (v as f32).clamp(0.0, 100.0)
        };

        let mut procs = Vec::with_capacity(self.raw.len() + 2);
        let (mut threads, mut handles) = (0u64, 0u64);
        for (r, d) in self.raw.iter().zip(&deltas) {
            threads += r.threads as u64;
            handles += r.handles as u64;
            procs.push(ProcStat {
                pid: r.pid,
                ppid: r.ppid,
                name: r.name.clone(),
                create_time: r.create_time,
                cpu: if r.pid == 0 { 0.0 } else { share(d.cycles, d.time) },
                cpu_time_ms: (r.cpu_time / 10_000) as u64,
                mem: r.ws_private,
                working_set: r.working_set,
                private_bytes: r.private_bytes,
                io_read_bps: d.rd,
                io_write_bps: d.wr,
                threads: r.threads,
                handles: r.handles,
                session: r.session,
                base_priority: r.base_priority,
                suspended: r.suspended,
                born: d.born,
                ..blank(r.pid, "")
            });
        }
        let exited: Vec<ProcStat> = gone
            .iter()
            .map(|&(p, key, cycles, time)| ProcStat { ppid: p.ppid, create_time: key.1, cpu: share(cycles, time), mem: p.mem, ..blank(key.0, &p.name) })
            .collect();

        // 4. interrupts and DPC (class 8). By cycles their total share is known (class 108) —
        //    split it in proportion to time; without cycles — just time shares
        let (mut isr, mut dpc) = (0.0f32, 0.0f32);
        if let (Some(p), Some(n)) = (prev_cpu.and_then(|p| p.perf), cpu_now.perf) {
            let dpc_t = n.dpc.saturating_sub(p.dpc) as f64;
            let isr_t = n.interrupt.saturating_sub(p.interrupt) as f64;
            let all_t = (n.kernel + n.user).saturating_sub(p.kernel + p.user) as f64;
            match cyc {
                Some((total, _, sys)) => {
                    let both = sys / total * 100.0;
                    let k = if dpc_t + isr_t > 0.0 { dpc_t / (dpc_t + isr_t) } else { 0.5 };
                    dpc = (both * k) as f32;
                    isr = (both * (1.0 - k)) as f32;
                }
                None if all_t > 0.0 => {
                    dpc = (dpc_t / all_t * 100.0) as f32;
                    isr = (isr_t / all_t * 100.0) as f32;
                }
                None => {}
            }
        }
        let (isr, dpc) = (isr.clamp(0.0, 100.0), dpc.clamp(0.0, 100.0));
        procs.push(ProcStat { cpu: isr, ..blank(INTERRUPTS_PID, "Interrupts") });
        procs.push(ProcStat { cpu: dpc, ..blank(DPC_PID, "DPCs") });

        let sys_cpu = match (cyc, prev_cpu) {
            (Some((total, idle, _)), _) => ((1.0 - idle / total) * 100.0).clamp(0.0, 100.0) as f32,
            (None, Some(p)) => system::cpu_busy(p.times, cpu_now.times),
            _ => 0.0,
        };
        // handles of exited processes are no longer needed
        self.handles.retain(|k, _| next.contains_key(k));
        self.denied.retain(|k| next.contains_key(k));
        self.prev = next;
        self.prev_at = Some(now);
        self.prev_cpu = Some(cpu_now);
        self.prev_ft = ft_now;

        Ok(Frame {
            at_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
            interval_ms: dt * 1000.0,
            system: SystemStat {
                cpu: sys_cpu,
                logical_cpus: self.ncpu,
                memory: system::memory(),
                processes: procs.iter().filter(|p| p.pid != 0 && !is_pseudo(p.pid)).count(),
                threads,
                handles,
                uptime_ms: system::uptime_ms(),
                unseen_cpu: 0.0,
                spawn_rate: 0.0,
                interrupt_cpu: isr,
                dpc_cpu: dpc,
                by_cycles: cyc.is_some(),
            },
            procs,
            exited,
        })
    }
}

/// An empty process row: the base for pseudo-processes and exited ones.
fn blank(pid: u32, name: &str) -> ProcStat {
    ProcStat {
        pid,
        ppid: 0,
        name: name.to_string(),
        create_time: 0,
        cpu: 0.0,
        cpu_time_ms: 0,
        mem: 0,
        working_set: 0,
        private_bytes: 0,
        io_read_bps: 0.0,
        io_write_bps: 0.0,
        threads: 0,
        handles: 0,
        session: 0,
        base_priority: 0,
        suspended: false,
        gpu: 0.0,
        gpu_mem: 0,
        gpu_by: Vec::new(),
        net_rx_bps: 0.0,
        net_tx_bps: 0.0,
        net_by: Vec::new(),
        born: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_survive_javascript() {
        // FILETIME ~1.3e17 is above 2^53: JavaScript stores it approximately and prints it its own way
        let raw = 134_348_367_698_375_941i64;
        let ct = crate::nt::js_safe(raw);
        assert_eq!(ct, 134_348_367_698_375_936); // this is how the value is stored in the sample
        assert_eq!(key_str((7, ct)), "7:134348367698375940"); // this is how String(ct) shows it in JS
        // the notation “…940” comes back from JS — the key matches the sample
        assert_eq!(norm_key((7, 134_348_367_698_375_940)), (7, ct));
        assert_eq!(crate::nt::js_safe(ct), ct);
    }
}
