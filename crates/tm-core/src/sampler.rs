//! Сборщик: каждый вызов `sample()` делает снимок и считает скорости
//! (ЦП %, ввод-вывод в байтах/с) относительно предыдущего снимка.

use std::collections::HashMap;
use std::io;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

use crate::handle::ProcHandle;
use crate::nt::{ProcessQuery, RawProc};
use crate::system::{self, CpuTimes, Memory};

/// Уникальный ключ процесса: PID + время создания (PID в Windows переиспользуются).
pub type ProcKey = (u32, i64);

/// Ключ, пришедший снаружи (из окна, от агента): время создания приводим к той же точности,
/// что и в замерах (см. `nt::js_safe`), — в JSON из JavaScript оно приходит в другой записи.
pub fn norm_key(k: ProcKey) -> ProcKey {
    (k.0, crate::nt::js_safe(k.1))
}

/// Строковый ключ «PID:время создания» в той же записи, что даёт JavaScript (`String(число)`).
pub fn key_str(k: ProcKey) -> String {
    format!("{}:{}", k.0, k.1 as f64)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcStat {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: i64,
    /// Загрузка ЦП в процентах от всей машины (как в диспетчере Windows).
    pub cpu: f32,
    /// Всего потрачено времени ЦП, мс.
    pub cpu_time_ms: u64,
    /// Частный рабочий набор, байты («Память» в диспетчере Windows).
    pub mem: u64,
    pub working_set: u64,
    pub private_bytes: u64,
    /// Чтение и запись (диск, сеть через файловые API, каналы), байт/с.
    pub io_read_bps: f64,
    pub io_write_bps: f64,
    pub threads: u32,
    pub handles: u32,
    pub session: u32,
    pub base_priority: i32,
    #[serde(default)]
    pub suspended: bool,
    /// Загрузка видеокарты, % (самый занятый движок); заполняет движок.
    #[serde(default)]
    pub gpu: f32,
    /// Выделенная видеопамять, байты.
    #[serde(default)]
    pub gpu_mem: u64,
    /// Сетевой трафик процесса, байт/с (только с правами администратора, иначе 0).
    #[serde(default)]
    pub net_rx_bps: f64,
    #[serde(default)]
    pub net_tx_bps: f64,
    /// Процесс родился после прошлого замера (его ЦП — всё время с момента запуска).
    #[serde(default)]
    pub born: bool,
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
    /// ЦП коротких процессов, которые родились и завершились между замерами и в списке
    /// не видны (git, grep, sh из скриптов): занятость машины минус сумма по видимым процессам,
    /// по завершившимся за интервал и по прерываниям с DPC.
    /// Движок раздаёт его приложениям, которые такие процессы запускают (`AppStat::short_cpu`);
    /// здесь — остаток, который отнести некому.
    #[serde(default)]
    pub unseen_cpu: f32,
    /// Сколько процессов в секунду запускается (замеченных живыми), сглажено.
    #[serde(default)]
    pub spawn_rate: f32,
    /// Загрузка ЦП обработкой аппаратных прерываний, % — ни одному процессу не принадлежит;
    /// видна и строкой-псевдопроцессом в списке.
    #[serde(default)]
    pub interrupt_cpu: f32,
    /// То же для отложенных вызовов процедур (DPC).
    #[serde(default)]
    pub dpc_cpu: f32,
    /// ЦП считается по тактам процессора (как в System Informer), а не по тикам таймера.
    #[serde(default)]
    pub by_cycles: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    /// Время замера, мс Unix.
    pub at_ms: u64,
    /// Интервал до предыдущего замера, мс (0 — первый замер, скорости ещё не посчитаны).
    pub interval_ms: f64,
    pub system: SystemStat,
    pub procs: Vec<ProcStat>,
    /// Процессы, завершившиеся за интервал, с ЦП за их последние мгновения — дочитано по
    /// удерживаемому дескриптору. В `procs` их уже нет; движок относит этот ЦП их приложениям.
    #[serde(default)]
    pub exited: Vec<ProcStat>,
}

/// Псевдопроцессы, как у System Informer: прерывания и DPC. PID вне диапазона настоящих.
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
    /// Для строки завершившегося процесса.
    name: String,
    ppid: u32,
}

/// Счётчики чтения и записи: диск из расширения записи процесса, иначе общий ввод-вывод.
fn io_of(r: &RawProc) -> (u64, u64) {
    r.disk.unwrap_or((r.io_read, r.io_write))
}

/// Процессорные счётчики прошлого замера.
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
    /// Дескрипторы живых процессов: после завершения процесса по дескриптору ещё можно
    /// дочитать его итоговое время ЦП (так делает System Informer).
    handles: HashMap<ProcKey, ProcHandle>,
    prev_at: Option<Instant>,
    prev_cpu: Option<Cpu>,
    /// Время прошлого замера (FILETIME): кто создан позже — родился между замерами.
    prev_ft: i64,
    ncpu: u32,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

/// Итоговые время ЦП (100 нс) и такты процесса — работает и после его завершения.
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

/// Приращения одного процесса за интервал.
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
        // время ЦП в 100 нс, доступное всем ядрам за интервал
        let cpu_budget = dt * 1e7 * self.ncpu as f64;

        // 1. приращения по живым процессам: такты, время, диск
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
                // родился между замерами: всё его время ЦП потрачено за этот интервал
                // (раньше первый замер давал 0 — сборка из сотни коротких javac и git была невидима)
                None if born => Delta { cycles: r.cycle_time, time: r.cpu_time.max(0), rd: rd_now as f64 / dt, wr: wr_now as f64 / dt, born },
                _ => Delta { cycles: 0, time: 0, rd: 0.0, wr: 0.0, born },
            });
            next.insert(key, Prev { cpu_time: r.cpu_time, cycles: r.cycle_time, io_read: rd_now, io_write: wr_now, name: r.name.clone(), ppid: r.ppid });
            if r.pid != 0 && r.pid != 4 && !self.handles.contains_key(&key) {
                if let Ok(h) = ProcHandle::open(r.pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(r.create_time)) {
                    self.handles.insert(key, h);
                }
            }
        }

        // 2. завершившиеся за интервал: итог по дескриптору минус прошлый замер
        let mut gone: Vec<(&Prev, ProcKey, u64, i64)> = Vec::new();
        for (key, p) in &self.prev {
            if next.contains_key(key) {
                continue;
            }
            if let Some((time, cycles)) = self.handles.get(key).and_then(final_counters) {
                gone.push((p, *key, cycles.saturating_sub(p.cycles), (time - p.cpu_time).max(0)));
            }
        }

        // 3. знаменатель по тактам — сумма приращений всех процессов (и завершившихся), простоя
        //    и прерываний с DPC: способ System Informer, он не ломается, когда процессы завершаются
        let prev_cpu = self.prev_cpu;
        let cyc = prev_cpu.and_then(|p| {
            let idle = cpu_now.idle_cycles?.checked_sub(p.idle_cycles?)?;
            let sys = cpu_now.sys_cycles?.checked_sub(p.sys_cycles?)?;
            let procs: u64 = deltas.iter().map(|d| d.cycles).sum::<u64>() + gone.iter().map(|g| g.2).sum::<u64>();
            let total = procs + idle + sys;
            // на виртуальных машинах без счётчика тактов простой = 0 — тогда по времени
            (dt > 0.0 && idle > 0 && total > 0).then_some((total as f64, idle as f64, sys as f64))
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
            .map(|&(p, key, cycles, time)| ProcStat { ppid: p.ppid, create_time: key.1, cpu: share(cycles, time), ..blank(key.0, &p.name) })
            .collect();

        // 4. прерывания и DPC (класс 8). По тактам известна их общая доля (класс 108) —
        //    делим её в пропорции времени; без тактов — просто доли времени
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
        // дескрипторы завершившихся больше не нужны
        self.handles.retain(|k, _| next.contains_key(k));
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

/// Пустая строка процесса: основа для псевдопроцессов и завершившихся.
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
        net_rx_bps: 0.0,
        net_tx_bps: 0.0,
        born: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_survive_javascript() {
        // FILETIME ~1,3e17 больше 2^53: JavaScript хранит его приближённо и пишет по-своему
        let raw = 134_348_367_698_375_941i64;
        let ct = crate::nt::js_safe(raw);
        assert_eq!(ct, 134_348_367_698_375_936); // так значение хранится в замере
        assert_eq!(key_str((7, ct)), "7:134348367698375940"); // так его покажет String(ct) в JS
        // обратно из JS приходит запись «…940» — ключ совпадает с замером
        assert_eq!(norm_key((7, 134_348_367_698_375_940)), (7, ct));
        assert_eq!(crate::nt::js_safe(ct), ct);
    }
}
