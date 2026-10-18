//! The engine: a background sampler once a second, a day of history and a problem watcher.
//! One instance per machine — the app starts it (or `tm daemon`),
//! and the window, the CLI and other clients get the data through `Service`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL};

use crate::history::{AppSample, History, HistoryResult, Metric, ProcSample, Pt, Query};
use crate::gpu::{GpuSampler, GpuStat};
use crate::net::{NetSampler, NetStat};
use crate::watch::{Event, Issue, Watch};
use crate::{apps, AppStat, Frame, InfoCache, ProcKey, Sampler, Tree};

/// Everything known about the last sample. Cheap to clone (reference counts only).
#[derive(Clone)]
pub struct Snapshot {
    /// Sample number: grows by 1 every second.
    pub seq: u64,
    pub frame: Arc<Frame>,
    /// Apps — with their names already resolved.
    pub apps: Arc<Vec<AppStat>>,
    pub nets: Arc<Vec<NetStat>>,
    /// GPUs (empty if there are no counters).
    pub gpus: Arc<Vec<GpuStat>>,
    /// Whether per-process traffic is available (needs administrator rights).
    pub net_per_process: bool,
    /// Kernel, cache and driver memory — what is in use but does not belong to processes.
    pub mem_detail: crate::sysmem::MemDetail,
    pub issues: Arc<Vec<Issue>>,
    /// Kernel pool alarms: driver leaks, token build-up, zombie processes.
    pub pool_alerts: Arc<Vec<crate::pool::PoolAlert>>,
}

struct State {
    latest: Option<Snapshot>,
    history: History,
    watch: Watch,
    pool: crate::pool::PoolWatch,
    samples: u64,
    cost_avg_ms: f64,
    cost_max_ms: f64,
    /// How much of a sample goes to the GPUs (PDH counters), ms, moving average.
    gpu_cost_ms: f64,
    error: Option<String>,
}

struct Inner {
    state: Mutex<State>,
    fresh: Condvar,
    stop: AtomicBool,
    started_ms: u64,
    interval: Duration,
    /// Where to save the history; `None` — do not save.
    store: Option<PathBuf>,
    /// Serialises file writes: the periodic save and the save on exit will not overlap.
    save_lock: Mutex<()>,
    /// false — the history is only read from disk, never written (a second instance, development mode).
    persist: bool,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

/// The default history file: %LOCALAPPDATA%\tm\history.bin.
pub fn default_store() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("tm").join("history.bin"))
}

const SAVE_EVERY: Duration = Duration::from_secs(600);

pub fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Engine {
    /// Starts the sampler. The history is picked up from `store` if the file exists and fits.
    pub fn start(interval: Duration, store: Option<PathBuf>) -> Self {
        Self::start_with(interval, store, true)
    }

    /// Like `start`, but only reads the history from disk: the main engine’s file is not overwritten.
    pub fn start_readonly(interval: Duration, store: Option<PathBuf>) -> Self {
        Self::start_with(interval, store, false)
    }

    fn start_with(interval: Duration, store: Option<PathBuf>, persist: bool) -> Self {
        let history = store
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| History::load(&b))
            .unwrap_or_default();
        let inner = Arc::new(Inner {
            state: Mutex::new(State {
                latest: None,
                history,
                watch: Watch::default(),
                pool: Default::default(),
                samples: 0,
                cost_avg_ms: 0.0,
                cost_max_ms: 0.0,
                gpu_cost_ms: 0.0,
                error: None,
            }),
            fresh: Condvar::new(),
            stop: AtomicBool::new(false),
            started_ms: wall_ms(),
            interval,
            store,
            save_lock: Mutex::new(()),
            persist,
        });
        let worker = inner.clone();
        std::thread::Builder::new()
            .name("tm-sampler".into())
            .spawn(move || run(&worker))
            .expect("could not start the sampler thread");
        Self { inner }
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
    }

    pub fn interval(&self) -> Duration {
        self.inner.interval
    }

    /// Writes the history to disk: first to a temporary file, then an atomic replace.
    pub fn save(&self) -> std::io::Result<()> {
        save(&self.inner)
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.inner.state.lock().unwrap().latest.clone()
    }

    /// Waits for a sample newer than `after` no longer than `timeout`. Returns at once if it is already there.
    pub fn wait_newer(&self, after: u64, timeout: Duration) -> Option<Snapshot> {
        let deadline = Instant::now() + timeout;
        let mut st = self.inner.state.lock().unwrap();
        loop {
            if let Some(s) = &st.latest {
                if s.seq > after {
                    return Some(s.clone());
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return st.latest.clone();
            }
            st = self.inner.fresh.wait_timeout(st, deadline - now).unwrap().0;
        }
    }

    pub fn history(&self, q: &Query) -> HistoryResult {
        self.inner.state.lock().unwrap().history.query(q)
    }

    /// Per-second series (up to 5 min) for process groups — one sum per group.
    pub fn procs_t0(&self, groups: &[Vec<ProcKey>], m: Metric, points: usize) -> Vec<Vec<f64>> {
        let st = self.inner.state.lock().unwrap();
        groups.iter().map(|g| st.history.procs_t0(g, m, points)).collect()
    }

    /// Kernel pool by tag: sizes, growth rate, alarms.
    pub fn pool_report(&self, n: usize, by: &str) -> crate::pool::PoolReport {
        self.inner.state.lock().unwrap().pool.report(n, by)
    }

    /// Tags the engine watches (for finding drivers).
    pub fn pool_tracked(&self) -> Vec<u32> {
        self.inner.state.lock().unwrap().pool.tracked()
    }

    pub fn events_after(&self, after: u64) -> Vec<Event> {
        self.inner.state.lock().unwrap().watch.events_after(after)
    }

    /// A log entry (for example, about a user action).
    pub fn log(&self, level: &str, text: String, who: Option<ProcKey>) {
        self.inner.state.lock().unwrap().watch.log(wall_ms(), level, text, who);
    }

    pub fn status(&self) -> Value {
        let st = self.inner.state.lock().unwrap();
        let me = unsafe { GetCurrentProcessId() };
        let own = st.latest.as_ref().and_then(|s| s.frame.procs.iter().find(|p| p.pid == me).cloned());
        json!({
            "pid": me,
            "started_ms": self.inner.started_ms,
            "uptime_ms": wall_ms().saturating_sub(self.inner.started_ms),
            "interval_ms": self.inner.interval.as_millis() as u64,
            "samples": st.samples,
            "sample_cost_avg_ms": st.cost_avg_ms,
            "sample_cost_max_ms": st.cost_max_ms,
            "gpu_cost_avg_ms": st.gpu_cost_ms,
            "own_cpu": own.as_ref().map(|p| p.cpu),
            "own_mem": own.as_ref().map(|p| p.mem),
            "history": st.history.stats(),
            "history_since_ms": st.history.first_ms(),
            "store": self.inner.store.as_ref().map(|p| p.display().to_string()),
            "elevated": crate::system::is_elevated(),
            "error": st.error,
        })
    }
}

fn pt(cpu: f32, gpu: f32, mem: u64, rd: f64, wr: f64) -> Pt {
    Pt { cpu, cpu_max: cpu, gpu, mem, rd: rd as f32, wr: wr as f32 }
}

fn run(inner: &Inner) {
    // above normal: the chart does not freeze even when the CPU is at 100 %
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) };
    let mut sampler = Sampler::new();
    let mut nets = NetSampler::default();
    let mut gpu = GpuSampler::new();
    // the ETW session is shared by the whole system: a second instance (development mode) does not touch it,
    // otherwise it would take over or stop the main app’s session
    let etw = if inner.persist { crate::net_etw::NetEtw::start() } else { None };
    let mut sysmem = crate::sysmem::MemSampler::new();
    let mut info = InfoCache::default();
    let mut lineage = apps::Lineage::default();
    let mut spawns = apps::Spawns::default();
    // process → app from the previous sample: the CPU of an exited process goes to its app
    let mut prev_app: HashMap<ProcKey, String> = HashMap::new();
    let _ = sampler.sample(); // the first sample is only the baseline for rates
    nets.sample();
    // history time: a monotonic clock anchored to the wall clock at start (clock changes do not break the rings)
    let t0 = Instant::now();
    let wall0 = wall_ms();
    let mut next = Instant::now() + inner.interval;
    let mut last_save = Instant::now();
    let mut pool_due = true;
    let mut last_hist: Option<u64> = None;

    while !inner.stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        }
        // after sleep or a hang, do not try to “catch up” with missed ticks
        next = (next + inner.interval).max(Instant::now());

        let t = Instant::now();
        let mut frame = match sampler.sample() {
            Ok(f) => f,
            Err(e) => {
                let msg = e.to_string();
                // into the log — only a new error, not the same one every second; the file write is
                // outside the state lock, so readers are not delayed
                let new = {
                    let mut st = inner.state.lock().unwrap();
                    let new = st.error.as_deref() != Some(msg.as_str());
                    st.error = Some(msg.clone());
                    new
                };
                if new {
                    crate::logs::error(format!("sample: {msg}"));
                }
                continue;
            }
        };
        let net = nets.sample();
        let tg = Instant::now();
        let g = gpu.as_mut().map(GpuSampler::sample).unwrap_or_default();
        let gpu_cost = tg.elapsed().as_secs_f64() * 1000.0;
        for p in frame.procs.iter_mut() {
            if let Some(x) = g.procs.get(&p.pid) {
                p.gpu = x.util;
                p.gpu_mem = x.mem;
                p.gpu_by = x.by.iter().map(|(k, u)| crate::sampler::GpuShare { key: k.clone(), util: *u }).collect();
            }
        }
        if let Some(e) = &etw {
            let dt = (frame.interval_ms / 1000.0).max(0.001);
            // the packet’s local address (source when sending, destination when receiving — check both) → adapter
            let addrs = nets.addresses();
            let mut per: HashMap<u32, HashMap<&str, (u64, u64)>> = HashMap::new();
            let bytes = e.take();
            for (&(pid, s, d), &(rx, tx)) in &bytes {
                let key = addrs.get(&s).or_else(|| addrs.get(&d)).map_or("", String::as_str);
                let e = per.entry(pid).or_default().entry(key).or_default();
                e.0 += rx;
                e.1 += tx;
            }
            for p in frame.procs.iter_mut() {
                if let Some(m) = per.get(&p.pid) {
                    let (rx, tx) = m.values().fold((0, 0), |a, v| (a.0 + v.0, a.1 + v.1));
                    p.net_rx_bps = rx as f64 / dt;
                    p.net_tx_bps = tx as f64 / dt;
                    p.net_by = m
                        .iter()
                        .map(|(k, v)| crate::sampler::NetShare { key: k.to_string(), rx_bps: v.0 as f64 / dt, tx_bps: v.1 as f64 / dt })
                        .collect();
                }
            }
        }
        let sys_gpu = g.adapters.iter().map(|a| a.util).fold(0.0f32, f32::max);
        let tree = Tree::build(&frame.procs);
        let mut groups = apps::group_with(&frame.procs, &tree, &mut info, Some(&mut lineage));
        lineage.update(&frame.procs, &groups, wall_ms());
        let mut exited_cpu = 0.0f32;
        for e in &frame.exited {
            exited_cpu += e.cpu;
            // the app is gone (its last process exited) — its CPU is counted in the system, but not in the groups
            if let Some(g) = prev_app.get(&e.key()).and_then(|k| groups.iter_mut().find(|g| &g.key == k)) {
                g.cpu += e.cpu;
            }
        }
        spawns.apply(&frame.procs, &mut groups, &mut frame.system, frame.interval_ms / 1000.0, exited_cpu);
        prev_app = groups.iter().flat_map(|g| g.members.iter().map(|&i| (frame.procs[i].key(), g.key.clone()))).collect();
        let alive: Vec<ProcKey> = frame.procs.iter().map(|p| p.key()).collect();
        info.retain_alive(alive.iter());

        let sys = pt(
            frame.system.cpu,
            sys_gpu,
            frame.system.memory.used,
            frame.procs.iter().map(|p| p.io_read_bps).sum(),
            frame.procs.iter().map(|p| p.io_write_bps).sum(),
        );
        let app_samples: Vec<AppSample> = groups
            .iter()
            .map(|g| AppSample { key: &g.key, title: &g.title, pid: g.root_pid, pt: pt(g.cpu, g.gpu.min(100.0), g.mem, g.io_read_bps, g.io_write_bps) })
            .collect();
        let gpu_keys: Vec<String> = g.adapters.iter().map(|a| format!("{}{}", crate::history::GPU_PREFIX, a.key)).collect();
        let net_samples: Vec<AppSample> = net
            .iter()
            .map(|n| AppSample { key: &n.key, title: &n.name, pid: 0, pt: pt(0.0, 0.0, 0, n.rx_bps, n.tx_bps) })
            .chain(g.adapters.iter().zip(&gpu_keys).map(|(a, k)| AppSample { key: k, title: &a.name, pid: 0, pt: pt(0.0, a.util, a.mem_used, 0.0, 0.0) }))
            .collect();
        let proc_samples: Vec<ProcSample> = frame
            .procs
            .iter()
            .chain(&frame.exited)
            .filter(|p| p.pid != 0)
            .map(|p| ProcSample { key: p.key(), name: &p.name, pt: pt(p.cpu, p.gpu, p.mem, p.io_read_bps, p.io_write_bps) })
            .collect();
        // The sample time is by tick, not by the end of the work: under full load the sample itself takes 50
        // or 400 ms, and an “after the work” stamp sometimes landed twice in one second slot (the second overwrote
        // the first), sometimes skipped a slot — a zero stayed there, and the CPU chart sawed 100 → 0 → 100.
        // The tick came roughly on time — place it exactly one step after the previous one; very late — by the clock.
        let real_t = wall0 + (t - t0).as_millis() as u64;
        let iv = inner.interval.as_millis() as u64;
        let hist_t = match last_hist {
            Some(p) if real_t.abs_diff(p + iv) < iv / 2 => p + iv,
            _ => real_t,
        };
        last_hist = Some(hist_t);
        // kernel pool — once a minute; the call itself is outside the lock
        let pool_raw = pool_due.then(crate::pool::query);

        let mut st = inner.state.lock().unwrap();
        st.history.push(hist_t, sys, &app_samples, &net_samples, &proc_samples);
        drop(app_samples);
        drop(net_samples);
        drop(proc_samples);
        st.watch.update(hist_t, &frame, &groups);
        if let Some(raw) = pool_raw {
            let procs = frame.system.processes;
            for (lvl, text) in st.pool.ingest(hist_t, raw, procs, frame.system.threads) {
                st.watch.log(hist_t, lvl, text, None);
            }
        }
        pool_due = st.pool.due(hist_t + inner.interval.as_millis() as u64);
        st.samples += 1;
        // compressed memory lives in the working set of the “Memory Compression” process
        let compressed = frame.procs.iter().find(|p| p.name.eq_ignore_ascii_case("Memory Compression")).map_or(0, |p| p.working_set);
        let snap = Snapshot {
            seq: st.samples,
            frame: Arc::new(frame),
            apps: Arc::new(groups),
            nets: Arc::new(net),
            gpus: Arc::new(g.adapters),
            net_per_process: etw.is_some(),
            mem_detail: crate::sysmem::MemDetail { compressed, ..sysmem.as_mut().map(|m| m.sample()).unwrap_or_default() },
            issues: Arc::new(st.watch.issues().to_vec()),
            pool_alerts: Arc::new(st.pool.alerts().to_vec()),
        };
        st.latest = Some(snap);
        let cost = t.elapsed().as_secs_f64() * 1000.0;
        st.cost_avg_ms = if st.samples == 1 { cost } else { st.cost_avg_ms * 0.95 + cost * 0.05 };
        st.cost_max_ms = st.cost_max_ms.max(cost);
        st.gpu_cost_ms = if st.samples == 1 { gpu_cost } else { st.gpu_cost_ms * 0.95 + gpu_cost * 0.05 };
        st.error = None;
        drop(st);
        inner.fresh.notify_all();

        if inner.store.is_some() && last_save.elapsed() >= SAVE_EVERY {
            last_save = Instant::now();
            if let Err(e) = save(inner) {
                crate::logs::error(format!("could not save the history: {e}"));
                inner.state.lock().unwrap().error = Some(format!("could not save the history: {e}"));
            }
        }
    }
}

fn save(inner: &Inner) -> std::io::Result<()> {
    let Some(path) = inner.store.as_ref().filter(|_| inner.persist) else { return Ok(()) };
    let _guard = inner.save_lock.lock().unwrap();
    let bytes = inner.state.lock().unwrap().history.save(); // only serialisation under the lock, no disk
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)
}
