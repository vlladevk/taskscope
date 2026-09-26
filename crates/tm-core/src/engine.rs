//! Движок: фоновый сборщик раз в секунду, история за сутки и наблюдатель за проблемами.
//! Один экземпляр на машину — его запускает приложение (или `tm daemon`),
//! а окно, CLI и другие клиенты получают данные через `Service`.

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

/// Всё, что известно о последнем замере. Дёшево клонируется (только счётчики ссылок).
#[derive(Clone)]
pub struct Snapshot {
    /// Номер замера: растёт на 1 каждую секунду.
    pub seq: u64,
    pub frame: Arc<Frame>,
    /// Приложения — с уже найденными названиями.
    pub apps: Arc<Vec<AppStat>>,
    pub nets: Arc<Vec<NetStat>>,
    /// Видеокарты (пусто, если счётчиков нет).
    pub gpus: Arc<Vec<GpuStat>>,
    /// Есть ли трафик по процессам (нужны права администратора).
    pub net_per_process: bool,
    /// Память ядра, кэша и драйверов — то, что занято, но не принадлежит процессам.
    pub mem_detail: crate::sysmem::MemDetail,
    pub issues: Arc<Vec<Issue>>,
    /// Тревоги по пулу ядра: утечки в драйверах, накопление токенов, зомби-процессы.
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
    /// Сколько из замера уходит на видеокарты (счётчики PDH), мс, скользящее среднее.
    gpu_cost_ms: f64,
    error: Option<String>,
}

struct Inner {
    state: Mutex<State>,
    fresh: Condvar,
    stop: AtomicBool,
    started_ms: u64,
    interval: Duration,
    /// Куда сохранять историю; `None` — не сохранять.
    store: Option<PathBuf>,
    /// Сериализует запись файла: периодическое сохранение и сохранение при выходе не пересекутся.
    save_lock: Mutex<()>,
    /// false — историю только читаем с диска, но не пишем (второй экземпляр, режим разработки).
    persist: bool,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

/// Файл истории по умолчанию: %LOCALAPPDATA%\tm\history.bin.
pub fn default_store() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("tm").join("history.bin"))
}

const SAVE_EVERY: Duration = Duration::from_secs(600);

pub fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Engine {
    /// Запускает сборщик. История подхватывается из `store`, если файл есть и подходит.
    pub fn start(interval: Duration, store: Option<PathBuf>) -> Self {
        Self::start_with(interval, store, true)
    }

    /// Как `start`, но историю с диска только читает: файл основного движка не перезаписывается.
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
            .expect("не удалось запустить поток сборщика");
        Self { inner }
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
    }

    pub fn interval(&self) -> Duration {
        self.inner.interval
    }

    /// Записывает историю на диск: сначала во временный файл, потом атомарная замена.
    pub fn save(&self) -> std::io::Result<()> {
        save(&self.inner)
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.inner.state.lock().unwrap().latest.clone()
    }

    /// Ждёт замер новее `after` не дольше `timeout`. Если он уже есть — возвращает сразу.
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

    /// Посекундные ряды (до 5 мин) для групп процессов — по одной сумме на группу.
    pub fn procs_t0(&self, groups: &[Vec<ProcKey>], m: Metric, points: usize) -> Vec<Vec<f64>> {
        let st = self.inner.state.lock().unwrap();
        groups.iter().map(|g| st.history.procs_t0(g, m, points)).collect()
    }

    /// Пул ядра по меткам: размеры, скорость роста, тревоги.
    pub fn pool_report(&self, n: usize, by: &str) -> crate::pool::PoolReport {
        self.inner.state.lock().unwrap().pool.report(n, by)
    }

    /// Метки, за которыми следит движок (для поиска драйверов).
    pub fn pool_tracked(&self) -> Vec<u32> {
        self.inner.state.lock().unwrap().pool.tracked()
    }

    pub fn events_after(&self, after: u64) -> Vec<Event> {
        self.inner.state.lock().unwrap().watch.events_after(after)
    }

    /// Запись в журнал (например, о действии пользователя).
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
    // выше обычного: график не замирает, даже когда процессор загружен на 100 %
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) };
    let mut sampler = Sampler::new();
    let mut nets = NetSampler::default();
    let mut gpu = GpuSampler::new();
    // сеанс ETW общий для всей системы: второй экземпляр (режим разработки) его не трогает,
    // иначе он перехватил бы или остановил сеанс основного приложения
    let etw = if inner.persist { crate::net_etw::NetEtw::start() } else { None };
    let mut sysmem = crate::sysmem::MemSampler::new();
    let mut info = InfoCache::default();
    let mut lineage = apps::Lineage::default();
    let mut spawns = apps::Spawns::default();
    // процесс → приложение по прошлому замеру: ЦП завершившегося процесса отдаём его приложению
    let mut prev_app: HashMap<ProcKey, String> = HashMap::new();
    let _ = sampler.sample(); // первый замер — только база для скоростей
    nets.sample();
    // время истории: монотонные часы, привязанные к настенным при старте (перевод часов не ломает кольца)
    let t0 = Instant::now();
    let wall0 = wall_ms();
    let mut next = Instant::now() + inner.interval;
    let mut last_save = Instant::now();
    let mut pool_due = true;

    while !inner.stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        }
        // после сна или зависания не пытаемся «догнать» пропущенные тики
        next = (next + inner.interval).max(Instant::now());

        let t = Instant::now();
        let mut frame = match sampler.sample() {
            Ok(f) => f,
            Err(e) => {
                let msg = e.to_string();
                let mut st = inner.state.lock().unwrap();
                // в журнал — только новую ошибку, а не каждую секунду одну и ту же
                if st.error.as_deref() != Some(msg.as_str()) {
                    crate::logs::error(format!("замер: {msg}"));
                }
                st.error = Some(msg);
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
            }
        }
        if let Some(e) = &etw {
            let bytes = e.take();
            let dt = (frame.interval_ms / 1000.0).max(0.001);
            for p in frame.procs.iter_mut() {
                if let Some(&(rx, tx)) = bytes.get(&p.pid) {
                    p.net_rx_bps = rx as f64 / dt;
                    p.net_tx_bps = tx as f64 / dt;
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
            // приложения уже нет (завершился последний процесс) — его ЦП учтён в системе, но не в группах
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
        let hist_t = wall0 + t0.elapsed().as_millis() as u64;
        // пул ядра — раз в минуту; сам вызов вне замка
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
        // сжатая память живёт в рабочем наборе процесса «Memory Compression»
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
                crate::logs::error(format!("не удалось сохранить историю: {e}"));
                inner.state.lock().unwrap().error = Some(format!("не удалось сохранить историю: {e}"));
            }
        }
    }
}

fn save(inner: &Inner) -> std::io::Result<()> {
    let Some(path) = inner.store.as_ref().filter(|_| inner.persist) else { return Ok(()) };
    let _guard = inner.save_lock.lock().unwrap();
    let bytes = inner.state.lock().unwrap().history.save(); // под замком только сериализация, без диска
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)
}
