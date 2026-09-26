//! Сборщик: каждый вызов `sample()` делает снимок и считает скорости
//! (ЦП %, ввод-вывод в байтах/с) относительно предыдущего снимка.

use std::collections::HashMap;
use std::io;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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
    /// не видны (git, grep, sh из скриптов): занятость машины минус сумма по видимым процессам.
    /// Движок раздаёт его приложениям, которые такие процессы запускают (`AppStat::short_cpu`);
    /// здесь — остаток, который отнести некому (прерывания, неизвестные запуски).
    #[serde(default)]
    pub unseen_cpu: f32,
    /// Сколько процессов в секунду запускается (замеченных живыми), сглажено.
    #[serde(default)]
    pub spawn_rate: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    /// Время замера, мс Unix.
    pub at_ms: u64,
    /// Интервал до предыдущего замера, мс (0 — первый замер, скорости ещё не посчитаны).
    pub interval_ms: f64,
    pub system: SystemStat,
    pub procs: Vec<ProcStat>,
}

#[derive(Clone, Copy)]
struct Prev {
    cpu_time: i64,
    io_read: u64,
    io_write: u64,
}

pub struct Sampler {
    query: ProcessQuery,
    raw: Vec<RawProc>,
    prev: HashMap<ProcKey, Prev>,
    prev_at: Option<Instant>,
    prev_cpu: Option<CpuTimes>,
    /// Время прошлого замера (FILETIME): кто создан позже — родился между замерами.
    prev_ft: i64,
    ncpu: u32,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            query: ProcessQuery::default(),
            raw: Vec::with_capacity(512),
            prev: HashMap::with_capacity(512),
            prev_at: None,
            prev_cpu: None,
            prev_ft: i64::MAX,
            ncpu: system::logical_cpus(),
        }
    }

    pub fn sample(&mut self) -> io::Result<Frame> {
        let now = Instant::now();
        let cpu_now = system::cpu_times();
        let ft_now = system::filetime_now();
        self.query.snapshot(&mut self.raw)?;

        let dt = self.prev_at.map(|p| now.duration_since(p).as_secs_f64()).unwrap_or(0.0);
        // время ЦП в 100 нс, доступное всем ядрам за интервал
        let cpu_budget = dt * 1e7 * self.ncpu as f64;

        let mut next = HashMap::with_capacity(self.raw.len());
        let mut procs = Vec::with_capacity(self.raw.len());
        let (mut threads, mut handles) = (0u64, 0u64);
        for r in &self.raw {
            let key = (r.pid, r.create_time);
            let prev = self.prev.get(&key);
            let (cpu, rd, wr) = match prev {
                Some(p) if dt > 0.0 => (
                    ((r.cpu_time - p.cpu_time).max(0) as f64 / cpu_budget * 100.0) as f32,
                    r.io_read.saturating_sub(p.io_read) as f64 / dt,
                    r.io_write.saturating_sub(p.io_write) as f64 / dt,
                ),
                // родился между замерами: всё его время ЦП потрачено за этот интервал
                // (раньше первый замер давал 0 — сборка из сотни коротких javac и git была невидима)
                None if dt > 0.0 && r.create_time >= self.prev_ft => (
                    (r.cpu_time.max(0) as f64 / cpu_budget * 100.0) as f32,
                    r.io_read as f64 / dt,
                    r.io_write as f64 / dt,
                ),
                _ => (0.0, 0.0, 0.0),
            };
            let born = prev.is_none() && dt > 0.0 && r.create_time >= self.prev_ft;
            next.insert(key, Prev { cpu_time: r.cpu_time, io_read: r.io_read, io_write: r.io_write });
            threads += r.threads as u64;
            handles += r.handles as u64;
            procs.push(ProcStat {
                pid: r.pid,
                ppid: r.ppid,
                name: r.name.clone(),
                create_time: r.create_time,
                cpu: if r.pid == 0 { 0.0 } else { cpu.min(100.0) },
                cpu_time_ms: (r.cpu_time / 10_000) as u64,
                mem: r.ws_private,
                working_set: r.working_set,
                private_bytes: r.private_bytes,
                io_read_bps: rd,
                io_write_bps: wr,
                threads: r.threads,
                handles: r.handles,
                session: r.session,
                base_priority: r.base_priority,
                suspended: r.suspended,
                gpu: 0.0,
                gpu_mem: 0,
                net_rx_bps: 0.0,
                net_tx_bps: 0.0,
                born,
            });
        }
        // завершившиеся процессы просто не попадают в next — карта не растёт
        self.prev = next;

        let sys_cpu = self.prev_cpu.map(|p| system::cpu_busy(p, cpu_now)).unwrap_or(0.0);
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
                processes: procs.iter().filter(|p| p.pid != 0).count(),
                threads,
                handles,
                uptime_ms: system::uptime_ms(),
                unseen_cpu: 0.0,
                spawn_rate: 0.0,
            },
            procs,
        })
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
