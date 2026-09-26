//! Docker: контейнеры и их нагрузка через Docker Engine API (`\\.\pipe\docker_engine`).
//!
//! Процессы контейнеров живут внутри виртуальной машины WSL и в списке процессов Windows
//! видны одним `vmmem`; здесь — разбивка по контейнерам. Подробная статистика собирается,
//! только пока её кто-то смотрит (окно, CLI, агент): простаивающий Docker не нагружается.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const PIPE: &str = r"\\.\pipe\docker_engine";
/// Пока кто-то смотрит — статистика раз в 2 с; без зрителей — только список раз в 15 с.
const ACTIVE_EVERY: Duration = Duration::from_secs(2);
const IDLE_EVERY: Duration = Duration::from_secs(15);
const INTEREST_FOR: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    /// running | paused | exited | created | restarting | dead
    pub state: String,
    /// «Up 3 hours», «Exited (0) 2 days ago»
    pub status: String,
    /// Проект docker compose, если контейнер из него.
    pub project: Option<String>,
    /// Загрузка ЦП в процентах от всего компьютера (как у процессов).
    pub cpu: f32,
    pub mem: u64,
    pub mem_limit: u64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub blk_read_bps: f64,
    pub blk_write_bps: f64,
    pub pids: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DockerState {
    /// Отвечает ли Docker Engine.
    pub available: bool,
    pub error: Option<String>,
    pub version: Option<String>,
    pub containers: Vec<Container>,
    /// Когда собрана статистика (0 — ещё не собиралась), мс Unix.
    pub stats_ms: u64,
    pub at_ms: u64,
}

/* ------------------------------------------------------------------ HTTP через канал */

fn request(method: &str, path: &str) -> io::Result<(u16, Vec<u8>)> {
    let mut f = OpenOptions::new().read(true).write(true).open(PIPE)?;
    let req = format!("{method} {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: tm\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    f.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            // сервер закрыл канал после ответа — это конец данных
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe || e.raw_os_error() == Some(109) => break,
            Err(e) => return Err(e),
        }
        if let Some(body) = complete_body(&raw) {
            return Ok(body);
        }
    }
    complete_body(&raw).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Docker оборвал ответ"))
}

/// Разбирает ответ, если он пришёл целиком: (код, тело).
fn complete_body(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let code: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
    let body = &raw[head_end + 4..];
    let header = |name: &str| {
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    if header("Transfer-Encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        let mut out = Vec::new();
        let mut rest = body;
        loop {
            let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).ok()?.split(';').next()?.trim(), 16).ok()?;
            rest = &rest[line_end + 2..];
            if size == 0 {
                return Some((code, out));
            }
            if rest.len() < size + 2 {
                return None;
            }
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
    }
    match header("Content-Length").and_then(|v| v.parse::<usize>().ok()) {
        Some(n) if body.len() >= n => Some((code, body[..n].to_vec())),
        Some(_) => None,
        None if code == 204 || code == 304 => Some((code, Vec::new())),
        None => None, // до конца соединения
    }
}

fn get_json(path: &str) -> io::Result<Value> {
    let (code, body) = request("GET", path)?;
    if code >= 400 {
        return Err(io::Error::other(api_error(code, &body)));
    }
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn api_error(code: u16, body: &[u8]) -> String {
    let msg = serde_json::from_slice::<Value>(body).ok().and_then(|v| v["message"].as_str().map(str::to_string));
    format!("Docker ответил {code}: {}", msg.unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string()))
}

/// Как действие называется в журнале.
pub fn action_title(action: &str) -> &'static str {
    match action {
        "start" => "запущен",
        "stop" => "остановлен",
        "restart" => "перезапущен",
        "pause" => "приостановлен",
        "unpause" => "возобновлён",
        "kill" => "принудительно остановлен",
        _ => "действие выполнено",
    }
}

/// Действие над контейнером: start | stop | restart | pause | unpause | kill.
pub fn act(id: &str, action: &str) -> Result<(), String> {
    if !matches!(action, "start" | "stop" | "restart" | "pause" | "unpause" | "kill") {
        return Err(format!("неизвестное действие «{action}»"));
    }
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
        return Err("неверный идентификатор контейнера".into());
    }
    let path = match action {
        "stop" | "restart" => format!("/containers/{id}/{action}?t=10"),
        _ => format!("/containers/{id}/{action}"),
    };
    match request("POST", &path) {
        Ok((code, _)) if code < 300 || code == 304 => Ok(()),
        Ok((code, body)) => Err(api_error(code, &body)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err("Docker не запущен".into()),
        Err(e) => Err(e.to_string()),
    }
}

/* ------------------------------------------------------------------ сбор */

#[derive(Clone, Copy)]
struct Prev {
    cpu: u64,
    sys: u64,
    rx: u64,
    tx: u64,
    rd: u64,
    wr: u64,
    at: Instant,
}

fn list() -> io::Result<Vec<Container>> {
    let v = get_json("/containers/json?all=1")?;
    Ok(v.as_array()
        .map(|a| {
            a.iter()
                .map(|c| Container {
                    id: c["Id"].as_str().unwrap_or("").chars().take(12).collect(),
                    name: c["Names"][0].as_str().unwrap_or("").trim_start_matches('/').to_string(),
                    image: c["Image"].as_str().unwrap_or("").to_string(),
                    state: c["State"].as_str().unwrap_or("").to_string(),
                    status: c["Status"].as_str().unwrap_or("").to_string(),
                    project: c["Labels"]["com.docker.compose.project"].as_str().map(str::to_string),
                    ..Default::default()
                })
                .collect()
        })
        .unwrap_or_default())
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// Статистика одного контейнера; скорости — относительно предыдущего замера.
fn stats(c: &mut Container, prev: &mut HashMap<String, Prev>) {
    let Ok(s) = get_json(&format!("/containers/{}/stats?stream=false&one-shot=true", c.id)) else { return };
    let cpu = u(&s["cpu_stats"]["cpu_usage"]["total_usage"]);
    let sys = u(&s["cpu_stats"]["system_cpu_usage"]);
    let ms = &s["memory_stats"];
    // как `docker stats`: без неактивного файлового кэша
    let cache = ms["stats"]["inactive_file"].as_u64().or_else(|| ms["stats"]["total_inactive_file"].as_u64()).unwrap_or(0);
    c.mem = u(&ms["usage"]).saturating_sub(cache);
    c.mem_limit = u(&ms["limit"]);
    c.pids = u(&s["pids_stats"]["current"]) as u32;
    let (mut rx, mut tx) = (0, 0);
    if let Some(n) = s["networks"].as_object() {
        for v in n.values() {
            rx += u(&v["rx_bytes"]);
            tx += u(&v["tx_bytes"]);
        }
    }
    let (mut rd, mut wr) = (0, 0);
    if let Some(list) = s["blkio_stats"]["io_service_bytes_recursive"].as_array() {
        for e in list {
            match e["op"].as_str().unwrap_or("").to_ascii_lowercase().as_str() {
                "read" => rd += u(&e["value"]),
                "write" => wr += u(&e["value"]),
                _ => {}
            }
        }
    }
    let now = Instant::now();
    if let Some(p) = prev.get(&c.id) {
        let dt = now.duration_since(p.at).as_secs_f64().max(0.001);
        if sys > p.sys {
            // доля машины Docker × её процессоры = занятые ядра; делим на процессоры Windows —
            // получаем долю всего компьютера, как у процессов в таблице
            let online = s["cpu_stats"]["online_cpus"].as_u64().unwrap_or(1).max(1) as f64;
            let host = crate::system::logical_cpus().max(1) as f64;
            c.cpu = ((cpu.saturating_sub(p.cpu)) as f64 / (sys - p.sys) as f64 * online / host * 100.0).clamp(0.0, 100.0) as f32;
        }
        c.net_rx_bps = rx.saturating_sub(p.rx) as f64 / dt;
        c.net_tx_bps = tx.saturating_sub(p.tx) as f64 / dt;
        c.blk_read_bps = rd.saturating_sub(p.rd) as f64 / dt;
        c.blk_write_bps = wr.saturating_sub(p.wr) as f64 / dt;
    }
    prev.insert(c.id.clone(), Prev { cpu, sys, rx, tx, rd, wr, at: now });
}

/// Один полный опрос: список, версия и (если `with_stats`) нагрузка работающих контейнеров.
fn poll(with_stats: bool, prev: &mut HashMap<String, Prev>) -> DockerState {
    let at_ms = crate::engine::wall_ms();
    match list() {
        Ok(mut containers) => {
            let version = get_json("/version").ok().and_then(|v| v["Version"].as_str().map(str::to_string));
            if with_stats {
                for c in containers.iter_mut().filter(|c| c.state == "running") {
                    stats(c, prev);
                }
                prev.retain(|id, _| containers.iter().any(|c| &c.id == id && c.state == "running"));
            }
            containers.sort_by(|a, b| (b.state == "running").cmp(&(a.state == "running")).then(b.cpu.total_cmp(&a.cpu)).then(a.name.cmp(&b.name)));
            DockerState { available: true, error: None, version, containers, stats_ms: if with_stats { at_ms } else { 0 }, at_ms }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => DockerState { error: Some("Docker не запущен".into()), at_ms, ..Default::default() },
        Err(e) => DockerState { error: Some(e.to_string()), at_ms, ..Default::default() },
    }
}

/// Разовый опрос без движка (CLI с --local): два замера с паузой, чтобы посчитать скорости.
pub fn snapshot_now() -> DockerState {
    let mut prev = HashMap::new();
    let first = poll(true, &mut prev);
    if !first.available || !first.containers.iter().any(|c| c.state == "running") {
        return first;
    }
    std::thread::sleep(Duration::from_millis(1000));
    poll(true, &mut prev)
}

/* ------------------------------------------------------------------ фоновый наблюдатель */

struct Shared {
    state: Mutex<DockerState>,
    fresh: Condvar,
    interest_ms: AtomicU64,
    wake: AtomicBool,
}

#[derive(Clone)]
pub struct DockerWatch {
    inner: Arc<Shared>,
}

impl DockerWatch {
    pub fn start() -> Self {
        let inner = Arc::new(Shared { state: Mutex::default(), fresh: Condvar::new(), interest_ms: AtomicU64::new(0), wake: AtomicBool::new(true) });
        let w = inner.clone();
        let _ = std::thread::Builder::new().name("tm-docker".into()).spawn(move || {
            let mut prev = HashMap::new();
            loop {
                let active = crate::engine::wall_ms().saturating_sub(w.interest_ms.load(Ordering::Relaxed)) < INTEREST_FOR.as_millis() as u64;
                w.wake.store(false, Ordering::Relaxed);
                let s = poll(active, &mut prev);
                let every = if active && s.available { ACTIVE_EVERY } else { IDLE_EVERY };
                *w.state.lock().unwrap() = s;
                w.fresh.notify_all();
                // спим, но просыпаемся сразу, если кто-то начал смотреть
                let until = Instant::now() + every;
                while Instant::now() < until && !w.wake.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        Self { inner }
    }

    /// Внеочередной опрос (после действия над контейнером): ждёт его не дольше 3 с.
    pub fn refresh(&self) {
        let s = self.inner.state.lock().unwrap();
        let before = s.at_ms;
        self.inner.wake.store(true, Ordering::Relaxed);
        let _ = self.inner.fresh.wait_timeout_while(s, Duration::from_secs(3), |s| s.at_ms == before);
    }

    /// Текущее состояние. Отмечает интерес: следующие 60 с статистика собирается раз в 2 с.
    /// Если до этого никто не смотрел — дожидается двух опросов со статистикой (до ~3,5 с):
    /// по одному нельзя посчитать скорости.
    pub fn get(&self) -> DockerState {
        let now = crate::engine::wall_ms();
        let was = self.inner.interest_ms.swap(now, Ordering::Relaxed);
        let watching = now.saturating_sub(was) < INTEREST_FOR.as_millis() as u64;
        let mut s = self.inner.state.lock().unwrap();
        if watching && !(s.available && s.stats_ms == 0) {
            return s.clone();
        }
        self.inner.wake.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_millis(3500);
        let (mut last, mut with_stats) = (s.at_ms, 0);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            s = self.inner.fresh.wait_timeout(s, left).unwrap().0;
            if s.at_ms != last {
                last = s.at_ms;
                with_stats += (s.stats_ms > 0) as u32;
                let running = s.containers.iter().any(|c| c.state == "running");
                if !s.available || with_stats >= 2 || (with_stats >= 1 && !running) {
                    break;
                }
            }
        }
        s.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_bodies() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]";
        assert_eq!(complete_body(r), Some((200, b"[]".to_vec())));
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(complete_body(c), Some((200, b"abcde".to_vec())));
        let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab";
        assert_eq!(complete_body(partial), None);
        assert_eq!(complete_body(b"HTTP/1.1 204 No Content\r\n\r\n"), Some((204, vec![])));
    }
}
