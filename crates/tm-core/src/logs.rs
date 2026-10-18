//! Error log to a file: `%LOCALAPPDATA%\tm\logs\<program>.log`. Panics go there too,
//! with location and backtrace (panic hook): the tray app has no console, and without
//! a log a crash would leave no trace. A file over 1 MB is renamed to `.log.1`.

use std::fmt::Display;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const MAX_BYTES: u64 = 1 << 20;

static NAME: OnceLock<String> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());

/// The log folder.
pub fn dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("tm").join("logs"))
}

/// This program’s log file.
pub fn path() -> Option<PathBuf> {
    Some(dir()?.join(format!("{}.log", NAME.get().map_or("tm", String::as_str))))
}

fn stamp() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let t = unsafe {
        let mut t = std::mem::zeroed();
        GetLocalTime(&mut t);
        t
    };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds)
}

/// Appends a line to the log. Errors of the log itself are silently ignored: the log must not crash the program.
pub fn write(level: &str, msg: impl Display) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    append(level, &msg.to_string());
}

/// A line from the window (window.onerror): line breaks become a visible “⏎” so neighbouring entries
/// cannot be forged, and no more than 30 lines a minute — a flood of errors does not push out the real ones.
pub fn write_ui(msg: &str) {
    use std::time::{Duration, Instant};
    static WINDOW: Mutex<Option<(Instant, u32)>> = Mutex::new(None);
    {
        let mut w = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let (start, n) = w.get_or_insert((now, 0));
        if now.duration_since(*start) > Duration::from_secs(60) {
            *start = now;
            *n = 0;
        }
        *n += 1;
        if *n > 30 {
            return;
        }
    }
    write("ui", msg.replace('\r', "").replace('\n', " ⏎ "));
}

fn append(level: &str, msg: &str) {
    let Some(p) = path() else { return };
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > MAX_BYTES) {
        let _ = std::fs::rename(&p, p.with_extension("log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{} [{level}] pid {}: {msg}", stamp(), std::process::id());
    }
}

pub fn error(msg: impl Display) {
    write("error", msg);
}

pub fn warn(msg: impl Display) {
    write("warn", msg);
}

/// Log name and panic hook. Call once at the start of `main`.
pub fn init(name: &str) {
    let _ = NAME.set(name.to_string());
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // `tm … | head`: the reader closed the pipe — not a program failure, do not log it
        let text = info.to_string();
        // try_lock: the panic may have happened inside a log write (the lock is already ours) — do not hang
        if !text.contains("failed printing to std") {
            let guard = match LOCK.try_lock() {
                Ok(g) => Some(g),
                Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(_g) = guard {
                let thread = std::thread::current().name().unwrap_or("?").to_string();
                let bt = std::backtrace::Backtrace::force_capture();
                append("panic", &format!("thread “{thread}”: {text}\n{bt}"));
            }
        }
        prev(info);
    }));
}
