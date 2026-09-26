//! Журнал ошибок в файл: `%LOCALAPPDATA%\tm\logs\<программа>.log`. Туда же — паники
//! с местом и стеком вызовов (panic hook): приложение в трее не имеет консоли, и без
//! журнала падение оставалось бы без следа. Файл больше 1 МБ переименовывается в `.log.1`.

use std::fmt::Display;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const MAX_BYTES: u64 = 1 << 20;

static NAME: OnceLock<String> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());

/// Папка журналов.
pub fn dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("tm").join("logs"))
}

/// Файл журнала этой программы.
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

/// Дописывает строку в журнал. Ошибки самого журнала молча игнорируются: журнал не должен ронять программу.
pub fn write(level: &str, msg: impl Display) {
    let Some(p) = path() else { return };
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

/// Имя журнала и перехват паник. Вызывать один раз в начале `main`.
pub fn init(name: &str) {
    let _ = NAME.set(name.to_string());
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current().name().unwrap_or("?").to_string();
        let bt = std::backtrace::Backtrace::force_capture();
        write("panic", format!("поток «{thread}»: {info}\n{bt}"));
        prev(info);
    }));
}
