//! Именованный канал `\\.\pipe\tm`: построчный JSON-RPC между движком и клиентами.
//!
//! Запрос:  `{"id":1,"method":"frame","params":{}}\n`
//! Ответ:   `{"id":1,"result":…}\n` или `{"id":1,"error":"…"}\n`
//!
//! Канал доступен только локально (удалённые клиенты отклоняются). Действия над процессами
//! (kill и т.п.) через канал не выполняются: клиент делает их сам, со своими правами, —
//! иначе запущенное от администратора приложение стало бы обходом UAC.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::windows::io::FromRawHandle;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const PIPE_NAME: &str = r"\\.\pipe\tm";
/// Предел длины одного запроса — защита от мусора в канале.
const MAX_REQUEST: u64 = 1 << 20;

pub type Handler = Arc<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Права на канал: система и администраторы — всё, вошедшие в систему пользователи — чтение и запись,
/// метка целостности «средняя». Иначе обычный `tm` не смог бы подключиться к приложению,
/// запущенному от администратора (по умолчанию остальным даётся только чтение).
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;GRGW;;;IU)S:(ML;;NW;;;ME)";

fn pipe_security() -> Option<SECURITY_ATTRIBUTES> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(PIPE_SDDL).as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
    // дескриптор нужен всё время работы сервера — не освобождаем
    (ok != 0).then(|| SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 })
}

/// Блокирующий цикл сервера: каждое подключение обслуживается в своём потоке.
/// Ошибка `AlreadyExists` — канал уже держит другой экземпляр tm.
pub fn serve(handler: Handler) -> io::Result<()> {
    let name = wide(PIPE_NAME);
    let sa = pipe_security();
    let sa_ptr = sa.as_ref().map_or(std::ptr::null(), |s| s as *const SECURITY_ATTRIBUTES);
    let mut first = true;
    loop {
        let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                256 * 1024,
                64 * 1024,
                0,
                sa_ptr,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let e = io::Error::last_os_error();
            if first && e.raw_os_error() == Some(5) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "tm уже запущен: канал занят другим экземпляром"));
            }
            return Err(e);
        }
        first = false;
        let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        // SAFETY: дескриптор только что создан и больше нигде не используется; File закроет его.
        let file = unsafe { File::from_raw_handle(h as _) };
        if !connected {
            continue;
        }
        let handler = handler.clone();
        let _ = std::thread::Builder::new().name("tm-pipe".into()).spawn(move || serve_conn(file, &handler));
    }
}

fn serve_conn(file: File, handler: &Handler) {
    let Ok(read_half) = file.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = file;
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut reader).take(MAX_REQUEST).read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => match handler(&req.method, &req.params) {
                Ok(v) => json!({ "id": req.id, "result": v }),
                Err(e) => json!({ "id": req.id, "error": e }),
            },
            Err(e) => json!({ "id": null, "error": format!("неверный запрос: {e}") }),
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_default();
        out.push(b'\n');
        if writer.write_all(&out).is_err() {
            break;
        }
    }
}

/// Ошибка клиента: движок не запущен — это не сбой, а повод собрать данные самому.
pub fn is_not_running(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

/// Один запрос к движку. Не зависает дольше `timeout`, даже если сервер повис.
pub fn call(method: &str, params: Value, timeout: Duration) -> io::Result<Value> {
    let (tx, rx) = mpsc::channel();
    let method = method.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(call_blocking(&method, params));
    });
    rx.recv_timeout(timeout)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "движок tm не ответил вовремя"))?
}

fn call_blocking(method: &str, params: Value) -> io::Result<Value> {
    let mut f = open_client()?;
    let mut req = serde_json::to_vec(&json!({ "id": 1, "method": method, "params": params }))?;
    req.push(b'\n');
    f.write_all(&req)?;
    let mut line = String::new();
    BufReader::new(f).read_line(&mut line)?;
    let mut v: Value = serde_json::from_str(&line)?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Err(io::Error::other(e.to_string()));
    }
    Ok(v.get_mut("result").map(Value::take).unwrap_or(Value::Null))
}

fn open_client() -> io::Result<File> {
    for _ in 0..25 {
        match OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            // 231 — все экземпляры канала заняты: сервер вот-вот создаст следующий
            Err(e) if e.raw_os_error() == Some(231) => std::thread::sleep(Duration::from_millis(20)),
            r => return r,
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "канал tm занят"))
}
