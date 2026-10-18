//! The named pipe `\\.\pipe\tm-<SID>-<session>`: line-based JSON-RPC between the engine and clients.
//!
//! Request:  `{"id":1,"method":"frame","params":{}}\n`
//! Response: `{"id":1,"result":…}\n` or `{"id":1,"error":"…"}\n`
//!
//! Every user and session has its own pipe; only that user and SYSTEM can open it,
//! and the client checks before a request that our tm is on the other end (same owner, the tm.exe
//! or tm-app.exe file from the same folder): pipe names are shared across the whole machine, and a foreign process could
//! take the name first.
//!
//! The pipe is local only (remote clients are rejected). Actions on processes
//! (kill and so on) are not performed through the pipe: the client does them itself, with its own rights, —
//! otherwise an app running as administrator would become a UAC bypass.

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

/// The pipe name of the current user and session. An app running as administrator and a regular
/// `tm` in the same session get the same name: they share the SID.
pub fn pipe_name() -> String {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    let mut session = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
    let sid = crate::system::current_user_sid().unwrap_or_else(|| "unknown".into());
    format!(r"\\.\pipe\tm-{sid}-{session}")
}
/// Maximum length of one request — protection against garbage in the pipe.
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

/// Pipe permissions: only SYSTEM and the current user; integrity label “medium” — so that a regular
/// `tm` can write to the pipe of an app running as administrator, while low-integrity
/// processes (browser sandboxes) cannot.
fn pipe_sddl() -> Option<String> {
    let sid = crate::system::current_user_sid()?;
    Some(format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})S:(ML;;NW;;;ME)"))
}

fn pipe_security() -> Option<SECURITY_ATTRIBUTES> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let sddl = pipe_sddl()?;
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&sddl).as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
    // the descriptor is needed for the whole lifetime of the server — not freed
    (ok != 0).then(|| SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 })
}

/// The blocking server loop: every connection is served in its own thread.
/// The `AlreadyExists` error — another tm instance already holds the pipe.
pub fn serve(handler: Handler) -> io::Result<()> {
    let name = wide(&pipe_name());
    // without its own permissions the pipe would get the defaults (readable by everyone) — better not to open it at all
    let sa = pipe_security().ok_or_else(|| io::Error::other("could not set the pipe permissions"))?;
    let sa_ptr = &sa as *const SECURITY_ATTRIBUTES;
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
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "tm is already running: the pipe is held by another instance"));
            }
            return Err(e);
        }
        first = false;
        let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        // SAFETY: the handle was just created and is not used anywhere else; File will close it.
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
            Err(e) => json!({ "id": null, "error": format!("invalid request: {e}") }),
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_default();
        out.push(b'\n');
        if writer.write_all(&out).is_err() {
            break;
        }
    }
}

/// Client error: the engine is not running — not a failure, but a reason to collect the data ourselves.
pub fn is_not_running(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

/// One request to the engine. Never hangs longer than `timeout`, even if the server is stuck.
pub fn call(method: &str, params: Value, timeout: Duration) -> io::Result<Value> {
    let (tx, rx) = mpsc::channel();
    let method = method.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(call_blocking(&method, params));
    });
    rx.recv_timeout(timeout)
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the tm engine did not answer in time"))?
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
    let name = pipe_name();
    for _ in 0..25 {
        match OpenOptions::new().read(true).write(true).open(&name) {
            // 231 — all pipe instances are busy: the server is about to create the next one
            Err(e) if e.raw_os_error() == Some(231) => std::thread::sleep(Duration::from_millis(20)),
            Ok(f) => {
                verify_server(&f)?;
                return Ok(f);
            }
            r => return r,
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "the tm pipe is busy"))
}

/// Our engine is on the other end of the pipe: the same user, the tm.exe or tm-app.exe file
/// from the same folder as us. Otherwise requests (and responses) would go to a foreign process.
fn verify_server(f: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    let bad = |why: &str| io::Error::new(io::ErrorKind::PermissionDenied, format!("the tm pipe is held by a foreign process: {why}"));
    let mut pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(f.as_raw_handle() as _, &mut pid) } == 0 {
        return Err(bad("could not identify the server"));
    }
    let h = crate::handle::ProcHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION, None).map_err(|_| bad("no access to the server"))?;
    if crate::system::process_user_sid(h.raw()) != crate::system::current_user_sid() {
        return Err(bad("another user"));
    }
    let path = crate::info::image_path(&h).map(std::path::PathBuf::from).ok_or_else(|| bad("unknown file"))?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let dir = |p: &std::path::Path| p.parent().map(|d| d.to_string_lossy().to_ascii_lowercase());
    let same_dir = std::env::current_exe().ok().and_then(|me| dir(&me)).is_some_and(|mine| dir(&path) == Some(mine));
    if !matches!(name.as_str(), "tm.exe" | "tm-app.exe") || !same_dir {
        return Err(bad(&path.display().to_string()));
    }
    Ok(())
}
