//! Details of one process — like the tabs of the process properties window in System Informer:
//! modules, threads, handles and environment. Everything is read on request (the process tab
//! is open), not in every sample: it is expensive (the system-wide handle table is megabytes).

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::OnceLock;

use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, GetFinalPathNameByHandleW, FILE_TYPE_DISK, VOLUME_NAME_DOS, VOLUME_NAME_NT};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetThreadId, OpenThread, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
};

use crate::handle::ProcHandle;
use crate::nt;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQueryInformationThread(h: HANDLE, class: i32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryObject(h: HANDLE, class: i32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

/// No more handles of one process are parsed: “leaking” processes have hundreds of thousands.
const MAX_HANDLES: usize = 20_000;

#[derive(Clone, Debug, Serialize)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub tid: u32,
    /// Kernel and user CPU time, 100 ns — the window computes the load from the difference between requests.
    pub kernel: i64,
    pub user: i64,
    pub create_time: i64,
    pub priority: i32,
    pub base_priority: i32,
    pub switches: u32,
    /// running, ready, waiting, suspended, standby, terminated, other.
    pub state: &'static str,
    pub wait_reason: u32,
    /// The thread start address: “module.dll+0x1a2b”, as in System Informer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Handle {
    pub handle: u64,
    /// File, Key, Event, Section, Process, Thread, …
    #[serde(rename = "type")]
    pub kind: String,
    pub access: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Handles {
    pub list: Vec<Handle>,
    /// Total handles of the process (the list may be cut to MAX_HANDLES).
    pub total: usize,
    /// Whether the handles could be duplicated to learn their names (no — for protected processes and other users’ without rights).
    pub names: bool,
    /// How many handles of each type — for the summary.
    pub by_type: Vec<(String, usize)>,
    /// The name of one of the files could not be obtained in time (an operation hangs on it) —
    /// the names of the remaining files were not queried.
    pub files_skipped: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Environment {
    pub cwd: String,
    pub vars: Vec<(String, String)>,
}

fn open_checked(pid: u32, create_time: i64, access: u32) -> io::Result<ProcHandle> {
    ProcHandle::open(pid, access | PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time))
}

/// Loaded modules (EXE and DLL), by load address.
pub fn modules(pid: u32, create_time: i64) -> io::Result<Vec<Module>> {
    // creation time check: the PID may have gone to another process
    drop(open_checked(pid, create_time, 0)?);
    let mut snap = ptr::null_mut();
    // ERROR_BAD_LENGTH: the process is loading a module right now — retry
    for _ in 0..5 {
        snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if snap as isize != -1 || io::Error::last_os_error().raw_os_error() != Some(24) {
            break;
        }
    }
    if snap as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut e: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let wstr = |s: &[u16]| String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]);
    let mut ok = unsafe { Module32FirstW(snap, &mut e) };
    while ok != 0 {
        out.push(Module { name: wstr(&e.szModule), path: wstr(&e.szExePath), base: e.modBaseAddr as u64, size: e.modBaseSize });
        ok = unsafe { Module32NextW(snap, &mut e) };
    }
    unsafe { CloseHandle(snap) };
    out.sort_by_key(|m| m.base);
    Ok(out)
}

/// Modules for labelling start addresses: the window refreshes threads every 2 s, while the module list
/// changes rarely — keep it for 10 s (last process).
fn modules_cached(pid: u32, create_time: i64) -> Vec<Module> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static CACHE: Mutex<Option<(u32, i64, Instant, Vec<Module>)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((p, ct, at, m)) = c.as_ref() {
        if *p == pid && *ct == create_time && at.elapsed() < Duration::from_secs(10) {
            return m.clone();
        }
    }
    let m = modules(pid, create_time).unwrap_or_default();
    *c = Some((pid, create_time, Instant::now(), m.clone()));
    m
}

fn thread_state(state: u32, reason: u32) -> &'static str {
    match state {
        2 => "running",
        1 | 7 => "ready",
        3 => "standby",
        4 => "terminated",
        5 if reason == 5 => "suspended",
        5 => "waiting",
        _ => "other",
    }
}

/// “module+0xOFFSET” from the module list (sorted by address).
fn symbolize(addr: u64, mods: &[Module]) -> String {
    let i = mods.partition_point(|m| m.base <= addr);
    match i.checked_sub(1).map(|i| &mods[i]) {
        Some(m) if addr < m.base + m.size as u64 => format!("{}+0x{:x}", m.name, addr - m.base),
        _ => format!("0x{addr:x}"),
    }
}

/// Process threads from the system snapshot (SYSTEM_THREAD_INFORMATION) and their start addresses.
pub fn threads(pid: u32, create_time: i64) -> io::Result<Vec<Thread>> {
    let buf = nt::query_system(5, 1 << 20)?;
    // SYSTEM_PROCESS_INFORMATION offsets (x64): thread count, creation time, PID; threads — right after 256 bytes
    let rd32 = |o: usize| buf.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let rd64 = |o: usize| buf.get(o..o + 8).map_or(0, |b| i64::from_le_bytes(b.try_into().unwrap()));
    let mut off = 0usize;
    let entry = loop {
        if off + 256 > buf.len() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "the process has exited"));
        }
        if rd64(off + 0x50) as u32 == pid && nt::js_safe(rd64(off + 32)) == create_time {
            break off;
        }
        let next = rd32(off) as usize;
        if next == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "the process has exited"));
        }
        off += next;
    };
    let n = rd32(entry + 4) as usize;
    let mods = modules_cached(pid, create_time);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let t = entry + 256 + i * 80;
        if t + 80 > buf.len() {
            break;
        }
        let tid = rd64(t + 48) as u32;
        let (state, reason) = (rd32(t + 68), rd32(t + 72));
        // the address from the snapshot is usually RtlUserThreadStart; the real start address is Win32StartAddress (class 9)
        let start = unsafe {
            // class 9 needs the full query right; the “limited” one is not enough everywhere
            let mut h = OpenThread(THREAD_QUERY_INFORMATION, 0, tid);
            if h.is_null() {
                h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid);
            }
            if h.is_null() {
                None
            } else {
                let mut a = 0usize;
                let st = NtQueryInformationThread(h, 9, (&mut a as *mut usize).cast(), 8, ptr::null_mut());
                CloseHandle(h);
                (st >= 0 && a != 0).then(|| symbolize(a as u64, &mods))
            }
        };
        out.push(Thread {
            tid,
            kernel: rd64(t),
            user: rd64(t + 8),
            create_time: nt::js_safe(rd64(t + 16)),
            priority: rd32(t + 56) as i32,
            base_priority: rd32(t + 60) as i32,
            switches: rd32(t + 64),
            state: thread_state(state, reason),
            wait_reason: reason,
            start,
        });
    }
    Ok(out)
}

/// Kernel object type names by index (ObjectTypesInformation) — once per run.
pub(crate) fn type_names() -> &'static HashMap<u16, String> {
    static T: OnceLock<HashMap<u16, String>> = OnceLock::new();
    T.get_or_init(|| {
        let mut map = HashMap::new();
        let mut buf = vec![0u64; 16 * 1024];
        let mut ret = 0u32;
        let st = unsafe { NtQueryObject(ptr::null_mut(), 3, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut ret) };
        if st < 0 {
            return map;
        }
        let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), buf.len() * 8) };
        let n = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
        // OBJECT_TYPE_INFORMATION — 104 bytes (x64), followed by the name aligned to 8
        let mut off = 8usize;
        for i in 0..n {
            if off + 104 > b.len() {
                break;
            }
            let len = u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) as usize;
            let max = u16::from_le_bytes(b[off + 2..off + 4].try_into().unwrap()) as usize;
            let p = u64::from_le_bytes(b[off + 8..off + 16].try_into().unwrap()) as *const u16;
            let name = if p.is_null() { String::new() } else { String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len / 2) }) };
            // TypeIndex (Windows 8.1+); on old systems the indices start at 2
            let idx = b[off + 90];
            map.insert(if idx != 0 { idx as u16 } else { i as u16 + 2 }, name);
            off += 104 + ((max + 7) & !7);
        }
        map
    })
}

/// “\REGISTRY\MACHINE\…” → “HKLM\…”, “\REGISTRY\USER\<SID>…” → “HKCU…” (own SID) or “HKU\…”.
fn pretty_key(name: &str) -> String {
    static SID: OnceLock<Option<String>> = OnceLock::new();
    // the case can be anything: “\REGISTRY\MACHINE” and “\Registry\Machine”
    const MACHINE: &str = r"\REGISTRY\MACHINE";
    const USER: &str = r"\REGISTRY\USER\";
    let upper = name.to_ascii_uppercase();
    if upper.starts_with(MACHINE) {
        return format!("HKLM{}", &name[MACHINE.len()..]);
    }
    if upper.starts_with(USER) {
        let rest = &name[USER.len()..];
        if let Some(sid) = SID.get_or_init(crate::system::current_user_sid) {
            if let Some(tail) = rest.strip_prefix(sid.as_str()) {
                // “<SID>_Classes\…” is HKCU\Software\Classes, not “HKCU_Classes”
                if let Some(t) = tail.strip_prefix("_Classes") {
                    if t.is_empty() || t.starts_with('\\') {
                        return format!(r"HKCU\Software\Classes{t}");
                    }
                } else if tail.is_empty() || tail.starts_with('\\') {
                    return format!("HKCU{tail}");
                }
            }
        }
        return format!(r"HKU\{rest}");
    }
    name.to_string()
}

fn object_name(h: HANDLE) -> String {
    let mut buf = vec![0u64; 512];
    let mut ret = 0u32;
    let st = unsafe { NtQueryObject(h, 1, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut ret) };
    if st < 0 {
        return String::new();
    }
    // OBJECT_NAME_INFORMATION — a UNICODE_STRING at the start of the buffer
    let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), 16) };
    let len = u16::from_le_bytes([b[0], b[1]]) as usize;
    let p = u64::from_le_bytes(b[8..16].try_into().unwrap()) as *const u16;
    if p.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len / 2) })
}

/// The object name from a duplicated handle. Names of pipe files are not queried: a query
/// to a synchronous pipe can hang forever (System Informer works around this with a separate thread).
fn name_of(kind: &str, h: HANDLE) -> String {
    match kind {
        "File" => file_name(h),
        // 0 — no right to learn the number: empty, not “PID 0”
        "Process" => match unsafe { GetProcessId(h) } {
            0 => String::new(),
            id => format!("PID {id}"),
        },
        "Thread" => match unsafe { GetThreadId(h) } {
            0 => String::new(),
            id => format!("TID {id}"),
        },
        "Key" => pretty_key(&object_name(h)),
        "Directory" | "Event" | "Mutant" | "Section" | "Semaphore" | "SymbolicLink" | "ALPC Port" | "WindowStation" | "Desktop" | "Timer"
        | "Job" | "Partition" => object_name(h),
        _ => String::new(),
    }
}

/// Types that can have a name (the others are not duplicated — that would be thousands of extra calls).
const NAMED: &[&str] = &[
    "File", "Process", "Thread", "Key", "Directory", "Event", "Mutant", "Section", "Semaphore", "SymbolicLink", "ALPC Port", "WindowStation",
    "Desktop", "Timer", "Job", "Partition",
];

fn file_name(h: HANDLE) -> String {
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return String::new();
    }
    let mut w = vec![0u16; 1024];
    let n = unsafe { GetFinalPathNameByHandleW(h, w.as_mut_ptr(), w.len() as u32, VOLUME_NAME_DOS) } as usize;
    if n == 0 || n >= w.len() {
        return String::new();
    }
    let s = String::from_utf16_lossy(&w[..n]);
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// The file name in kernel form: “\Device\HarddiskVolume3\…”. Without asking the volume manager for
/// the drive letter — noticeably faster, which matters when walking all open files of the system.
pub(crate) fn nt_file_name(h: HANDLE) -> String {
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return String::new();
    }
    let mut w = vec![0u16; 1024];
    let n = unsafe { GetFinalPathNameByHandleW(h, w.as_mut_ptr(), w.len() as u32, VOLUME_NAME_NT) } as usize;
    if n == 0 || n >= w.len() {
        return String::new();
    }
    String::from_utf16_lossy(&w[..n])
}

/// File names in a separate thread: if a query hangs, the thread stays waiting by itself (it will also close
/// the handle copy when the operation finishes), and the check goes on without file names.
pub(crate) struct FileNamer {
    tx: Option<std::sync::mpsc::Sender<usize>>,
    rx: std::sync::mpsc::Receiver<String>,
}

impl FileNamer {
    const WAIT: std::time::Duration = std::time::Duration::from_millis(300);

    pub(crate) fn new(namer: fn(HANDLE) -> String) -> Self {
        let (tx, jobs) = std::sync::mpsc::channel::<usize>();
        let (done, rx) = std::sync::mpsc::channel::<String>();
        let spawned = std::thread::Builder::new().name("tm-file-names".into()).spawn(move || {
            for h in jobs {
                let h = h as HANDLE;
                let n = namer(h);
                unsafe { CloseHandle(h) };
                if done.send(n).is_err() {
                    break;
                }
            }
        });
        Self { tx: spawned.ok().map(|_| tx), rx }
    }

    /// The file name; `None` — no answer in time (the thread closes the handle copy when it is free).
    pub(crate) fn name(&self, h: HANDLE) -> Option<String> {
        let Some(tx) = &self.tx else {
            unsafe { CloseHandle(h) };
            return Some(String::new());
        };
        if tx.send(h as usize).is_err() {
            unsafe { CloseHandle(h) };
            return None;
        }
        self.rx.recv_timeout(Self::WAIT).ok()
    }
}

/// Process handles: type, access and, where it is safe, the object name.
pub fn handles(pid: u32, create_time: i64) -> io::Result<Handles> {
    let proc = open_checked(pid, create_time, 0)?;
    // duplicating handles needs PROCESS_DUP_HANDLE; without it — types only
    let dup_from = ProcHandle::open(pid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time)).ok();
    drop(proc);
    // SystemExtendedHandleInformation (64): count, reserved, then 40-byte entries
    let buf = nt::query_system(64, 4 << 20)?;
    let rd = |o: usize, n: usize| -> u64 {
        let mut a = [0u8; 8];
        a[..n].copy_from_slice(&buf[o..o + n]);
        u64::from_le_bytes(a)
    };
    let count = rd(0, 8) as usize;
    let types = type_names();
    let me = unsafe { GetCurrentProcess() };
    let mut list = Vec::new();
    let mut total = 0usize;
    let mut by_type: HashMap<String, usize> = HashMap::new();
    let files = FileNamer::new(file_name);
    let mut files_stuck = false;
    for i in 0..count {
        let e = 16 + i * 40;
        if e + 40 > buf.len() {
            break;
        }
        if rd(e + 8, 8) as u32 != pid {
            continue;
        }
        total += 1;
        let kind = types.get(&(rd(e + 30, 2) as u16)).cloned().unwrap_or_else(|| format!("#{}", rd(e + 30, 2)));
        *by_type.entry(kind.clone()).or_default() += 1;
        if list.len() >= MAX_HANDLES {
            continue;
        }
        let hv = rd(e + 16, 8);
        // duplicate only types that can have a name at all (EtwRegistration, IRTimer… cannot)
        let dup = match &dup_from {
            Some(src) if NAMED.contains(&kind.as_str()) && !(kind == "File" && files_stuck) => unsafe {
                let mut d: HANDLE = ptr::null_mut();
                (DuplicateHandle(src.raw(), hv as usize as HANDLE, me, &mut d, 0, 0, DUPLICATE_SAME_ACCESS) != 0).then_some(d)
            },
            _ => None,
        };
        let name = match dup {
            // the file name — in a separate thread with a timeout: a query to a file with a pending
            // synchronous operation (ReadDirectoryChangesW, a pipe read) waits for it to finish
            Some(d) if kind == "File" => match files.name(d) {
                Some(n) => n,
                None => {
                    files_stuck = true;
                    String::new()
                }
            },
            Some(d) => unsafe {
                let n = name_of(&kind, d);
                CloseHandle(d);
                n
            },
            None => String::new(),
        };
        list.push(Handle { handle: hv, kind, access: rd(e + 24, 4) as u32, name });
    }
    let mut by_type: Vec<_> = by_type.into_iter().collect();
    by_type.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Ok(Handles { list, total, names: dup_from.is_some(), by_type, files_skipped: files_stuck })
}

/// The current folder and environment variables of the process (from its PEB).
pub fn environment(pid: u32, create_time: i64) -> io::Result<Environment> {
    let h = open_checked(pid, create_time, PROCESS_VM_READ)?;
    let lp = nt::launch_params(h.raw())?;
    let mut vars: Vec<(String, String)> = lp
        .env
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        // “=C:=C:\…” — internal variables for the current folders of drives
        .filter(|s| !s.starts_with('='))
        .filter_map(|s| s.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    vars.sort_by_key(|a| a.0.to_lowercase());
    Ok(Environment { cwd: lp.cwd, vars })
}

