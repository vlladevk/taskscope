//! “Who holds the file”: processes that opened a file or anything in a folder.
//!
//! A file — through Restart Manager (the same mechanism installers use to find out what prevents
//! replacing a file): needs no administrator rights, sees services too, answers at once for a single file
//! and knows window and service names.
//!
//! A folder — two ways at once:
//! - the system-wide handle table, like “Find handles” in System Informer: one pass
//!   in a second for a folder of any size (even all of C:\), with paths of open files, but only
//!   for processes whose handles can be read (without administrator rights — your own);
//! - walking the folder and asking the kernel about every file and subfolder “who opened you”
//!   (FileProcessIdsUsingFileInformation): sees everyone, services included, without administrator rights,
//!   but a huge folder cannot be walked in the allotted time — only this one yields “partial”.
//!
//! Restart Manager is no good for folders: on 556 files it thought for 39 seconds.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueW, RevertToSelf, SecurityImpersonation, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, QueryDosDeviceW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::RestartManager::{RmEndSession, RmGetList, RmRegisterResources, RmStartSession, RM_PROCESS_INFO};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread, OpenThreadToken, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::handle::ProcHandle;
use crate::inspect::FileNamer;
use crate::system::wide;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQueryInformationFile(h: HANDLE, iosb: *mut [u64; 2], buf: *mut c_void, len: u32, class: i32) -> i32;
}

/// Walking the folder — no longer than this: huge trees (AppData, a whole drive) — partially.
const WALK_BUDGET: Duration = Duration::from_secs(3);
/// And no more than this many files and subfolders.
const MAX_FILES: usize = 100_000;
/// No more paths per process are put into the answer.
const FILES_PER_HOLDER: usize = 5;
/// A file name may not answer (a synchronous operation hangs on the file) — the thread that
/// asked stays waiting, and the pass continues with a new one. After this many hung ones — stop.
const MAX_STUCK: usize = 8;

#[derive(Clone, Debug, Serialize)]
pub struct Holder {
    pub pid: u32,
    /// Process creation time (as in the samples) — so the action hits exactly this process.
    pub create_time: i64,
    /// The app name: from Restart Manager — the window title or description, otherwise — the program file name.
    pub app: String,
    /// The short service name, if a service holds the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// window, service, explorer, console, critical, other.
    pub kind: &'static str,
    /// Which paths inside the folder are open (the first few).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// How many are open inside the folder in total (handles or found paths).
    #[serde(skip_serializing_if = "is_zero")]
    pub open: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Clone, Debug, Serialize)]
pub struct Holders {
    pub holders: Vec<Holder>,
    /// How many files and subfolders the walk checked.
    pub files: usize,
    /// The folder was not walked completely, and there are processes whose handles cannot be read — “nobody”
    /// is then not final (for them).
    pub truncated: bool,
    /// Files that cannot be opened even to read attributes (no access) — skipped.
    pub skipped: usize,
    /// The folder was checked against the handle table (completely, for all accessible processes).
    pub scanned: bool,
    /// Processes with open files whose handles cannot be read (services, programs running as
    /// administrator, protected processes): only the folder walk covers them.
    pub unscanned: usize,
}

struct Session(u32);

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { RmEndSession(self.0) };
    }
}

fn wstr(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])
}

/// Network paths are not accepted: accessing \\server\… would send the server the user’s
/// credentials (NTLM), and the path may come from an AI agent or a web page.
pub fn is_remote(p: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let s = p.to_string_lossy().replace('/', "\\");
    if s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\") {
        return true;
    }
    if s.to_ascii_uppercase().starts_with(r"\\?\UNC\") {
        return true;
    }
    // a mapped network drive (Z:) — the same server
    let root: String = s.chars().take(2).collect();
    if root.len() == 2 && root.ends_with(':') {
        const DRIVE_REMOTE: u32 = 4;
        return unsafe { GetDriveTypeW(wide(&format!("{root}\\")).as_ptr()) } == DRIVE_REMOTE;
    }
    false
}

fn rm_err(code: u32) -> io::Error {
    match code {
        5 => io::Error::new(io::ErrorKind::PermissionDenied, "no access — a service or the system holds the file, administrator rights required"),
        32 => io::Error::other("the file is in use by the system (for example, the page file or a log) — Restart Manager does not check it"),
        c => io::Error::from_raw_os_error(c as i32),
    }
}

/// Processes that hold the file (or anything inside the folder).
pub fn holders(path: &str) -> io::Result<Holders> {
    let p = Path::new(path.trim().trim_matches('"'));
    if is_remote(p) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "network paths are not checked — only local drives"));
    }
    if !p.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no such file or folder: {}", p.display())));
    }
    if !p.is_dir() {
        let w = wide(&p.to_string_lossy());
        return Ok(finish(query(&[&w]).map_err(rm_err)?));
    }
    // if the handle table was read for all processes, stop the walk without waiting:
    // it is only needed for the inaccessible ones
    let stop = AtomicBool::new(false);
    let (scan, probe) = std::thread::scope(|sc| {
        let probe = std::thread::Builder::new().name("tm-who-walk".into()).spawn_scoped(sc, || probe_folder(p, &stop));
        let scan = scan_folder(p);
        if scan.as_ref().is_ok_and(Scan::complete) {
            stop.store(true, Ordering::Relaxed);
        }
        (scan, probe.ok().and_then(|t| t.join().ok()).unwrap_or_default())
    });
    let mut out = Holders {
        holders: Vec::new(),
        files: probe.checked,
        truncated: probe.truncated,
        skipped: probe.skipped,
        scanned: false,
        unscanned: 0,
    };
    let mut names = Names::default();
    match scan {
        Ok(scan) => {
            out.scanned = true;
            out.unscanned = scan.unscanned;
            if scan.complete() {
                // all processes were checked across the whole folder — gaps in the walk mean nothing
                out.truncated = false;
                out.skipped = 0;
            }
            for h in scan.hits {
                let (service, kind) = names.service(h.pid);
                out.holders.push(Holder { pid: h.pid, create_time: h.create_time, app: h.image, service, kind, files: h.files, open: h.open });
            }
        }
        Err(e) => crate::logs::warn(format!("who holds the folder: the handle table was not read: {e}")),
    }
    // what the walk found — for processes missing from the table (services, programs running as administrator)
    let me = std::process::id();
    let mut extra: Vec<(u32, Found)> = probe.found.into_iter().filter(|(pid, _)| *pid != me && *pid != 0).collect();
    extra.sort_by(|a, b| b.1.open.cmp(&a.1.open).then(a.0.cmp(&b.0)));
    for (pid, f) in extra {
        if let Some(h) = out.holders.iter_mut().find(|h| h.pid == pid) {
            // an accessible process already has paths from the table; if not — at least from the walk
            if h.files.is_empty() {
                h.files = f.files;
                h.open = f.open;
            }
            continue;
        }
        let Some((create_time, image)) = names.process(pid) else { continue };
        let (service, kind) = names.service(pid);
        out.holders.push(Holder { pid, create_time, app: image, service, kind, files: f.files, open: f.open });
    }
    Ok(out)
}

/// Process and service names — on demand, once per check.
#[derive(Default)]
struct Names {
    procs: Option<HashMap<u32, (i64, String)>>,
    services: Option<HashMap<u32, Vec<String>>>,
}

impl Names {
    fn process(&mut self, pid: u32) -> Option<(i64, String)> {
        self.procs
            .get_or_insert_with(|| {
                let mut list = Vec::new();
                let _ = crate::nt::ProcessQuery::default().snapshot(&mut list);
                list.into_iter().map(|p| (p.pid, (crate::nt::js_safe(p.create_time), p.name))).collect()
            })
            .get(&pid)
            .cloned()
    }

    fn service(&mut self, pid: u32) -> (Option<String>, &'static str) {
        let map = self.services.get_or_insert_with(|| {
            let mut m: HashMap<u32, Vec<String>> = HashMap::new();
            for s in crate::services::list(false).unwrap_or_default() {
                if s.pid != 0 {
                    m.entry(s.pid).or_default().push(s.name);
                }
            }
            m
        });
        match map.get(&pid) {
            Some(v) => (Some(v.join(", ")), "service"),
            None => (None, "other"),
        }
    }
}

// ───────────────────────────── folder walk: “who opened you” ─────────────────────────────

#[derive(Default)]
struct Found {
    files: Vec<String>,
    open: usize,
}

#[derive(Default)]
struct Probe {
    found: HashMap<u32, Found>,
    checked: usize,
    skipped: usize,
    truncated: bool,
}

/// Processes that opened this file or folder (FileProcessIdsUsingFileInformation, class 47):
/// the kernel knows by itself, no administrator rights needed, services are visible. Opened only to read
/// attributes — this does not interfere with other locks and does not wake the antivirus. `None` — cannot open.
fn pids_using(path: &Path) -> Option<Vec<u32>> {
    let w = wide(&path.to_string_lossy());
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            // folders can be opened only this way; links — by themselves, not what they point to
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    // FILE_PROCESS_IDS_USING_FILE_INFORMATION: count (u32, aligned to 8), then 8-byte PIDs
    let mut buf = vec![0u64; 256];
    let out = loop {
        let mut iosb = [0u64; 2];
        let st = unsafe { NtQueryInformationFile(h, &mut iosb, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, 47) };
        if st == STATUS_INFO_LENGTH_MISMATCH && buf.len() < 1 << 16 {
            buf = vec![0u64; buf.len() * 8];
            continue;
        }
        if st < 0 {
            break None;
        }
        let n = (buf[0] as u32 as usize).min(buf.len() - 1);
        break Some(buf[1..=n].iter().map(|&p| p as u32).collect());
    };
    unsafe { CloseHandle(h) };
    out
}

/// The whole folder (including itself) — the “who opened you” question for every file and subfolder.
fn probe_folder(root: &Path, stop: &AtomicBool) -> Probe {
    let started = Instant::now();
    let over = || started.elapsed() > WALK_BUDGET || stop.load(Ordering::Relaxed);
    // the query is expensive (~40–90 ms: the kernel goes through the handles of all processes), but with several
    // threads it is almost that many times faster: 44 files — 2.8 s on one thread, 0.6 s on eight
    let workers = std::thread::available_parallelism().map_or(4, |n| (n.get() / 2).clamp(2, 8));
    let result = Mutex::new(Probe::default());
    let (tx, rx) = std::sync::mpsc::sync_channel::<PathBuf>(workers * 4);
    let rx = Mutex::new(rx);
    let mut truncated = false;
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| loop {
                let Ok(p) = rx.lock().unwrap_or_else(|e| e.into_inner()).recv() else { break };
                if over() {
                    // time is up — what is left in the queue is only drained, not checked
                    result.lock().unwrap_or_else(|e| e.into_inner()).truncated = true;
                    continue;
                }
                let pids = pids_using(&p);
                let mut r = result.lock().unwrap_or_else(|e| e.into_inner());
                let Some(pids) = pids else {
                    r.skipped += 1;
                    continue;
                };
                r.checked += 1;
                for pid in pids {
                    let f = r.found.entry(pid).or_default();
                    f.open += 1;
                    if f.files.len() < FILES_PER_HOLDER {
                        f.files.push(p.to_string_lossy().into_owned());
                    }
                }
            });
        }
        // the folder breadth-first: top levels first — when cut short, what is closest to it has been checked
        let mut sent = 1usize;
        let _ = tx.send(root.to_path_buf());
        let mut queue = VecDeque::from([root.to_path_buf()]);
        'walk: while let Some(d) = queue.pop_front() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                if over() || sent >= MAX_FILES {
                    truncated = true;
                    break 'walk;
                }
                let Ok(t) = e.file_type() else { continue };
                // links to other folders are not followed: that could loop or go to another drive
                if t.is_symlink() {
                    continue;
                }
                let path = e.path();
                if t.is_dir() {
                    queue.push_back(path.clone());
                }
                if tx.send(path).is_err() {
                    break 'walk;
                }
                sent += 1;
            }
        }
        drop(tx);
    });
    let mut pr = result.into_inner().unwrap_or_else(|e| e.into_inner());
    pr.truncated |= truncated;
    pr
}


// ───────────────────────────── handle table ─────────────────────────────

struct Hit {
    pid: u32,
    create_time: i64,
    image: String,
    files: Vec<String>,
    open: usize,
}

struct Scan {
    hits: Vec<Hit>,
    unscanned: usize,
    /// The pass stopped early (too many files did not answer).
    incomplete: bool,
}

impl Scan {
    fn complete(&self) -> bool {
        self.unscanned == 0 && !self.incomplete
    }
}

/// The folder in kernel form (“\Device\HarddiskVolume3\Users\me”) and how to map it back to a drive letter.
struct NtPath {
    /// The folder path, lower-case.
    target: String,
    /// “\Device\HarddiskVolume3”, lower-case.
    device: String,
    /// «C:».
    drive: String,
}

fn nt_path(p: &Path) -> io::Result<NtPath> {
    // the real path: without “..”, 8.3 short names, substituted drives (subst) and links
    let c = std::fs::canonicalize(p)?;
    let s = c.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let drive = s.get(..2).filter(|d| d.ends_with(':')).ok_or_else(|| io::Error::other(format!("the folder has no drive letter: {s}")))?;
    let mut dev = vec![0u16; 1024];
    let n = unsafe { QueryDosDeviceW(wide(drive).as_ptr(), dev.as_mut_ptr(), dev.len() as u32) };
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    let device = wstr(&dev).to_lowercase();
    let rest = s[2..].trim_end_matches('\\').to_lowercase();
    Ok(NtPath { target: format!("{device}{rest}"), device, drive: drive.to_string() })
}

/// A pass over the open files of all processes: who holds anything inside the folder.
/// 200 thousand handles (11 thousand files of accessible processes) — about a second.
fn scan_folder(p: &Path) -> io::Result<Scan> {
    let nt = nt_path(p)?;
    let prefix = format!("{}\\", nt.target);
    let Some(file_type) = crate::inspect::type_names().iter().find(|(_, n)| n.as_str() == "File").map(|(&i, _)| i) else {
        return Err(io::Error::other("the File object type was not found"));
    };
    let _debug = DebugPrivilege::enable();
    // SystemExtendedHandleInformation (64): count, reserved, then 40-byte entries
    let buf = crate::nt::query_system(64, 8 << 20)?;
    let rd = |o: usize, n: usize| -> u64 {
        let mut a = [0u8; 8];
        a[..n].copy_from_slice(&buf[o..o + n]);
        u64::from_le_bytes(a)
    };
    let count = rd(0, 8) as usize;
    let (me_pid, me) = (std::process::id(), unsafe { GetCurrentProcess() });
    let mut procs: HashMap<u32, Option<(ProcHandle, i64)>> = HashMap::new();
    let mut hits: HashMap<u32, Hit> = HashMap::new();
    let mut unscanned = HashSet::new();
    let mut namer = FileNamer::new(crate::inspect::nt_file_name);
    let (mut stuck, mut incomplete) = (0usize, false);
    for i in 0..count {
        let e = 16 + i * 40;
        if e + 40 > buf.len() {
            break;
        }
        if rd(e + 30, 2) as u16 != file_type {
            continue;
        }
        let pid = rd(e + 8, 8) as u32;
        // skip ourselves: the check itself holds nothing in the folder
        if pid == me_pid {
            continue;
        }
        let src = procs.entry(pid).or_insert_with(|| {
            let h = ProcHandle::open(pid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, None).ok()?;
            let ct = h.create_time().ok()?;
            Some((h, ct))
        });
        let Some((src, ct)) = src else {
            unscanned.insert(pid);
            continue;
        };
        let mut d: HANDLE = std::ptr::null_mut();
        if unsafe { DuplicateHandle(src.raw(), rd(e + 16, 8) as usize as HANDLE, me, &mut d, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
            continue;
        }
        let Some(name) = namer.name(d) else {
            stuck += 1;
            if stuck >= MAX_STUCK {
                incomplete = true;
                break;
            }
            namer = FileNamer::new(crate::inspect::nt_file_name);
            continue;
        };
        let low = name.to_lowercase();
        if low != nt.target && !low.starts_with(&prefix) {
            continue;
        }
        let ct = *ct;
        let h = hits.entry(pid).or_insert_with(|| Hit { pid, create_time: ct, image: String::new(), files: Vec::new(), open: 0 });
        h.open += 1;
        // back to the drive letter: “\Device\HarddiskVolume3\x” → “C:\x”
        let dos = format!("{}{}", nt.drive, name.get(nt.device.len()..).unwrap_or(""));
        if h.files.len() < FILES_PER_HOLDER && !h.files.contains(&dos) {
            h.files.push(dos);
        }
    }
    for h in hits.values_mut() {
        if let Some(Some((src, _))) = procs.get(&h.pid) {
            h.image = crate::info::image_path(src).map(|p| p.rsplit('\\').next().unwrap_or(&p).to_string()).unwrap_or_default();
        }
    }
    let mut hits: Vec<Hit> = hits.into_values().collect();
    hits.sort_by(|a, b| b.open.cmp(&a.open).then(a.pid.cmp(&b.pid)));
    Ok(Scan { hits, unscanned: unscanned.len(), incomplete })
}

/// As administrator — the debug privilege (SeDebugPrivilege) for the duration of the pass, to read
/// the handles of system processes too. Only in a copy of this thread’s token: the rest of the program
/// (ending processes!) works with the previous rights.
struct DebugPrivilege(bool);

impl DebugPrivilege {
    fn enable() -> Self {
        if !crate::system::is_elevated() || unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Self(false);
        }
        unsafe {
            let mut tok: HANDLE = std::ptr::null_mut();
            if OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 0, &mut tok) != 0 {
                let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
                tp.PrivilegeCount = 1;
                if LookupPrivilegeValueW(std::ptr::null(), wide("SeDebugPrivilege").as_ptr(), &mut tp.Privileges[0].Luid) != 0 {
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    AdjustTokenPrivileges(tok, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
                }
                CloseHandle(tok);
            }
        }
        Self(true)
    }
}

impl Drop for DebugPrivilege {
    fn drop(&mut self) {
        if self.0 {
            unsafe { RevertToSelf() };
        }
    }
}

// ───────────────────────────── Restart Manager (one file) ─────────────────────────────

/// One Restart Manager session: register the files and ask who holds them.
fn query(files: &[&[u16]]) -> Result<Vec<RM_PROCESS_INFO>, u32> {
    let mut key = [0u16; 64]; // CCH_RM_SESSION_KEY + 1
    let mut h = 0u32;
    let r = unsafe { RmStartSession(&mut h, 0, key.as_mut_ptr()) };
    if r != 0 {
        return Err(r);
    }
    let session = Session(h);
    let ptrs: Vec<*const u16> = files.iter().map(|w| w.as_ptr()).collect();
    let r = unsafe { RmRegisterResources(session.0, ptrs.len() as u32, ptrs.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null()) };
    if r != 0 {
        return Err(r);
    }
    let mut list: Vec<RM_PROCESS_INFO> = Vec::new();
    for _ in 0..5 {
        let (mut need, mut n, mut reasons) = (0u32, list.len() as u32, 0u32);
        let r = unsafe { RmGetList(session.0, &mut need, &mut n, list.as_mut_ptr(), &mut reasons) };
        match r {
            0 => {
                list.truncate(n as usize);
                return Ok(list);
            }
            234 => list = vec![unsafe { std::mem::zeroed() }; need as usize + 4], // ERROR_MORE_DATA
            _ => return Err(r),
        }
    }
    // the list keeps changing — treat it as a failure
    Err(234)
}

fn finish(list: Vec<RM_PROCESS_INFO>) -> Holders {
    let me = std::process::id();
    let mut seen = std::collections::HashSet::new();
    let holders = list
        .iter()
        .filter(|i| seen.insert((i.Process.dwProcessId, i.Process.ProcessStartTime.dwLowDateTime, i.Process.ProcessStartTime.dwHighDateTime)))
        // do not show ourselves: the check opens the file itself
        .filter(|i| i.Process.dwProcessId != me && i.Process.dwProcessId != 0)
        .map(|i| {
            let ft = i.Process.ProcessStartTime;
            let service = wstr(&i.strServiceShortName);
            Holder {
                pid: i.Process.dwProcessId,
                create_time: crate::nt::js_safe(((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64),
                app: wstr(&i.strAppName),
                service: (!service.is_empty()).then_some(service),
                kind: match i.ApplicationType {
                    1 => "window",
                    2 => "other",
                    3 => "service",
                    4 => "explorer",
                    5 => "console",
                    1000 => "critical",
                    _ => "other",
                },
                files: Vec::new(),
                open: 0,
            }
        })
        .collect();
    Holders { holders, files: 1, truncated: false, skipped: 0, scanned: false, unscanned: 0 }
}
