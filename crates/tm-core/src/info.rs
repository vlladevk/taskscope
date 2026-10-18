//! Rarely changing process details: path, command line, description and publisher from the .exe.
//! Everything is cached by the key (PID, creation time), the file description by path.

use std::collections::HashMap;
use std::ffi::c_void;

use serde::Serialize;
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows_sys::Win32::System::Threading::{QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::handle::ProcHandle;
use crate::sampler::ProcKey;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ProcInfo {
    pub path: Option<String>,
    pub cmdline: Option<String>,
    /// FileDescription from the .exe resources, e.g. “Google Chrome”.
    pub description: Option<String>,
    pub company: Option<String>,
    /// false — no access (usually system processes without administrator rights).
    pub accessible: bool,
    /// The role inside the app from the command line: “GPU process”, “Service: Dnscache” and so on.
    #[serde(default)]
    pub role: Option<String>,
}

/// A helper Node.js in Electron (Claude, VS Code, Cursor) cannot be told apart by the command line; the
/// terminal host is recognised by the loaded node-pty.
fn node_host(pid: u32, create_time: i64, role: String) -> String {
    if role != "Node.js" {
        return role;
    }
    let pty = crate::inspect::modules(pid, create_time).is_ok_and(|ms| {
        ms.iter().any(|m| {
            let p = m.path.to_ascii_lowercase();
            p.ends_with("conpty.node") || p.ends_with("pty.node")
        })
    });
    if pty { "Terminals (node-pty)".into() } else { role }
}

/// A readable name for the process role from the command line (Chromium/Electron, svchost).
pub fn role_of(cmd: &str) -> Option<String> {
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let arg = |k: &str| toks.iter().find_map(|t| t.trim_matches('"').strip_prefix(k)).map(|v| v.trim_matches('"').to_string());
    if let Some(t) = arg("--type=") {
        return Some(match t.as_str() {
            "gpu-process" => "GPU process".into(),
            "renderer" if cmd.contains("--extension-process") => "Extension".into(),
            "renderer" if cmd.contains("--top-chrome-webui") => "Browser UI".into(),
            "renderer" => "Renderer (tab or window)".into(),
            "utility" => match arg("--utility-sub-type=") {
                Some(s) if s.starts_with("network.") => "Network service".into(),
                Some(s) if s.starts_with("storage.") => "Storage".into(),
                Some(s) if s.starts_with("audio.") => "Audio".into(),
                Some(s) if s.contains("video_capture") => "Camera".into(),
                Some(s) if s.starts_with("node.") => "Node.js".into(),
                Some(s) => format!("Utility process ({})", s.split('.').next().unwrap_or(&s)),
                None => "Utility process".into(),
            },
            "crashpad-handler" => "Crash reports".into(),
            other => other.to_string(),
        });
    }
    if cmd.to_ascii_lowercase().contains("svchost") {
        let next = |k: &str| toks.iter().position(|t| t.eq_ignore_ascii_case(k)).and_then(|i| toks.get(i + 1)).map(|s| s.to_string());
        if let Some(s) = next("-s") {
            return Some(format!("Service: {s}"));
        }
        if let Some(g) = next("-k") {
            return Some(format!("Service group: {g}"));
        }
    }
    None
}

#[derive(Clone, Default)]
struct FileMeta {
    description: Option<String>,
    company: Option<String>,
}

#[derive(Default)]
pub struct InfoCache {
    procs: HashMap<ProcKey, ProcInfo>,
    files: HashMap<String, FileMeta>,
}

impl InfoCache {
    pub fn get(&mut self, key: ProcKey) -> &ProcInfo {
        if !self.procs.contains_key(&key) {
            let info = self.load(key);
            self.procs.insert(key, info);
        }
        &self.procs[&key]
    }

    /// Removes entries of exited processes so the cache does not grow forever.
    pub fn retain_alive<'a>(&mut self, alive: impl Iterator<Item = &'a ProcKey>) {
        let alive: std::collections::HashSet<ProcKey> = alive.copied().collect();
        self.procs.retain(|k, _| alive.contains(k));
    }

    fn load(&mut self, (pid, create_time): ProcKey) -> ProcInfo {
        if pid == 0 || pid == 4 {
            return ProcInfo { accessible: false, ..Default::default() };
        }
        let h = match ProcHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time)) {
            Ok(h) => h,
            // the process exited or the PID was taken by another one — the path by PID would be someone else’s
            Err(e) if e.raw_os_error() != Some(5) => return ProcInfo::default(),
            // no rights (protected, another user’s without administrator rights) — we still get the path and
            // description: the path by PID needs no access to the process
            Err(_) => {
                let path = path_by_pid(pid);
                let meta = match &path {
                    Some(p) => self.files.entry(p.clone()).or_insert_with(|| file_meta(p)).clone(),
                    None => FileMeta::default(),
                };
                return ProcInfo { path, description: meta.description, company: meta.company, ..Default::default() };
            }
        };
        let path = image_path(&h);
        let cmdline = crate::nt::command_line(h.raw());
        let meta = match &path {
            Some(p) => self.files.entry(p.clone()).or_insert_with(|| file_meta(p)).clone(),
            None => FileMeta::default(),
        };
        // the role for Chromium and svchost; otherwise — what was started: a Claude Code session, a script, a jar, a command
        let exe = path.as_deref().map(|p| p.rsplit('\\').next().unwrap_or(p)).unwrap_or("");
        let role = cmdline.as_deref().and_then(|cmd| {
            role_of(cmd).map(|r| node_host(pid, create_time, r)).or_else(|| {
                if crate::labels::is_claude_code(exe, path.as_deref(), cmd) {
                    Some(crate::labels::claude_code(pid, create_time, cmd))
                } else {
                    crate::labels::from_cmdline(exe, cmd).or_else(|| crate::labels::shell_folder(pid, create_time, exe, cmd))
                }
            })
        });
        ProcInfo { path, cmdline, description: meta.description, company: meta.company, accessible: true, role }
    }
}

/// The process file path by PID without opening it (class 88) — in the usual “C:\…” form.
/// The PID may have been reused: the caller checks the creation time itself if it matters.
pub fn path_by_pid(pid: u32) -> Option<String> {
    crate::nt::image_path_by_pid(pid).and_then(|nt| dos_path(&nt))
}

/// “\Device\HarddiskVolume3\Windows\…” → “C:\Windows\…” using the disk device table.
pub fn dos_path(nt: &str) -> Option<String> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    // the table changes only when drives are attached — refresh once a minute
    static MAP: OnceLock<Mutex<(Option<Instant>, Vec<(String, String)>)>> = OnceLock::new();
    let mut m = MAP.get_or_init(|| Mutex::new((None, Vec::new()))).lock().unwrap_or_else(|e| e.into_inner());
    if m.0.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
        let mut v = Vec::new();
        for d in b'A'..=b'Z' {
            let drive = format!("{}:", d as char);
            let mut buf = vec![0u16; 512];
            let n = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 {
                let dev = String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]);
                if !dev.is_empty() {
                    v.push((dev.to_ascii_lowercase(), drive));
                }
            }
        }
        *m = (Some(Instant::now()), v);
    }
    let low = nt.to_ascii_lowercase();
    for (dev, drive) in &m.1 {
        if low.starts_with(dev.as_str()) && low[dev.len()..].starts_with('\\') {
            return Some(format!("{drive}{}", &nt[dev.len()..]));
        }
    }
    // “\??\C:\…” and “\SystemRoot\…” appear in early system processes
    if let Some(rest) = nt.strip_prefix(r"\??\") {
        return Some(rest.to_string());
    }
    if let Some(rest) = nt.strip_prefix(r"\SystemRoot\") {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        return Some(format!(r"{root}\{rest}"));
    }
    None
}

pub fn image_path(h: &ProcHandle) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h.raw(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn file_meta(path: &str) -> FileMeta {
    let wpath = wide(path);
    let mut dummy = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(wpath.as_ptr(), &mut dummy) };
    if size == 0 {
        return FileMeta::default();
    }
    let mut data = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(wpath.as_ptr(), 0, size, data.as_mut_ptr().cast()) } == 0 {
        return FileMeta::default();
    }
    // the first “language + code page” pair from the translation table, otherwise English Unicode
    let mut tr: *mut c_void = std::ptr::null_mut();
    let mut tr_len = 0u32;
    let lang = if unsafe { VerQueryValueW(data.as_ptr().cast(), wide("\\VarFileInfo\\Translation").as_ptr(), &mut tr, &mut tr_len) } != 0 && tr_len >= 4 {
        let pair = unsafe { std::slice::from_raw_parts(tr as *const u16, 2) };
        format!("{:04x}{:04x}", pair[0], pair[1])
    } else {
        "040904b0".to_string()
    };
    let query = |field: &str| -> Option<String> {
        let mut p: *mut c_void = std::ptr::null_mut();
        let mut n = 0u32;
        let q = wide(&format!("\\StringFileInfo\\{lang}\\{field}"));
        if unsafe { VerQueryValueW(data.as_ptr().cast(), q.as_ptr(), &mut p, &mut n) } == 0 || n == 0 {
            return None;
        }
        let s = unsafe { std::slice::from_raw_parts(p as *const u16, n as usize) };
        let s = String::from_utf16_lossy(s).trim_end_matches('\0').trim().to_string();
        (!s.is_empty()).then_some(s)
    };
    FileMeta { description: query("FileDescription"), company: query("CompanyName") }
}
