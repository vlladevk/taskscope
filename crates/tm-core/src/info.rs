//! Редко меняющиеся сведения о процессе: путь, командная строка, описание и издатель из .exe.
//! Всё кэшируется по ключу (PID, время создания), описание файла — по пути.

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
    /// FileDescription из ресурсов .exe, например «Google Chrome».
    pub description: Option<String>,
    pub company: Option<String>,
    /// false — нет доступа (обычно системные процессы без прав администратора).
    pub accessible: bool,
    /// Роль внутри приложения по командной строке: «GPU-процесс», «Служба: Dnscache» и т.п.
    #[serde(default)]
    pub role: Option<String>,
}

/// Понятное имя роли процесса по командной строке (Chromium/Electron, svchost).
pub fn role_of(cmd: &str) -> Option<String> {
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let arg = |k: &str| toks.iter().find_map(|t| t.trim_matches('"').strip_prefix(k)).map(|v| v.trim_matches('"').to_string());
    if let Some(t) = arg("--type=") {
        return Some(match t.as_str() {
            "gpu-process" => "GPU-процесс".into(),
            "renderer" if cmd.contains("--extension-process") => "Расширение".into(),
            "renderer" => "Рендерер (вкладка или окно)".into(),
            "utility" => match arg("--utility-sub-type=") {
                Some(s) if s.starts_with("network.") => "Сетевая служба".into(),
                Some(s) if s.starts_with("storage.") => "Хранилище".into(),
                Some(s) if s.starts_with("audio.") => "Аудио".into(),
                Some(s) if s.contains("video_capture") => "Камера".into(),
                Some(s) if s.starts_with("node.") => "Node.js".into(),
                Some(s) => format!("Служебный процесс ({})", s.split('.').next().unwrap_or(&s)),
                None => "Служебный процесс".into(),
            },
            "crashpad-handler" => "Отчёты о сбоях".into(),
            other => other.to_string(),
        });
    }
    if cmd.to_ascii_lowercase().contains("svchost") {
        let next = |k: &str| toks.iter().position(|t| t.eq_ignore_ascii_case(k)).and_then(|i| toks.get(i + 1)).map(|s| s.to_string());
        if let Some(s) = next("-s") {
            return Some(format!("Служба: {s}"));
        }
        if let Some(g) = next("-k") {
            return Some(format!("Группа служб: {g}"));
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

    /// Убирает записи о завершившихся процессах, чтобы кэш не рос бесконечно.
    pub fn retain_alive<'a>(&mut self, alive: impl Iterator<Item = &'a ProcKey>) {
        let alive: std::collections::HashSet<ProcKey> = alive.copied().collect();
        self.procs.retain(|k, _| alive.contains(k));
    }

    fn load(&mut self, (pid, create_time): ProcKey) -> ProcInfo {
        if pid == 0 || pid == 4 {
            return ProcInfo { accessible: false, ..Default::default() };
        }
        let Ok(h) = ProcHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time)) else {
            return ProcInfo::default();
        };
        let path = image_path(&h);
        let cmdline = crate::nt::command_line(h.raw());
        let meta = match &path {
            Some(p) => self.files.entry(p.clone()).or_insert_with(|| file_meta(p)).clone(),
            None => FileMeta::default(),
        };
        let role = cmdline.as_deref().and_then(role_of);
        ProcInfo { path, cmdline, description: meta.description, company: meta.company, accessible: true, role }
    }
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
    // первая пара «язык + кодовая страница» из таблицы переводов, иначе английский Unicode
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
