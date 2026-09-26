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
        let h = match ProcHandle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time)) {
            Ok(h) => h,
            // процесс завершился или PID занят другим — путь по PID был бы чужой
            Err(e) if e.raw_os_error() != Some(5) => return ProcInfo::default(),
            // нет прав (защищённый, чужой без прав администратора) — путь и описание
            // всё равно узнаём: путь по PID не требует доступа к процессу
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
        let role = cmdline.as_deref().and_then(role_of);
        ProcInfo { path, cmdline, description: meta.description, company: meta.company, accessible: true, role }
    }
}

/// Путь к файлу процесса по PID без его открытия (класс 88) — в обычном виде «C:\…».
/// PID может оказаться переиспользован: вызывающий сверяет время создания сам, если это важно.
pub fn path_by_pid(pid: u32) -> Option<String> {
    crate::nt::image_path_by_pid(pid).and_then(|nt| dos_path(&nt))
}

/// «\Device\HarddiskVolume3\Windows\…» → «C:\Windows\…» по таблице устройств дисков.
pub fn dos_path(nt: &str) -> Option<String> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    // таблица меняется только при подключении дисков — обновляем раз в минуту
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
    // «\??\C:\…» и «\SystemRoot\…» встречаются у ранних системных процессов
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
