//! «Кто держит файл»: процессы, открывшие файл или файлы в папке, — через Restart Manager
//! (тот же механизм, которым установщики выясняют, что мешает заменить файл). Прав
//! администратора не требует; видит и службы.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use windows_sys::Win32::System::RestartManager::{RmEndSession, RmGetList, RmRegisterResources, RmStartSession, RM_PROCESS_INFO};

use crate::system::wide;

/// Больше файлов из папки не регистрируем: Restart Manager на тысячах файлов думает долго.
const MAX_FILES: usize = 3000;

#[derive(Clone, Debug, Serialize)]
pub struct Holder {
    pub pid: u32,
    /// Время создания процесса (как в замерах) — чтобы действие попало именно в него.
    pub create_time: i64,
    /// Имя приложения по мнению Restart Manager: заголовок окна или описание.
    pub app: String,
    /// Короткое имя службы, если файл держит служба.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// window, service, explorer, console, critical, other.
    pub kind: &'static str,
}

struct Session(u32);

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { RmEndSession(self.0) };
    }
}

fn files_of(path: &Path) -> Vec<PathBuf> {
    if !path.is_dir() {
        return vec![path.to_path_buf()];
    }
    let mut out = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(t) = e.file_type() else { continue };
            // ссылки на другие папки не обходим: можно уйти в цикл
            if t.is_dir() && !t.is_symlink() {
                stack.push(e.path());
            } else if t.is_file() {
                out.push(e.path());
                if out.len() >= MAX_FILES {
                    return out;
                }
            }
        }
    }
    out
}

fn wstr(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])
}

/// Процессы, которые держат файл (или любой файл внутри папки).
pub fn holders(path: &str) -> io::Result<Vec<Holder>> {
    let p = Path::new(path.trim().trim_matches('"'));
    if !p.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("нет такого файла или папки: {}", p.display())));
    }
    let files = files_of(p);
    let mut key = [0u16; 64]; // CCH_RM_SESSION_KEY + 1
    let mut h = 0u32;
    let r = unsafe { RmStartSession(&mut h, 0, key.as_mut_ptr()) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r as i32));
    }
    let session = Session(h);
    let wides: Vec<Vec<u16>> = files.iter().map(|f| wide(&f.to_string_lossy())).collect();
    for chunk in wides.chunks(500) {
        let ptrs: Vec<*const u16> = chunk.iter().map(|w| w.as_ptr()).collect();
        let r = unsafe { RmRegisterResources(session.0, ptrs.len() as u32, ptrs.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null()) };
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
    }
    let mut list: Vec<RM_PROCESS_INFO> = Vec::new();
    for _ in 0..5 {
        let (mut need, mut n, mut reasons) = (0u32, list.len() as u32, 0u32);
        let r = unsafe { RmGetList(session.0, &mut need, &mut n, list.as_mut_ptr(), &mut reasons) };
        match r {
            0 => {
                list.truncate(n as usize);
                break;
            }
            234 => list = vec![unsafe { std::mem::zeroed() }; need as usize + 4], // ERROR_MORE_DATA
            _ => return Err(io::Error::from_raw_os_error(r as i32)),
        }
    }
    Ok(list
        .iter()
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
            }
        })
        .collect())
}
