//! «Кто держит файл»: процессы, открывшие файл или файлы в папке, — через Restart Manager
//! (тот же механизм, которым установщики выясняют, что мешает заменить файл). Прав
//! администратора не требует; видит и службы.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::Win32::System::RestartManager::{RmEndSession, RmGetList, RmRegisterResources, RmStartSession, RM_PROCESS_INFO};

use crate::system::wide;

/// Больше файлов из папки не регистрируем: Restart Manager на тысячах файлов думает долго.
const MAX_FILES: usize = 1000;
/// И не обходим папку дольше этого: огромные деревья (AppData, диск целиком) — частично.
const WALK_BUDGET: Duration = Duration::from_secs(2);
/* Restart Manager на тысячах файлов отвечает десятками секунд: вся проверка — не дольше этого */
const QUERY_BUDGET: Duration = Duration::from_secs(15);

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

#[derive(Clone, Debug, Serialize)]
pub struct Holders {
    pub holders: Vec<Holder>,
    /// Сколько файлов проверено (для папки).
    pub files: usize,
    /// Папка проверена не целиком (слишком много файлов или долго) — «никто» тогда не окончательно.
    pub truncated: bool,
    /// Файлы, которые Restart Manager не принял (нет доступа, заняты системой) — пропущены.
    pub skipped: usize,
}

struct Session(u32);

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { RmEndSession(self.0) };
    }
}

/// Файлы папки в ширину: сначала верхние уровни — при обрезке проверено самое близкое к папке.
fn files_of(path: &Path) -> (Vec<PathBuf>, bool) {
    if !path.is_dir() {
        return (vec![path.to_path_buf()], false);
    }
    let started = Instant::now();
    let mut out = Vec::new();
    let mut queue = VecDeque::from([path.to_path_buf()]);
    while let Some(d) = queue.pop_front() {
        if started.elapsed() > WALK_BUDGET {
            return (out, true);
        }
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(t) = e.file_type() else { continue };
            // ссылки на другие папки не обходим: можно уйти в цикл
            if t.is_dir() && !t.is_symlink() {
                queue.push_back(e.path());
            } else if t.is_file() {
                out.push(e.path());
                if out.len() >= MAX_FILES {
                    return (out, true);
                }
            }
        }
    }
    (out, false)
}

fn wstr(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])
}

/// Сетевые пути не принимаем: обращение к \\сервер\… отправило бы серверу учётные данные
/// пользователя (NTLM), а путь может прийти от ИИ-агента или веб-страницы.
pub fn is_remote(p: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let s = p.to_string_lossy().replace('/', "\\");
    if s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\") {
        return true;
    }
    if s.to_ascii_uppercase().starts_with(r"\\?\UNC\") {
        return true;
    }
    // подключённый сетевой диск (Z:) — тот же сервер
    let root: String = s.chars().take(2).collect();
    if root.len() == 2 && root.ends_with(':') {
        const DRIVE_REMOTE: u32 = 4;
        return unsafe { GetDriveTypeW(wide(&format!("{root}\\")).as_ptr()) } == DRIVE_REMOTE;
    }
    false
}

fn rm_err(code: u32) -> io::Error {
    match code {
        5 => io::Error::new(io::ErrorKind::PermissionDenied, "нет доступа — файл держит служба или система, нужны права администратора"),
        32 => io::Error::other("файл занят системой (например, файл подкачки или журнал) — Restart Manager его не проверяет"),
        c => io::Error::from_raw_os_error(c as i32),
    }
}

/// Процессы, которые держат файл (или любой файл внутри папки).
pub fn holders(path: &str) -> io::Result<Holders> {
    let p = Path::new(path.trim().trim_matches('"'));
    if is_remote(p) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "сетевые пути не проверяются — только локальные диски"));
    }
    if !p.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("нет такого файла или папки: {}", p.display())));
    }
    let (files, truncated) = files_of(p);
    let wides: Vec<Vec<u16>> = files.iter().map(|f| wide(&f.to_string_lossy())).collect();
    let all: Vec<&[u16]> = wides.iter().map(Vec::as_slice).collect();
    if all.len() == 1 {
        return Ok(finish(query(&all).map_err(rm_err)?, 1, false, 0));
    }
    // папка: один «трудный» файл (нет доступа, занят системой, исчез на ходу) срывает весь запрос —
    // тогда делим пачку пополам и проверяем части; трудные файлы пропускаем
    let mut st = Split { list: Vec::new(), checked: 0, skipped: 0, queries: 0, truncated, until: Instant::now() + QUERY_BUDGET };
    split(&all, &mut st);
    Ok(finish(st.list, st.checked, st.truncated, st.skipped))
}

/// Не больше стольких обращений к Restart Manager за одну проверку папки.
const MAX_QUERIES: usize = 40;

struct Split {
    list: Vec<RM_PROCESS_INFO>,
    checked: usize,
    skipped: usize,
    queries: usize,
    truncated: bool,
    until: Instant,
}

fn split(files: &[&[u16]], st: &mut Split) {
    if files.is_empty() {
        return;
    }
    if st.queries >= MAX_QUERIES || Instant::now() > st.until {
        // не проверены (кончилось время) — это «частично», а не «нет доступа»
        st.truncated = true;
        return;
    }
    st.queries += 1;
    match query(files) {
        Ok(l) => {
            st.list.extend(l);
            st.checked += files.len();
        }
        Err(_) if files.len() == 1 => st.skipped += 1,
        Err(_) => {
            let (a, b) = files.split_at(files.len() / 2);
            split(a, st);
            split(b, st);
        }
    }
}

/// Один сеанс Restart Manager: регистрируем файлы и спрашиваем, кто их держит.
fn query(files: &[&[u16]]) -> Result<Vec<RM_PROCESS_INFO>, u32> {
    let mut key = [0u16; 64]; // CCH_RM_SESSION_KEY + 1
    let mut h = 0u32;
    let r = unsafe { RmStartSession(&mut h, 0, key.as_mut_ptr()) };
    if r != 0 {
        return Err(r);
    }
    let session = Session(h);
    for chunk in files.chunks(500) {
        let ptrs: Vec<*const u16> = chunk.iter().map(|w| w.as_ptr()).collect();
        let r = unsafe { RmRegisterResources(session.0, ptrs.len() as u32, ptrs.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null()) };
        if r != 0 {
            return Err(r);
        }
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
    // список всё время меняется — считаем отказом этой пачки
    Err(234)
}

fn finish(list: Vec<RM_PROCESS_INFO>, files: usize, truncated: bool, skipped: usize) -> Holders {
    let me = std::process::id();
    let mut seen = std::collections::HashSet::new();
    let holders = list
        .iter()
        // из разных пачек один процесс приходит несколько раз
        .filter(|i| seen.insert((i.Process.dwProcessId, i.Process.ProcessStartTime.dwLowDateTime, i.Process.ProcessStartTime.dwHighDateTime)))
        // себя не показываем: проверка открывает файлы сама
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
            }
        })
        .collect();
    Holders { holders, files, truncated, skipped }
}
