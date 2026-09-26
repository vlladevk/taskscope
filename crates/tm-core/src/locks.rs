//! «Кто держит файл»: процессы, открывшие файл или что-нибудь в папке.
//!
//! Файл — через Restart Manager (тот же механизм, которым установщики выясняют, что мешает
//! заменить файл): прав администратора не требует, видит и службы, для одного файла отвечает сразу
//! и знает названия окон и служб.
//!
//! Папка — двумя путями одновременно:
//! - таблица дескрипторов всей системы, как «Найти дескрипторы» в System Informer: один проход
//!   за секунду для папки любого размера (хоть весь C:\), с путями открытых файлов, но только
//!   у процессов, чьи дескрипторы можно прочитать (без прав администратора — у своих);
//! - обход папки с вопросом ядру про каждый файл и подпапку «кто тебя открыл»
//!   (FileProcessIdsUsingFileInformation): видит всех, включая службы, без прав администратора,
//!   но огромную папку за отведённое время не обойти — только он даёт «частично».
//!
//! Restart Manager для папок не годится: на 556 файлах он думал 39 секунд.

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

/// Обход папки — не дольше этого: огромные деревья (AppData, диск целиком) — частично.
const WALK_BUDGET: Duration = Duration::from_secs(3);
/// И не больше стольких файлов и подпапок.
const MAX_FILES: usize = 100_000;
/// Больше путей одного процесса в ответ не кладём.
const FILES_PER_HOLDER: usize = 5;
/// Имя файла может не ответить (на файле висит синхронная операция) — поток, который его
/// спросил, остаётся ждать, а проход продолжается с новым. После стольких зависших — стоп.
const MAX_STUCK: usize = 8;

#[derive(Clone, Debug, Serialize)]
pub struct Holder {
    pub pid: u32,
    /// Время создания процесса (как в замерах) — чтобы действие попало именно в него.
    pub create_time: i64,
    /// Имя приложения: у Restart Manager — заголовок окна или описание, иначе — имя файла программы.
    pub app: String,
    /// Короткое имя службы, если файл держит служба.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// window, service, explorer, console, critical, other.
    pub kind: &'static str,
    /// Какие пути внутри папки открыты (первые несколько).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Сколько всего открыто внутри папки (дескрипторов или найденных путей).
    #[serde(skip_serializing_if = "is_zero")]
    pub open: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Clone, Debug, Serialize)]
pub struct Holders {
    pub holders: Vec<Holder>,
    /// Сколько файлов и подпапок проверено обходом.
    pub files: usize,
    /// Папка обойдена не целиком, и есть процессы, чьи дескрипторы не прочитать, — «никто»
    /// тогда не окончательно (для них).
    pub truncated: bool,
    /// Файлы, которые не открыть даже для чтения атрибутов (нет доступа) — пропущены.
    pub skipped: usize,
    /// Папка проверена по таблице дескрипторов (целиком, у всех доступных процессов).
    pub scanned: bool,
    /// Процессы с открытыми файлами, чьи дескрипторы прочитать нельзя (службы, программы от
    /// администратора, защищённые процессы): для них — только обход папки.
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

/// Процессы, которые держат файл (или что-нибудь внутри папки).
pub fn holders(path: &str) -> io::Result<Holders> {
    let p = Path::new(path.trim().trim_matches('"'));
    if is_remote(p) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "сетевые пути не проверяются — только локальные диски"));
    }
    if !p.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("нет такого файла или папки: {}", p.display())));
    }
    if !p.is_dir() {
        let w = wide(&p.to_string_lossy());
        return Ok(finish(query(&[&w]).map_err(rm_err)?));
    }
    // если таблица дескрипторов прочитана у всех процессов, обход останавливаем, не дожидаясь:
    // он нужен только для недоступных
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
                // все процессы проверены по всей папке — пропуски обхода ничего не значат
                out.truncated = false;
                out.skipped = 0;
            }
            for h in scan.hits {
                let (service, kind) = names.service(h.pid);
                out.holders.push(Holder { pid: h.pid, create_time: h.create_time, app: h.image, service, kind, files: h.files, open: h.open });
            }
        }
        Err(e) => crate::logs::warn(format!("кто держит папку: таблица дескрипторов не прочитана: {e}")),
    }
    // найденное обходом — к процессам, которых нет в таблице (службы, программы от администратора)
    let me = std::process::id();
    let mut extra: Vec<(u32, Found)> = probe.found.into_iter().filter(|(pid, _)| *pid != me && *pid != 0).collect();
    extra.sort_by(|a, b| b.1.open.cmp(&a.1.open).then(a.0.cmp(&b.0)));
    for (pid, f) in extra {
        if let Some(h) = out.holders.iter_mut().find(|h| h.pid == pid) {
            // у доступного процесса пути уже есть из таблицы; если нет — хотя бы из обхода
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

/// Имена процессов и служб — по требованию, один раз на проверку.
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

// ───────────────────────────── обход папки: «кто тебя открыл» ─────────────────────────────

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

/// Процессы, открывшие этот файл или папку (FileProcessIdsUsingFileInformation, класс 47):
/// ядро знает само, прав администратора не нужно, службы видны. Открываем только для чтения
/// атрибутов — это не мешает чужим блокировкам и не будит антивирус. `None` — не открыть.
fn pids_using(path: &Path) -> Option<Vec<u32>> {
    let w = wide(&path.to_string_lossy());
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            // папки открываются только так; ссылки — сами по себе, не то, куда они ведут
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    // FILE_PROCESS_IDS_USING_FILE_INFORMATION: число (u32, выровнено до 8), затем PID по 8 байт
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

/// Папка целиком (с ней самой) — вопрос «кто тебя открыл» про каждый файл и подпапку.
fn probe_folder(root: &Path, stop: &AtomicBool) -> Probe {
    let started = Instant::now();
    let over = || started.elapsed() > WALK_BUDGET || stop.load(Ordering::Relaxed);
    // запрос дорогой (~40–90 мс: ядро перебирает дескрипторы всех процессов), но в несколько
    // потоков идёт почти во столько же раз быстрее: 44 файла — 2,8 с в один поток, 0,6 с в восемь
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
                    // время вышло — оставшееся в очереди только выбираем, не проверяя
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
        // папка в ширину: сначала верхние уровни — при обрезке проверено самое близкое к ней
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
                // ссылки на другие папки не обходим: можно уйти в цикл или на другой диск
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


// ───────────────────────────── таблица дескрипторов ─────────────────────────────

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
    /// Проход остановлен досрочно (слишком много файлов не ответило).
    incomplete: bool,
}

impl Scan {
    fn complete(&self) -> bool {
        self.unscanned == 0 && !self.incomplete
    }
}

/// Папка в виде ядра («\Device\HarddiskVolume3\Users\me») и как её вернуть к букве диска.
struct NtPath {
    /// Путь папки, строчными.
    target: String,
    /// «\Device\HarddiskVolume3», строчными.
    device: String,
    /// «C:».
    drive: String,
}

fn nt_path(p: &Path) -> io::Result<NtPath> {
    // настоящий путь: без «..», коротких имён 8.3, подставленных дисков (subst) и ссылок
    let c = std::fs::canonicalize(p)?;
    let s = c.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let drive = s.get(..2).filter(|d| d.ends_with(':')).ok_or_else(|| io::Error::other(format!("у папки нет буквы диска: {s}")))?;
    let mut dev = vec![0u16; 1024];
    let n = unsafe { QueryDosDeviceW(wide(drive).as_ptr(), dev.as_mut_ptr(), dev.len() as u32) };
    if n == 0 {
        return Err(io::Error::last_os_error());
    }
    let device = wstr(&dev).to_lowercase();
    let rest = s[2..].trim_end_matches('\\').to_lowercase();
    Ok(NtPath { target: format!("{device}{rest}"), device, drive: drive.to_string() })
}

/// Проход по открытым файлам всех процессов: кто держит что-нибудь внутри папки.
/// 200 тысяч дескрипторов (11 тысяч файлов у доступных процессов) — около секунды.
fn scan_folder(p: &Path) -> io::Result<Scan> {
    let nt = nt_path(p)?;
    let prefix = format!("{}\\", nt.target);
    let Some(file_type) = crate::inspect::type_names().iter().find(|(_, n)| n.as_str() == "File").map(|(&i, _)| i) else {
        return Err(io::Error::other("тип объекта File не найден"));
    };
    let _debug = DebugPrivilege::enable();
    // SystemExtendedHandleInformation (64): число, резерв, затем записи по 40 байт
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
        // себя не смотрим: проверка сама ничего в папке не держит
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
        // обратно к букве диска: «\Device\HarddiskVolume3\x» → «C:\x»
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

/// От администратора — право отладки (SeDebugPrivilege) на время прохода, чтобы прочитать
/// дескрипторы и системных процессов. Только в копии маркера этого потока: остальная программа
/// (завершение процессов!) работает с прежними правами.
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

// ───────────────────────────── Restart Manager (один файл) ─────────────────────────────

/// Один сеанс Restart Manager: регистрируем файлы и спрашиваем, кто их держит.
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
    // список всё время меняется — считаем отказом
    Err(234)
}

fn finish(list: Vec<RM_PROCESS_INFO>) -> Holders {
    let me = std::process::id();
    let mut seen = std::collections::HashSet::new();
    let holders = list
        .iter()
        .filter(|i| seen.insert((i.Process.dwProcessId, i.Process.ProcessStartTime.dwLowDateTime, i.Process.ProcessStartTime.dwHighDateTime)))
        // себя не показываем: проверка открывает файл сама
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
