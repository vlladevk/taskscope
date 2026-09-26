//! Подробности одного процесса — как вкладки окна свойств процесса в System Informer:
//! модули, потоки, дескрипторы и окружение. Всё читается по запросу (вкладка процесса
//! открыта), а не в каждом замере: это дорого (таблица дескрипторов всей системы — мегабайты).

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::OnceLock;

use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, GetFinalPathNameByHandleW, FILE_TYPE_DISK, VOLUME_NAME_DOS};
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

/// Больше дескрипторов одного процесса не разбираем: у «течущих» процессов их сотни тысяч.
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
    /// Время ЦП ядра и пользователя, 100 нс — окно считает загрузку по разнице между запросами.
    pub kernel: i64,
    pub user: i64,
    pub create_time: i64,
    pub priority: i32,
    pub base_priority: i32,
    pub switches: u32,
    /// running, ready, waiting, suspended, standby, terminated, other.
    pub state: &'static str,
    pub wait_reason: u32,
    /// Точка входа потока: «модуль.dll+0x1a2b», как в System Informer.
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
    /// Всего дескрипторов у процесса (список может быть обрезан до MAX_HANDLES).
    pub total: usize,
    /// Удалось ли скопировать дескрипторы к себе, чтобы узнать имена (нет — у защищённых и чужих без прав).
    pub names: bool,
    /// Сколько дескрипторов какого типа — для сводки.
    pub by_type: Vec<(String, usize)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Environment {
    pub cwd: String,
    pub vars: Vec<(String, String)>,
}

fn open_checked(pid: u32, create_time: i64, access: u32) -> io::Result<ProcHandle> {
    ProcHandle::open(pid, access | PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time))
}

/// Загруженные модули (EXE и DLL), по адресу загрузки.
pub fn modules(pid: u32, create_time: i64) -> io::Result<Vec<Module>> {
    // проверка времени создания: PID мог достаться другому процессу
    drop(open_checked(pid, create_time, 0)?);
    let mut snap = ptr::null_mut();
    // ERROR_BAD_LENGTH: процесс как раз загружает модуль — повторяем
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

/// «модуль+0xСМЕЩЕНИЕ» по списку модулей (отсортирован по адресу).
fn symbolize(addr: u64, mods: &[Module]) -> String {
    let i = mods.partition_point(|m| m.base <= addr);
    match i.checked_sub(1).map(|i| &mods[i]) {
        Some(m) if addr < m.base + m.size as u64 => format!("{}+0x{:x}", m.name, addr - m.base),
        _ => format!("0x{addr:x}"),
    }
}

/// Потоки процесса из общего снимка (SYSTEM_THREAD_INFORMATION) и их точки входа.
pub fn threads(pid: u32, create_time: i64) -> io::Result<Vec<Thread>> {
    let buf = nt::query_system(5, 1 << 20)?;
    // смещения SYSTEM_PROCESS_INFORMATION (x64): число потоков, время создания, PID; потоки — сразу после 256 байт
    let rd32 = |o: usize| buf.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let rd64 = |o: usize| buf.get(o..o + 8).map_or(0, |b| i64::from_le_bytes(b.try_into().unwrap()));
    let mut off = 0usize;
    let entry = loop {
        if off + 256 > buf.len() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "процесс завершился"));
        }
        if rd64(off + 0x50) as u32 == pid && nt::js_safe(rd64(off + 32)) == create_time {
            break off;
        }
        let next = rd32(off) as usize;
        if next == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "процесс завершился"));
        }
        off += next;
    };
    let n = rd32(entry + 4) as usize;
    let mods = modules(pid, create_time).unwrap_or_default();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let t = entry + 256 + i * 80;
        if t + 80 > buf.len() {
            break;
        }
        let tid = rd64(t + 48) as u32;
        let (state, reason) = (rd32(t + 68), rd32(t + 72));
        // адрес из снимка — обычно RtlUserThreadStart; настоящая точка входа — Win32StartAddress (класс 9)
        let start = unsafe {
            // класс 9 требует полного права запроса; «ограниченного» хватает не везде
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

/// Имена типов объектов ядра по номеру (ObjectTypesInformation) — один раз за запуск.
fn type_names() -> &'static HashMap<u16, String> {
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
        // OBJECT_TYPE_INFORMATION — 104 байта (x64), за ним имя, выровненное по 8
        let mut off = 8usize;
        for i in 0..n {
            if off + 104 > b.len() {
                break;
            }
            let len = u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) as usize;
            let max = u16::from_le_bytes(b[off + 2..off + 4].try_into().unwrap()) as usize;
            let p = u64::from_le_bytes(b[off + 8..off + 16].try_into().unwrap()) as *const u16;
            let name = if p.is_null() { String::new() } else { String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len / 2) }) };
            // TypeIndex (Windows 8.1+); на старых системах номера идут с 2
            let idx = b[off + 90];
            map.insert(if idx != 0 { idx as u16 } else { i as u16 + 2 }, name);
            off += 104 + ((max + 7) & !7);
        }
        map
    })
}

/// «\REGISTRY\MACHINE\…» → «HKLM\…», «\REGISTRY\USER\<SID>…» → «HKCU…» (свой SID) или «HKU\…».
fn pretty_key(name: &str) -> String {
    static SID: OnceLock<Option<String>> = OnceLock::new();
    // регистр бывает любым: «\REGISTRY\MACHINE» и «\Registry\Machine»
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
                return format!("HKCU{tail}");
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
    // OBJECT_NAME_INFORMATION — UNICODE_STRING в начале буфера
    let b: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), 16) };
    let len = u16::from_le_bytes([b[0], b[1]]) as usize;
    let p = u64::from_le_bytes(b[8..16].try_into().unwrap()) as *const u16;
    if p.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len / 2) })
}

/// Имя объекта по скопированному дескриптору. Имена файлов-каналов не спрашиваем: запрос
/// к синхронному каналу может зависнуть навсегда (System Informer обходит это отдельным потоком).
fn name_of(kind: &str, h: HANDLE) -> String {
    match kind {
        "File" => {
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
        "Process" => format!("PID {}", unsafe { GetProcessId(h) }),
        "Thread" => format!("TID {}", unsafe { GetThreadId(h) }),
        "Key" => pretty_key(&object_name(h)),
        "Directory" | "Event" | "Mutant" | "Section" | "Semaphore" | "SymbolicLink" | "ALPC Port" | "WindowStation" | "Desktop" | "Timer"
        | "Job" | "Partition" => object_name(h),
        _ => String::new(),
    }
}

/// Дескрипторы процесса: тип, доступ и, где это безопасно, имя объекта.
pub fn handles(pid: u32, create_time: i64) -> io::Result<Handles> {
    let proc = open_checked(pid, create_time, 0)?;
    // копировать дескрипторы — нужен PROCESS_DUP_HANDLE; без него — только типы
    let dup_from = ProcHandle::open(pid, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, Some(create_time)).ok();
    drop(proc);
    // SystemExtendedHandleInformation (64): число, резерв, затем записи по 40 байт
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
        let name = match &dup_from {
            Some(src) => unsafe {
                let mut d: HANDLE = ptr::null_mut();
                if DuplicateHandle(src.raw(), hv as usize as HANDLE, me, &mut d, 0, 0, DUPLICATE_SAME_ACCESS) != 0 {
                    let n = name_of(&kind, d);
                    CloseHandle(d);
                    n
                } else {
                    String::new()
                }
            },
            None => String::new(),
        };
        list.push(Handle { handle: hv, kind, access: rd(e + 24, 4) as u32, name });
    }
    let mut by_type: Vec<_> = by_type.into_iter().collect();
    by_type.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Ok(Handles { list, total, names: dup_from.is_some(), by_type })
}

/// Текущая папка и переменные окружения процесса (из его PEB).
pub fn environment(pid: u32, create_time: i64) -> io::Result<Environment> {
    let h = open_checked(pid, create_time, PROCESS_VM_READ)?;
    let lp = nt::launch_params(h.raw())?;
    let mut vars: Vec<(String, String)> = lp
        .env
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        // «=C:=C:\…» — служебные переменные текущих папок дисков
        .filter(|s| !s.starts_with('='))
        .filter_map(|s| s.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    vars.sort_by_key(|a| a.0.to_lowercase());
    Ok(Environment { cwd: lp.cwd, vars })
}

