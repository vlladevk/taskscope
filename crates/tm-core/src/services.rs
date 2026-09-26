//! Службы Windows: список (EnumServicesStatusEx), какие службы живут в каком процессе
//! (имена служб у svchost.exe — как в System Informer), запуск, остановка и перезапуск.

use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W, QueryServiceConfigW,
    QueryServiceStatusEx, StartServiceW, ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_STOP, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATE_ALL,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_WIN32, SERVICE_WIN32_SHARE_PROCESS,
};

use crate::system::wide;

/// Службы, без которых Windows перестаёт работать (вход, RPC, COM, питание, устройства).
/// Их не останавливаем без явного «принудительно»: System Informer тоже предупреждает.
const CRITICAL: &[&str] = &[
    "rpcss", "rpceptmapper", "dcomlaunch", "lsm", "brokerinfrastructure", "samss", "plugplay", "power",
    "coremessagingregistrar", "systemeventsbroker", "profsvc", "gpsvc", "eventlog", "winlogon", "lsass",
];

#[derive(Clone, Debug, Serialize)]
pub struct ServiceInfo {
    /// Короткое имя: Dnscache, wuauserv.
    pub name: String,
    /// Отображаемое имя: «DNS-клиент».
    pub display: String,
    /// running, stopped, start_pending, stop_pending, paused, …
    pub state: &'static str,
    /// Процесс службы (0 — не запущена).
    pub pid: u32,
    /// auto, auto_delayed, manual, disabled, boot, system (пусто — неизвестно).
    pub start: &'static str,
    /// Живёт в общем процессе svchost вместе с другими службами.
    pub shared: bool,
    /// Служба принимает команду остановки.
    pub can_stop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Системная: без неё Windows работать не будет.
    pub critical: bool,
}

/// Дескриптор диспетчера служб или службы, закрывается сам.
struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn last_err(what: &str) -> io::Error {
    let code = unsafe { GetLastError() };
    match code {
        5 => io::Error::new(io::ErrorKind::PermissionDenied, format!("{what}: нужны права администратора")),
        1060 => io::Error::new(io::ErrorKind::NotFound, format!("{what}: такой службы нет")),
        _ => io::Error::other(format!("{what}: {}", io::Error::from_raw_os_error(code as i32))),
    }
}

fn manager(access: u32) -> io::Result<Sc> {
    let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if h.is_null() {
        return Err(last_err("диспетчер служб"));
    }
    Ok(Sc(h))
}

fn pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let n = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

fn state_name(s: u32) -> &'static str {
    match s {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => "unknown",
    }
}

pub fn is_critical(name: &str) -> bool {
    CRITICAL.contains(&name.to_ascii_lowercase().as_str())
}

/// Тип запуска и описание меняются редко, а спрашивать их надо у каждой службы отдельно —
/// кэшируем на 5 минут.
fn config_of(scm: &Sc, name: &str) -> (&'static str, Option<String>) {
    type Cache = HashMap<String, (Instant, &'static str, Option<String>)>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some((at, s, d)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(name) {
        if at.elapsed() < Duration::from_secs(300) {
            return (s, d.clone());
        }
    }
    let h = Sc(unsafe { OpenServiceW(scm.0, wide(name).as_ptr(), SERVICE_QUERY_CONFIG) });
    if h.0.is_null() {
        return ("", None);
    }
    let mut buf = vec![0u64; 1024];
    let mut need = 0u32;
    let start = if unsafe { QueryServiceConfigW(h.0, buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(), (buf.len() * 8) as u32, &mut need) } != 0 {
        // SAFETY: буфер заполнен структурой QUERY_SERVICE_CONFIGW.
        let c = unsafe { &*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
        match c.dwStartType {
            0 => "boot",
            1 => "system",
            2 => {
                let mut d = [0u32; 2];
                let delayed = unsafe { QueryServiceConfig2W(h.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, d.as_mut_ptr().cast(), 8, &mut need) } != 0 && d[0] != 0;
                if delayed {
                    "auto_delayed"
                } else {
                    "auto"
                }
            }
            3 => "manual",
            4 => "disabled",
            _ => "",
        }
    } else {
        ""
    };
    let desc = if unsafe { QueryServiceConfig2W(h.0, SERVICE_CONFIG_DESCRIPTION, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) } != 0 {
        // SAFETY: в начале буфера — SERVICE_DESCRIPTIONW (указатель на строку в том же буфере).
        let p = unsafe { *buf.as_ptr().cast::<*const u16>() };
        let s = pwstr(p);
        // описания вида «@%SystemRoot%\system32\x.dll,-100» — ресурс, который не удалось прочитать
        (!s.is_empty() && !s.starts_with('@')).then_some(s)
    } else {
        None
    };
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), (Instant::now(), start, desc.clone()));
    (start, desc)
}

/// Все службы (без драйверов). `details` — ещё и тип запуска с описанием (дольше: по запросу на службу).
pub fn list(details: bool) -> io::Result<Vec<ServiceInfo>> {
    let scm = manager(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;
    // не больше 256 КБ: с буфером крупнее служба управления отвечает ошибкой 1783
    // (RPC_X_BAD_STUB_DATA); остальное дочитывается по resume
    let mut buf: Vec<u64> = vec![0; 32 * 1024];
    let mut out = Vec::new();
    let mut resume = 0u32;
    loop {
        let (mut need, mut count) = (0u32, 0u32);
        let ok = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut need,
                &mut count,
                &mut resume,
                std::ptr::null(),
            )
        };
        let more = ok == 0 && unsafe { GetLastError() } == 234; // ERROR_MORE_DATA
        if ok == 0 && !more {
            return Err(last_err("список служб"));
        }
        // SAFETY: EnumServicesStatusExW положил в буфер count структур, строки — в том же буфере.
        let items = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize) };
        for s in items {
            let st = &s.ServiceStatusProcess;
            let name = pwstr(s.lpServiceName);
            let (start, description) = if details { config_of(&scm, &name) } else { ("", None) };
            out.push(ServiceInfo {
                critical: is_critical(&name),
                display: pwstr(s.lpDisplayName),
                state: state_name(st.dwCurrentState),
                pid: st.dwProcessId,
                start,
                shared: st.dwServiceType & SERVICE_WIN32_SHARE_PROCESS != 0,
                can_stop: st.dwControlsAccepted & SERVICE_ACCEPT_STOP != 0,
                description,
                name,
            });
        }
        if !more {
            break;
        }
        if count == 0 {
            // буфер мал даже для одной записи
            buf.resize((need as usize).div_ceil(8) + 1024, 0);
        }
    }
    out.sort_by(|a, b| a.display.to_lowercase().cmp(&b.display.to_lowercase()));
    Ok(out)
}

/// Запущенные службы по PID процесса: у svchost.exe — какие именно службы внутри.
pub fn by_pid() -> HashMap<u32, Vec<ServiceInfo>> {
    let mut m: HashMap<u32, Vec<ServiceInfo>> = HashMap::new();
    for s in list(false).unwrap_or_default().into_iter().filter(|s| s.pid != 0) {
        m.entry(s.pid).or_default().push(s);
    }
    m
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Start,
    Stop,
    Restart,
}

fn status(h: &Sc) -> Option<SERVICE_STATUS_PROCESS> {
    let mut st: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut need = 0u32;
    let ok = unsafe {
        QueryServiceStatusEx(h.0, SC_STATUS_PROCESS_INFO, (&mut st as *mut SERVICE_STATUS_PROCESS).cast(), std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut need)
    };
    (ok != 0).then_some(st)
}

fn wait_state(h: &Sc, want: u32, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if status(h).is_some_and(|s| s.dwCurrentState == want) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

/// Запуск, остановка или перезапуск службы. Системные (`CRITICAL`) останавливаются только с `force`.
/// Возвращает итоговое состояние.
pub fn control(name: &str, what: Control, force: bool) -> io::Result<&'static str> {
    if what != Control::Start && is_critical(name) && !force {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{name} — системная служба: без неё Windows перестанет работать как надо (нужно подтверждение)"),
        ));
    }
    let scm = manager(SC_MANAGER_CONNECT)?;
    let access = SERVICE_QUERY_STATUS
        | match what {
            Control::Start => SERVICE_START,
            Control::Stop => SERVICE_STOP,
            Control::Restart => SERVICE_START | SERVICE_STOP,
        };
    let h = Sc(unsafe { OpenServiceW(scm.0, wide(name).as_ptr(), access) });
    if h.0.is_null() {
        return Err(last_err(name));
    }
    if matches!(what, Control::Stop | Control::Restart) && status(&h).is_some_and(|s| s.dwCurrentState != 1) {
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { ControlService(h.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
            let code = unsafe { GetLastError() };
            return Err(match code {
                1051 => io::Error::other(format!("{name}: сначала остановите зависимые от неё службы")),
                1052 => io::Error::other(format!("{name}: служба не принимает команду остановки")),
                _ => last_err(name),
            });
        }
        if what == Control::Restart && !wait_state(&h, 1, Duration::from_secs(30)) {
            return Err(io::Error::other(format!("{name}: не остановилась за 30 с — запуск отменён")));
        }
    }
    if matches!(what, Control::Start | Control::Restart) && unsafe { StartServiceW(h.0, 0, std::ptr::null()) } == 0 {
        let code = unsafe { GetLastError() };
        if code != 1056 {
            // 1056 — уже запущена
            return Err(match code {
                1058 => io::Error::other(format!("{name}: служба отключена (тип запуска «Отключена»)")),
                _ => last_err(name),
            });
        }
    }
    // короткое ожидание, чтобы ответить уже итоговым состоянием
    let want = if what == Control::Stop { 1 } else { 4 };
    wait_state(&h, want, Duration::from_secs(5));
    Ok(status(&h).map_or("unknown", |s| state_name(s.dwCurrentState)))
}
