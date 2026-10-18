//! Windows services: the list (EnumServicesStatusEx), which services live in which process
//! (service names for svchost.exe — as in System Informer), start, stop and restart.

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

/// Services without which Windows stops working (sign-in, RPC, COM, power, devices).
/// They are not stopped without an explicit “force”: System Informer warns about them too.
const CRITICAL: &[&str] = &[
    "rpcss", "rpceptmapper", "dcomlaunch", "lsm", "brokerinfrastructure", "samss", "plugplay", "power",
    "coremessagingregistrar", "systemeventsbroker", "profsvc", "gpsvc", "eventlog", "usermanager", "staterepository",
    "winmgmt", "cryptsvc", "keyiso", "audioendpointbuilder", "audiosrv", "lanmanworkstation", "bfe", "mpssvc", "nsi",
    "dhcp", "dnscache", "schedule", "sens", "themes", "wscsvc", "windefend", "wdnissvc", "sgrmbroker", "vaultsvc",
    "tokenbroker", "cdpsvc", "wlansvc", "netprofm", "nlasvc", "eventsystem", "fontcache", "shellhwdetection",
];

#[derive(Clone, Debug, Serialize)]
pub struct ServiceInfo {
    /// Short name: Dnscache, wuauserv.
    pub name: String,
    /// Display name: “DNS Client”.
    pub display: String,
    /// running, stopped, start_pending, stop_pending, paused, …
    pub state: &'static str,
    /// The service process (0 — not running).
    pub pid: u32,
    /// auto, auto_delayed, manual, disabled, boot, system (empty — unknown).
    pub start: &'static str,
    /// Lives in a shared svchost process together with other services.
    pub shared: bool,
    /// The service accepts the stop command.
    pub can_stop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// System service: Windows will not work without it.
    pub critical: bool,
}

/// A handle of the service manager or a service, closed automatically.
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
        5 => io::Error::new(io::ErrorKind::PermissionDenied, format!("{what}: administrator rights required")),
        1060 => io::Error::new(io::ErrorKind::NotFound, format!("{what}: no such service")),
        _ => io::Error::other(format!("{what}: {}", io::Error::from_raw_os_error(code as i32))),
    }
}

fn manager(access: u32) -> io::Result<Sc> {
    let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if h.is_null() {
        return Err(last_err("service manager"));
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

/// The start type and description change rarely, but they have to be asked for each service separately —
/// cached for 5 minutes.
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
        // SAFETY: the buffer is filled with a QUERY_SERVICE_CONFIGW struct.
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
        // SAFETY: the buffer starts with SERVICE_DESCRIPTIONW (a pointer to a string in the same buffer).
        let p = unsafe { *buf.as_ptr().cast::<*const u16>() };
        let s = pwstr(p);
        // descriptions like “@%SystemRoot%\system32\x.dll,-100” — a resource that could not be read
        (!s.is_empty() && !s.starts_with('@')).then_some(s)
    } else {
        None
    };
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), (Instant::now(), start, desc.clone()));
    (start, desc)
}

/// All services (without drivers). `details` — also the start type and description (slower: one query per service).
pub fn list(details: bool) -> io::Result<Vec<ServiceInfo>> {
    let scm = manager(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)?;
    // no more than 256 KB: with a larger buffer the service manager answers with error 1783
    // (RPC_X_BAD_STUB_DATA); the rest is read via resume
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
            return Err(last_err("service list"));
        }
        // SAFETY: EnumServicesStatusExW put count structs into the buffer, the strings are in the same buffer.
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
            // the buffer is too small even for one entry
            buf.resize((need as usize).div_ceil(8) + 1024, 0);
        }
    }
    out.sort_by(|a, b| a.display.to_lowercase().cmp(&b.display.to_lowercase()));
    Ok(out)
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

/// Start, stop or restart a service. System ones (`CRITICAL`) are stopped only with `force`.
/// Returns the resulting state.
/// A dry-run check: why the action would fail — before trying it.
pub fn precheck(s: &ServiceInfo, what: Control, force: bool) -> Result<(), String> {
    if what != Control::Start && s.critical && !force {
        return Err("system service: Windows will not work properly without it — --force required".into());
    }
    match what {
        Control::Stop | Control::Restart if s.state == "stopped" && what == Control::Stop => return Err("already stopped".into()),
        Control::Stop | Control::Restart if s.state != "stopped" && !s.can_stop => return Err("the service does not accept the stop command".into()),
        Control::Start if s.state == "running" => return Err("already running".into()),
        Control::Start | Control::Restart if s.start == "disabled" => return Err("start type is “Disabled” — enable it in Windows Services first".into()),
        _ => {}
    }
    if !crate::system::is_elevated() {
        return Err("administrator rights required".into());
    }
    Ok(())
}

pub fn control(name: &str, what: Control, force: bool) -> io::Result<&'static str> {
    if what != Control::Start && is_critical(name) && !force {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{name} is a system service: Windows will not work properly without it (confirmation required)"),
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
                1051 => io::Error::other(format!("{name}: stop the services that depend on it first")),
                1052 => io::Error::other(format!("{name}: the service does not accept the stop command")),
                _ => last_err(name),
            });
        }
        if what == Control::Restart && !wait_state(&h, 1, Duration::from_secs(30)) {
            return Err(io::Error::other(format!("{name}: did not stop within 30 s — start cancelled")));
        }
    }
    if matches!(what, Control::Start | Control::Restart) && unsafe { StartServiceW(h.0, 0, std::ptr::null()) } == 0 {
        let code = unsafe { GetLastError() };
        if code != 1056 {
            // 1056 — already running
            return Err(match code {
                1058 => io::Error::other(format!("{name}: the service is disabled (start type “Disabled”)")),
                _ => last_err(name),
            });
        }
    }
    // a short wait, to answer with the resulting state
    let want = if what == Control::Stop { 1 } else { 4 };
    wait_state(&h, want, Duration::from_secs(5));
    Ok(status(&h).map_or("unknown", |s| state_name(s.dwCurrentState)))
}
