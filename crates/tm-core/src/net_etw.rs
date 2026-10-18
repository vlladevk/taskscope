//! Network traffic per process: events of the Microsoft-Windows-Kernel-Network provider (ETW).
//!
//! Windows reports per-process traffic only through event tracing, and an own tracing
//! session requires administrator rights (that is why the Windows Task Manager runs
//! elevated too). Without the rights `NetEtw::start` returns `None` — everything else works.
//! Traffic over localhost is not counted: it never leaves the machine.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

const SESSION: &str = "tm-net";
/// Microsoft-Windows-Kernel-Network
const PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// KERNEL_NETWORK_KEYWORD_IPV4 | IPV6
const KEYWORDS: u64 = 0x10 | 0x20;
const INVALID_PROCESSTRACE: u64 = u64::MAX;

/// PID → (received, sent) bytes since the last `take`.
/// The process and both packet addresses (source, destination): the engine finds the adapter by the
/// local one — a program’s traffic through a VPN tunnel and the encrypted tunnel over Wi-Fi are not
/// added up into one number.
pub type Key = (u32, IpAddr, IpAddr);

fn counters() -> &'static Mutex<HashMap<Key, (u64, u64)>> {
    static C: OnceLock<Mutex<HashMap<Key, (u64, u64)>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Session properties with room for its name right after the struct (ETW requires this).
struct Props {
    buf: Vec<u64>,
}

impl Props {
    fn new() -> Self {
        let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut p = Self { buf: vec![0u64; size / 8 + 1] };
        let e = p.get();
        e.Wnode.BufferSize = size as u32;
        e.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        e.Wnode.ClientContext = 1; // QPC clock
        e.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        e.BufferSize = 64; // KB
        e.MinimumBuffers = 4;
        e.MaximumBuffers = 16;
        e.FlushTimer = 1; // s
        e.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        p
    }
    fn get(&mut self) -> &mut EVENT_TRACE_PROPERTIES {
        unsafe { &mut *(self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) }
    }
}

fn stop_session() {
    let mut p = Props::new();
    unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, wide(SESSION).as_ptr(), p.get(), EVENT_TRACE_CONTROL_STOP) };
}

fn is_loopback_v4(a: &[u8]) -> bool {
    a[0] == 127
}

fn is_loopback_v6(a: &[u8]) -> bool {
    a[..15].iter().all(|&b| b == 0) && a[15] == 1
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    // our session enables a single provider — Kernel-Network
    let r = &*rec;
    // 10/11 — TCP IPv4 send/receive, 26/27 — TCP IPv6, 42/43 — UDP IPv4, 58/59 — UDP IPv6
    let (recv, v6) = match r.EventHeader.EventDescriptor.Id {
        10 | 42 => (false, false),
        11 | 43 => (true, false),
        26 | 58 => (false, true),
        27 | 59 => (true, true),
        _ => return,
    };
    // PID (u32), size (u32), destination address, source address, …
    let len = r.UserDataLength as usize;
    let need = if v6 { 8 + 32 } else { 8 + 8 };
    if len < need || r.UserData.is_null() {
        return;
    }
    let data = std::slice::from_raw_parts(r.UserData as *const u8, len);
    let pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
    let local = if v6 { is_loopback_v6(&data[8..24]) || is_loopback_v6(&data[24..40]) } else { is_loopback_v4(&data[8..12]) || is_loopback_v4(&data[12..16]) };
    if local {
        return;
    }
    // daddr, then saddr
    let (d, s): (IpAddr, IpAddr) = if v6 {
        let a: [u8; 16] = data[8..24].try_into().unwrap_or([0; 16]);
        let b: [u8; 16] = data[24..40].try_into().unwrap_or([0; 16]);
        (Ipv6Addr::from(a).into(), Ipv6Addr::from(b).into())
    } else {
        let a: [u8; 4] = data[8..12].try_into().unwrap_or([0; 4]);
        let b: [u8; 4] = data[12..16].try_into().unwrap_or([0; 4]);
        (Ipv4Addr::from(a).into(), Ipv4Addr::from(b).into())
    };
    if let Ok(mut m) = counters().lock() {
        let e = m.entry((pid, s, d)).or_default();
        if recv {
            e.0 += size;
        } else {
            e.1 += size;
        }
    }
}

/// Stops the tracing session. Call on program exit: Windows itself
/// will not stop it, and the engine is not destroyed when the process ends.
pub fn shutdown() {
    stop_session();
}

pub struct NetEtw {
    session: CONTROLTRACE_HANDLE,
    trace: u64,
}

impl NetEtw {
    /// Starts an own tracing session. `None` — no administrator rights or ETW is unavailable.
    pub fn start() -> Option<Self> {
        if !crate::system::is_elevated() {
            return None;
        }
        stop_session(); // the session may be left over from a crashed instance
        let mut session = CONTROLTRACE_HANDLE { Value: 0 };
        let mut p = Props::new();
        if unsafe { StartTraceW(&mut session, wide(SESSION).as_ptr(), p.get()) } != 0 {
            return None;
        }
        let ok = unsafe { EnableTraceEx2(session, &PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 4, KEYWORDS, 0, 0, std::ptr::null()) } == 0;
        if !ok {
            stop_session();
            return None;
        }
        let mut name = wide(SESSION);
        let mut log: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        log.LoggerName = name.as_mut_ptr();
        log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.Anonymous2.EventRecordCallback = Some(on_event);
        let trace = unsafe { OpenTraceW(&mut log) };
        if trace.Value == INVALID_PROCESSTRACE {
            stop_session();
            return None;
        }
        let h = trace.Value;
        // ProcessTrace blocks the thread until the session is stopped
        let spawned = std::thread::Builder::new().name("tm-net-etw".into()).spawn(move || unsafe {
            let handle = PROCESSTRACE_HANDLE { Value: h };
            ProcessTrace(&handle, 1, std::ptr::null(), std::ptr::null());
        });
        if spawned.is_err() {
            unsafe { CloseTrace(trace) };
            stop_session();
            return None;
        }
        Some(Self { session, trace: h })
    }

    /// Bytes since the previous call: (PID, source, destination) → (received, sent).
    pub fn take(&self) -> HashMap<Key, (u64, u64)> {
        let _ = self.session;
        counters().lock().map(|mut m| std::mem::take(&mut *m)).unwrap_or_default()
    }
}

impl Drop for NetEtw {
    fn drop(&mut self) {
        unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: self.trace }) };
        stop_session();
    }
}
