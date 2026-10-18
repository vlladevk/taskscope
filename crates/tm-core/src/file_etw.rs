//! Which files processes read and write: events of the Microsoft-Windows-Kernel-File provider (ETW).
//!
//! A process’s “Disk” counters are bytes only. To see the files themselves you need tracing of
//! file operations; an own ETW session requires administrator rights. The session starts on
//! the first request and stops by itself after 2 minutes without requests: read and
//! write events come in thousands per second, and there is no point keeping them while nobody watches.
//!
//! Names: the “open” (Create) event gives the name for the file object, NameCreate — for the file
//! key; reads and writes come with both. Files opened before the observation started get no
//! name — they go as a single row “opened before observation started”.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, TdhGetEventInformation, CONTROLTRACE_HANDLE,
    EVENT_CONTROL_CODE_CAPTURE_STATE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_EVENT_INFO, WNODE_FLAG_TRACED_GUID,
};

const SESSION: &str = "tm-file";
/// Microsoft-Windows-Kernel-File
const PROVIDER: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// FILENAME | CREATE | READ | WRITE
const KEYWORDS: u64 = 0x10 | 0x80 | 0x100 | 0x200;
const INVALID_PROCESSTRACE: u64 = u64::MAX;
/// Without requests for longer than this the session stops.
const LINGER: Duration = Duration::from_secs(120);
/// “Now” — bytes decaying with this time constant: rate = remainder / TAU.
const TAU: f64 = 10.0;
const MAX_NAMES: usize = 200_000;
const MAX_FILES: usize = 50_000;

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
        e.BufferSize = 256; // KB: there are many file events
        e.MinimumBuffers = 8;
        e.MaximumBuffers = 64;
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

/// Where the needed fields lie in the event data. Windows itself reports the layout (TDH) —
/// it differs between event versions, and offsets must not be guessed.
#[derive(Clone, Copy, Default)]
struct Layout {
    file_object: Option<(usize, usize)>,
    file_key: Option<(usize, usize)>,
    io_size: Option<(usize, usize)>,
    /// start of the UTF-16 name string (it runs to the end or to a zero)
    file_name: Option<usize>,
}

fn layout(rec: &EVENT_RECORD) -> Layout {
    let mut size = 0u32;
    let first = unsafe { TdhGetEventInformation(rec, 0, std::ptr::null(), std::ptr::null_mut(), &mut size) };
    if first != 122 || size == 0 {
        // 122 — ERROR_INSUFFICIENT_BUFFER: otherwise there is no event description
        return Layout::default();
    }
    let mut buf = vec![0u64; size as usize / 8 + 1];
    let info = buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if unsafe { TdhGetEventInformation(rec, 0, std::ptr::null(), info, &mut size) } != 0 {
        return Layout::default();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, size as usize) };
    let top = unsafe { (*info).TopLevelPropertyCount } as usize;
    let arr = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    let step = std::mem::size_of::<EVENT_PROPERTY_INFO>();
    let ptr = if rec.EventHeader.Flags & 0x20 != 0 { 4 } else { 8 }; // EVENT_HEADER_FLAG_32_BIT_HEADER
    let u16_at = |o: usize| bytes.get(o..o + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| bytes.get(o..o + 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let name_at = |o: usize| {
        let mut s = String::new();
        let mut i = o;
        while i + 1 < bytes.len() {
            let c = u16_at(i);
            if c == 0 {
                break;
            }
            s.push(char::from_u32(c as u32).unwrap_or('?'));
            i += 2;
        }
        s
    };
    let mut out = Layout::default();
    let mut off = 0usize;
    for i in 0..top {
        let p = arr + i * step;
        if p + step > bytes.len() {
            break;
        }
        // EVENT_PROPERTY_INFO: Flags, NameOffset, InType (u16), OutType, MapNameOffset, count, length
        let flags = u32_at(p);
        let name = name_at(u32_at(p + 4) as usize);
        let in_type = u16_at(p + 8);
        let count = u16_at(p + 16);
        let length = u16_at(p + 18);
        // a struct, a variable-length array or a length from another field — offsets cannot be computed further
        if flags & (0x1 | 0x2 | 0x4) != 0 {
            break;
        }
        let one = match in_type {
            1 => {
                if name.eq_ignore_ascii_case("FileName") {
                    out.file_name = Some(off);
                }
                break; // a variable-length string: nothing needed comes after it
            }
            3 | 4 => 1,
            5 | 6 => 2,
            7 | 8 | 11 | 13 | 20 => 4,
            9 | 10 | 12 | 17 | 21 => 8,
            15 | 18 => 16,
            16 => ptr,
            14 if length > 0 => length as usize,
            _ => break,
        };
        let n = if count > 1 { one * count as usize } else { one };
        let at = Some((off, one));
        match name.as_str() {
            "FileObject" => out.file_object = at,
            "FileKey" => out.file_key = at,
            "IOSize" | "IoSize" => out.io_size = at,
            _ => {}
        }
        off += n;
    }
    out
}

fn read_uint(data: &[u8], f: Option<(usize, usize)>) -> Option<u64> {
    let (o, n) = f?;
    let b = data.get(o..o + n)?;
    Some(match n {
        4 => u32::from_le_bytes(b.try_into().ok()?) as u64,
        8 => u64::from_le_bytes(b.try_into().ok()?),
        2 => u16::from_le_bytes(b.try_into().ok()?) as u64,
        1 => b[0] as u64,
        _ => return None,
    })
}

fn read_name(data: &[u8], at: usize) -> Option<String> {
    let b = data.get(at..)?;
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    (!w.is_empty()).then(|| String::from_utf16_lossy(&w))
}

#[derive(Default)]
struct Acc {
    read: u64,
    write: u64,
    reads: u64,
    writes: u64,
    /// decaying bytes (see TAU) at the moment `at`
    rr: f64,
    rw: f64,
    at: Option<Instant>,
}

impl Acc {
    fn decay(&mut self, now: Instant) {
        if let Some(t) = self.at {
            let k = (-now.saturating_duration_since(t).as_secs_f64() / TAU).exp();
            self.rr *= k;
            self.rw *= k;
        }
        self.at = Some(now);
    }
}

#[derive(Default)]
struct State {
    layouts: HashMap<(u16, u8), Layout>,
    by_object: HashMap<u64, Arc<str>>,
    by_key: HashMap<u64, Arc<str>>,
    files: HashMap<(u32, Arc<str>), Acc>,
    events: u64,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(Default::default)
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let r = &*rec;
    let id = r.EventHeader.EventDescriptor.Id;
    let ver = r.EventHeader.EventDescriptor.Version;
    let data: &[u8] = if r.UserData.is_null() { &[] } else { std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize) };
    let Ok(mut s) = state().lock() else { return };
    let l = match s.layouts.get(&(id, ver)) {
        Some(l) => *l,
        None => {
            let l = layout(r);
            s.layouts.insert((id, ver), l);
            l
        }
    };
    let fo = read_uint(data, l.file_object);
    let fk = read_uint(data, l.file_key);
    // 11 — NameDelete: the file key is no longer valid
    if id == 11 {
        if let Some(k) = fk {
            s.by_key.remove(&k);
        }
        return;
    }
    // any event with a name (open, NameCreate, rundown at start) — remember the name
    if let Some(name) = l.file_name.and_then(|at| read_name(data, at)) {
        if s.by_object.len() + s.by_key.len() > MAX_NAMES {
            s.by_object.clear();
            s.by_key.clear();
        }
        let name: Arc<str> = name.into();
        if let Some(o) = fo {
            s.by_object.insert(o, name.clone());
        }
        if let Some(k) = fk {
            s.by_key.insert(k, name);
        }
        return;
    }
    // 15 — read, 16 — write
    let write = match id {
        15 => false,
        16 => true,
        _ => return,
    };
    let Some(size) = read_uint(data, l.io_size) else { return };
    let name = fo.and_then(|o| s.by_object.get(&o)).or_else(|| fk.and_then(|k| s.by_key.get(&k))).cloned().unwrap_or_else(|| Arc::from(""));
    let pid = r.EventHeader.ProcessId;
    s.events += 1;
    if s.files.len() > MAX_FILES {
        // drop what has not been touched for a long time
        let now = Instant::now();
        s.files.retain(|_, a| a.at.is_some_and(|t| now.saturating_duration_since(t) < Duration::from_secs(60)));
    }
    let a = s.files.entry((pid, name)).or_default();
    a.decay(Instant::now());
    if write {
        a.write += size;
        a.writes += 1;
        a.rw += size as f64;
    } else {
        a.read += size;
        a.reads += 1;
        a.rr += size as f64;
    }
}

struct Control {
    running: bool,
    since: Option<Instant>,
    asked: Option<Instant>,
}

fn control() -> &'static Mutex<Control> {
    static C: OnceLock<Mutex<Control>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Control { running: false, since: None, asked: None }))
}

fn start() -> Result<(), String> {
    stop_session(); // the session may be left over from a crashed instance
    let mut session = CONTROLTRACE_HANDLE { Value: 0 };
    let mut p = Props::new();
    let rc = unsafe { StartTraceW(&mut session, wide(SESSION).as_ptr(), p.get()) };
    if rc != 0 {
        return Err(format!("could not start file tracing (code {rc})"));
    }
    let rc = unsafe { EnableTraceEx2(session, &PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 4, KEYWORDS, 0, 0, std::ptr::null()) };
    if rc != 0 {
        stop_session();
        return Err(format!("could not enable file events (code {rc})"));
    }
    let mut name = wide(SESSION);
    let mut log: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    log.LoggerName = name.as_mut_ptr();
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Anonymous2.EventRecordCallback = Some(on_event);
    let trace = unsafe { OpenTraceW(&mut log) };
    if trace.Value == INVALID_PROCESSTRACE {
        stop_session();
        return Err("could not open the file trace".into());
    }
    let h = trace.Value;
    // ProcessTrace blocks the thread until the session is stopped
    let spawned = std::thread::Builder::new().name("tm-file-etw".into()).spawn(move || unsafe {
        let handle = PROCESSTRACE_HANDLE { Value: h };
        ProcessTrace(&handle, 1, std::ptr::null(), std::ptr::null());
        CloseTrace(handle);
    });
    if spawned.is_err() {
        unsafe { CloseTrace(trace) };
        stop_session();
        return Err("could not start the tracing thread".into());
    }
    // names of already open files, if the provider can enumerate them (if not — nothing happens)
    unsafe { EnableTraceEx2(session, &PROVIDER, EVENT_CONTROL_CODE_CAPTURE_STATE, 4, KEYWORDS, 0, 0, std::ptr::null()) };
    // watchdog: no requests for longer than LINGER — stop
    let _ = std::thread::Builder::new().name("tm-file-etw-idle".into()).spawn(|| loop {
        std::thread::sleep(Duration::from_secs(5));
        let mut c = control().lock().unwrap_or_else(|e| e.into_inner());
        if !c.running {
            return;
        }
        if c.asked.is_none_or(|t| t.elapsed() > LINGER) {
            stop_session();
            c.running = false;
            c.since = None;
            drop(c);
            if let Ok(mut s) = state().lock() {
                *s = State::default();
            }
            return;
        }
    });
    Ok(())
}

/// Stops the session. Call on program exit: Windows itself will not stop it.
pub fn shutdown() {
    let mut c = control().lock().unwrap_or_else(|e| e.into_inner());
    if c.running {
        stop_session();
        c.running = false;
    }
}

#[derive(Serialize)]
pub struct FileIo {
    pub pid: u32,
    /// a “C:\…” path; empty — the file was opened before observation started, no name
    pub path: String,
    pub read: u64,
    pub write: u64,
    pub reads: u64,
    pub writes: u64,
    /// bytes/s over the last ~10 s
    pub read_bps: f64,
    pub write_bps: f64,
    /// seconds since the last operation
    pub idle_s: f64,
}

#[derive(Serialize)]
pub struct Report {
    /// seconds since observation started
    pub since_s: f64,
    pub events: u64,
    pub files: Vec<FileIo>,
}

/// Files that processes (or one `pid`) read and wrote since observation started.
/// The first call starts the observation — the report is empty until events arrive.
pub fn report(pid: Option<u32>, limit: usize) -> Result<Report, String> {
    if !crate::system::is_elevated() {
        return Err("administrator rights required".into());
    }
    let since = {
        let mut c = control().lock().unwrap_or_else(|e| e.into_inner());
        c.asked = Some(Instant::now());
        if !c.running {
            start()?;
            c.running = true;
            c.since = Some(Instant::now());
        }
        c.since.map_or(0.0, |t| t.elapsed().as_secs_f64())
    };
    let now = Instant::now();
    let mut s = state().lock().map_err(|_| "file tracing is unavailable".to_string())?;
    let events = s.events;
    let mut files: Vec<FileIo> = s
        .files
        .iter_mut()
        .filter(|((p, _), _)| pid.is_none_or(|x| *p == x))
        .map(|((p, name), a)| {
            let idle = a.at.map_or(0.0, |t| now.saturating_duration_since(t).as_secs_f64());
            a.decay(now);
            FileIo {
                pid: *p,
                path: if name.is_empty() { String::new() } else { crate::info::dos_path(name).unwrap_or_else(|| name.to_string()) },
                read: a.read,
                write: a.write,
                reads: a.reads,
                writes: a.writes,
                read_bps: a.rr / TAU,
                write_bps: a.rw / TAU,
                idle_s: idle,
            }
        })
        .collect();
    drop(s);
    // first what is happening now, then — the most over the observation time
    files.sort_by(|a, b| {
        let (x, y) = (a.read_bps + a.write_bps, b.read_bps + b.write_bps);
        let total = (b.read + b.write).cmp(&(a.read + a.write));
        match (x >= 1024.0, y >= 1024.0) {
            (true, true) => y.total_cmp(&x).then(total),
            (false, false) => total,
            (bx, by) => by.cmp(&bx),
        }
    });
    files.truncate(limit);
    Ok(Report { since_s: since, events, files })
}
