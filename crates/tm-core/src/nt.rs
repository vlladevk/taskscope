//! Low-level access to ntdll: one `NtQuerySystemInformation` call
//! returns all processes at once with CPU time, memory, threads and I/O.
//! Process Hacker and System Informer do the same — it is the cheapest way.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;

const SYSTEM_PROCESS_INFORMATION_CLASS: i32 = 5;
const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQuerySystemInformation(class: i32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryInformationProcess(h: HANDLE, class: i32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtSuspendProcess(h: HANDLE) -> i32;
    fn NtResumeProcess(h: HANDLE) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// The `SYSTEM_PROCESS_INFORMATION` layout for x64 (from the phnt headers).
#[repr(C)]
#[derive(Clone, Copy)]
struct SystemProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: UnicodeString,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
    handle_count: u32,
    session_id: u32,
    unique_process_key: usize,
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_page_count: usize,
    read_operation_count: i64,
    write_operation_count: i64,
    other_operation_count: i64,
    read_transfer_count: i64,
    write_transfer_count: i64,
    other_transfer_count: i64,
}
const _: () = assert!(size_of::<SystemProcessInformation>() == 256);

/// Raw process data from one snapshot.
#[derive(Clone, Debug)]
pub struct RawProc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// Creation time, FILETIME (100 ns since 1601). Together with the PID — a unique process key.
    pub create_time: i64,
    /// Total CPU time (user + kernel), in 100 ns.
    pub cpu_time: i64,
    pub threads: u32,
    pub handles: u32,
    pub session: u32,
    pub base_priority: i32,
    /// The private working set — what the Windows Task Manager shows as “Memory”.
    pub ws_private: u64,
    pub working_set: u64,
    /// Committed private memory (commit).
    pub private_bytes: u64,
    pub io_read: u64,
    pub io_write: u64,
    pub io_other: u64,
    /// All threads wait with the Suspended reason — the process is suspended.
    pub suspended: bool,
    /// CPU cycles spent by the process threads (more precise than time: does not depend on the timer tick).
    pub cycle_time: u64,
    /// Bytes read from and written to disk (PROCESS_DISK_COUNTERS from the record extension);
    /// None — there is no extension (Windows older than 10 RS3).
    pub disk: Option<(u64, u64)>,
}

/// A reusable snapshot buffer: memory is not allocated again every second.
pub struct ProcessQuery {
    buf: Vec<u64>,
}

impl Default for ProcessQuery {
    fn default() -> Self {
        Self { buf: vec![0; 64 * 1024] } // 512 KB, enough for ~1000 processes
    }
}

impl ProcessQuery {
    pub fn snapshot(&mut self, out: &mut Vec<RawProc>) -> io::Result<()> {
        let filled;
        loop {
            let mut ret = 0u32;
            let len = (self.buf.len() * 8).min(u32::MAX as usize) as u32;
            let st = unsafe {
                NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION_CLASS, self.buf.as_mut_ptr().cast(), len, &mut ret)
            };
            if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL {
                // processes may have appeared between calls — take some headroom
                let need = (ret as usize).max(len as usize * 2) / 8 + 16 * 1024;
                self.buf.resize(need, 0);
                continue;
            }
            if st < 0 {
                return Err(io::Error::other(format!("NtQuerySystemInformation: 0x{:08X}", st as u32)));
            }
            filled = ret as usize;
            break;
        }
        out.clear();
        let base = self.buf.as_ptr() as *const u8;
        // bounds — by the filled part: further in the buffer are leftovers of the previous snapshot
        let total = if filled == 0 { self.buf.len() * 8 } else { filled.min(self.buf.len() * 8) };
        let mut off = 0usize;
        loop {
            if off + size_of::<SystemProcessInformation>() > total {
                break;
            }
            // SAFETY: an offset inside the buffer the kernel filled; read without alignment requirements.
            let p: SystemProcessInformation = unsafe { ptr::read_unaligned(base.add(off).cast()) };
            let name = if p.unique_process_id == 0 {
                "System Idle Process".to_string()
            } else if p.image_name.buffer.is_null() || p.image_name.length == 0 {
                String::new()
            } else {
                // SAFETY: the name string lies in the same buffer.
                let s = unsafe { std::slice::from_raw_parts(p.image_name.buffer, p.image_name.length as usize / 2) };
                String::from_utf16_lossy(s)
            };
            out.push(RawProc {
                pid: p.unique_process_id as u32,
                ppid: p.inherited_from_unique_process_id as u32,
                name,
                create_time: js_safe(p.create_time),
                cpu_time: p.user_time + p.kernel_time,
                threads: p.number_of_threads,
                handles: p.handle_count,
                session: p.session_id,
                base_priority: p.base_priority,
                ws_private: p.working_set_private_size.max(0) as u64,
                working_set: p.working_set_size as u64,
                private_bytes: p.private_page_count as u64,
                io_read: p.read_transfer_count.max(0) as u64,
                io_write: p.write_transfer_count.max(0) as u64,
                io_other: p.other_transfer_count.max(0) as u64,
                suspended: all_threads_suspended(base, off, total, p.number_of_threads),
                cycle_time: p.cycle_time,
                disk: extension_disk(base, off, total, &p),
            });
            if p.next_entry_offset == 0 {
                break;
            }
            off += p.next_entry_offset as usize;
        }
        Ok(())
    }
}

/// After the thread array lies `SYSTEM_PROCESS_INFORMATION_EXTENSION` (Windows 10 RS3+,
/// System Informer reads it this way — PH_PROCESS_EXTENSION). It starts with PROCESS_DISK_COUNTERS:
/// BytesRead, BytesWritten, … — the Task Manager’s “Disk”: reads and writes of the disk itself,
/// without network and pipes, which go into the general I/O counters.
fn extension_disk(base: *const u8, off: usize, total: usize, p: &SystemProcessInformation) -> Option<(u64, u64)> {
    const THREAD_SIZE: usize = 80;
    let ext = off + size_of::<SystemProcessInformation>() + p.number_of_threads as usize * THREAD_SIZE;
    // the record must fit the extension: for the last record the end is the end of the data
    let end = if p.next_entry_offset == 0 { total } else { off + p.next_entry_offset as usize };
    if ext + 16 > end {
        return None;
    }
    // SAFETY: bounds checked; read without alignment requirements.
    unsafe { Some((ptr::read_unaligned(base.add(ext).cast::<u64>()), ptr::read_unaligned(base.add(ext + 8).cast::<u64>()))) }
}

/// After the process record lie its thread records (`SYSTEM_THREAD_INFORMATION`, 80 bytes on x64).
/// The process is suspended if every thread is in the Waiting (5) state with the Suspended (5) reason.
fn all_threads_suspended(base: *const u8, off: usize, total: usize, n: u32) -> bool {
    const THREAD_SIZE: usize = 80;
    const STATE: usize = 68;
    const REASON: usize = 72;
    if n == 0 {
        return false;
    }
    let first = off + size_of::<SystemProcessInformation>();
    if first + n as usize * THREAD_SIZE > total {
        return false;
    }
    (0..n as usize).all(|i| {
        let t = first + i * THREAD_SIZE;
        // SAFETY: bounds checked above; read without alignment requirements.
        let (state, reason) = unsafe { (ptr::read_unaligned(base.add(t + STATE).cast::<u32>()), ptr::read_unaligned(base.add(t + REASON).cast::<u32>())) };
        state == 5 && reason == 5
    })
}

/// The process command line (Windows 8.1+, PROCESS_QUERY_LIMITED_INFORMATION is enough).
pub fn command_line(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u64; 512];
    loop {
        let mut ret = 0u32;
        let st = unsafe {
            NtQueryInformationProcess(h, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut ret)
        };
        if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL {
            if ret as usize <= buf.len() * 8 || buf.len() > 1 << 20 {
                return None;
            }
            buf.resize(ret as usize / 8 + 1, 0);
            continue;
        }
        if st < 0 {
            return None;
        }
        // SAFETY: the buffer starts with a UNICODE_STRING pointing inside the same buffer.
        let us: UnicodeString = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
        if us.buffer.is_null() || us.length == 0 {
            return Some(String::new());
        }
        let s = unsafe { std::slice::from_raw_parts(us.buffer, us.length as usize / 2) };
        return Some(String::from_utf16_lossy(s));
    }
}

/// The folder and environment of the process — what it was started with (for a restart “as it was”).
pub struct LaunchParams {
    pub cwd: String,
    /// A UTF-16 environment block: `NAME=value\0` strings, with one more `\0` at the end.
    pub env: Vec<u16>,
}

const PROCESS_BASIC_INFORMATION: i32 = 0;
const PROCESS_WOW64_INFORMATION: i32 = 26;

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb: usize,
    affinity: usize,
    base_priority: i32,
    pid: usize,
    ppid: usize,
}

fn read_mem(h: HANDLE, addr: usize, buf: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut n = 0usize;
    let ok = unsafe { ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr().cast(), buf.len(), &mut n) };
    if ok == 0 || n != buf.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_ptr(h: HANDLE, addr: usize, wow: bool) -> io::Result<usize> {
    let mut b = [0u8; 8];
    let n = if wow { 4 } else { 8 };
    read_mem(h, addr, &mut b[..n])?;
    Ok(u64::from_le_bytes(b) as usize)
}

/// A UNICODE_STRING from process memory: 16 bytes on x64, 8 bytes for a 32-bit process.
fn read_ustr(h: HANDLE, addr: usize, wow: bool) -> io::Result<String> {
    let mut len = [0u8; 2];
    read_mem(h, addr, &mut len)?;
    let len = u16::from_le_bytes(len) as usize;
    let buf = read_ptr(h, addr + if wow { 4 } else { 8 }, wow)?;
    if len == 0 || buf == 0 {
        return Ok(String::new());
    }
    let mut raw = vec![0u8; len];
    read_mem(h, buf, &mut raw)?;
    let w: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&w))
}

/// Reads the current folder and environment from PEB → RTL_USER_PROCESS_PARAMETERS
/// (like PhGetProcessCurrentDirectory / PhGetProcessEnvironment in System Informer).
/// Needs a handle with PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ.
/// For 32-bit processes their own 32-bit PEB is used: the 64-bit copy is not updated for them.
pub fn launch_params(h: HANDLE) -> io::Result<LaunchParams> {
    let mut peb32 = 0usize;
    let st = unsafe { NtQueryInformationProcess(h, PROCESS_WOW64_INFORMATION, (&mut peb32 as *mut usize).cast(), 8, ptr::null_mut()) };
    let wow = st >= 0 && peb32 != 0;
    let peb = if wow {
        peb32
    } else {
        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let st = unsafe {
            NtQueryInformationProcess(h, PROCESS_BASIC_INFORMATION, (&mut pbi as *mut ProcessBasicInformation).cast(), size_of::<ProcessBasicInformation>() as u32, ptr::null_mut())
        };
        nt_ok(st, "NtQueryInformationProcess")?;
        pbi.peb
    };
    // offsets from phnt: PEB.ProcessParameters, CurrentDirectory.DosPath, Environment, EnvironmentSize
    let (o_params, o_cwd, o_env, o_env_size) = if wow { (0x10, 0x24, 0x48, 0x290) } else { (0x20, 0x38, 0x80, 0x3F0) };
    let params = read_ptr(h, peb + o_params, wow)?;
    if params == 0 {
        return Err(io::Error::other("the process has no start parameters"));
    }
    let cwd = read_ustr(h, params + o_cwd, wow)?;
    let env_ptr = read_ptr(h, params + o_env, wow)?;
    let env_size = read_ptr(h, params + o_env_size, wow).unwrap_or(0);
    let mut env = Vec::new();
    if env_ptr != 0 {
        let bytes = if (4..=16 << 20).contains(&env_size) {
            let mut raw = vec![0u8; env_size];
            read_mem(h, env_ptr, &mut raw)?;
            raw
        } else {
            // old systems without EnvironmentSize: read page by page until a double zero
            let mut raw = Vec::new();
            let mut addr = env_ptr;
            loop {
                let chunk = 0x1000 - (addr & 0xFFF);
                let mut b = vec![0u8; chunk];
                if read_mem(h, addr, &mut b).is_err() {
                    break;
                }
                raw.extend_from_slice(&b);
                addr += chunk;
                if raw.len() > 1 << 20 || raw.chunks_exact(2).collect::<Vec<_>>().windows(2).any(|w| w[0] == [0, 0] && w[1] == [0, 0]) {
                    break;
                }
            }
            raw
        };
        env = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        // cut at the end of the block (double zero) and make sure it is there
        if let Some(end) = env.windows(2).position(|w| w == [0, 0]) {
            env.truncate(end + 2);
        } else {
            env.extend_from_slice(&[0, 0]);
        }
    }
    Ok(LaunchParams { cwd, env })
}

pub fn suspend(h: HANDLE) -> io::Result<()> {
    nt_ok(unsafe { NtSuspendProcess(h) }, "NtSuspendProcess")
}

pub fn resume(h: HANDLE) -> io::Result<()> {
    nt_ok(unsafe { NtResumeProcess(h) }, "NtResumeProcess")
}

fn nt_ok(st: i32, what: &str) -> io::Result<()> {
    if st < 0 {
        Err(io::Error::other(format!("{what}: 0x{:08X}", st as u32)))
    } else {
        Ok(())
    }
}

/// An arbitrary `NtQuerySystemInformation` class in full: the buffer grows until the data fits.
pub fn query_system(class: i32, hint: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; hint.max(4096)];
    loop {
        let mut ret = 0u32;
        let len = buf.len().min(u32::MAX as usize) as u32;
        let st = unsafe { NtQuerySystemInformation(class, buf.as_mut_ptr().cast(), len, &mut ret) };
        if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL) && buf.len() < 256 << 20 {
            let need = (ret as usize).max(buf.len() * 2) + 16 * 1024;
            buf = vec![0u8; need];
            continue;
        }
        if st < 0 {
            return Err(io::Error::other(format!("NtQuerySystemInformation({class}): 0x{:08X}", st as u32)));
        }
        return Ok(buf);
    }
}

/// The exact response size: for “per processor” arrays the extra tail of the buffer is not data.
fn query_exact(class: i32, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut ret = 0u32;
    let st = unsafe { NtQuerySystemInformation(class, buf.as_mut_ptr().cast(), len as u32, &mut ret) };
    if st < 0 {
        return None;
    }
    buf.truncate((ret as usize).min(len));
    Some(buf)
}

fn sum_u64(b: &[u8], stride: usize, at: usize) -> u64 {
    b.chunks_exact(stride).map(|c| u64::from_le_bytes(c[at..at + 8].try_into().unwrap())).fold(0u64, u64::wrapping_add)
}

/// Processor time since start (sum over all logical processors of the group), 100 ns.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuPerf {
    pub idle: u64,
    /// Includes idle, DPC and interrupts.
    pub kernel: u64,
    pub user: u64,
    pub dpc: u64,
    pub interrupt: u64,
}

/// SystemProcessorPerformanceInformation (class 8): 48 bytes per processor.
pub fn cpu_perf(ncpu: u32) -> Option<CpuPerf> {
    let b = query_exact(8, 48 * ncpu.max(1) as usize)?;
    Some(CpuPerf { idle: sum_u64(&b, 48, 0), kernel: sum_u64(&b, 48, 8), user: sum_u64(&b, 48, 16), dpc: sum_u64(&b, 48, 24), interrupt: sum_u64(&b, 48, 32) })
}

/// Idle cycles of all processors (class 83, SystemProcessorIdleCycleTimeInformation).
pub fn idle_cycles(ncpu: u32) -> Option<u64> {
    query_exact(83, 8 * ncpu.max(1) as usize).map(|b| sum_u64(&b, 8, 0))
}

/// Cycles spent on DPC and interrupts (class 108, SystemProcessorCycleTimeInformation).
pub fn system_cycles(ncpu: u32) -> Option<u64> {
    query_exact(108, 8 * ncpu.max(1) as usize).map(|b| sum_u64(&b, 8, 0))
}

/// The process file path by PID without opening the process (class 88, SystemProcessIdInformation):
/// works for protected and administrator processes too. The path is in NT form
/// (\Device\HarddiskVolume3\…), `crate::info::dos_path` converts it.
pub fn image_path_by_pid(pid: u32) -> Option<String> {
    #[repr(C)]
    struct ProcessIdInformation {
        pid: usize,
        name: UnicodeString,
    }
    let mut cap = 1024usize;
    for _ in 0..2 {
        let mut buf = vec![0u16; cap];
        let max = (cap * 2).min(u16::MAX as usize & !1) as u16;
        let mut info = ProcessIdInformation { pid: pid as usize, name: UnicodeString { length: 0, maximum_length: max, buffer: buf.as_mut_ptr() } };
        let st = unsafe { NtQuerySystemInformation(88, (&mut info as *mut ProcessIdInformation).cast(), size_of::<ProcessIdInformation>() as u32, ptr::null_mut()) };
        // a long path: the kernel writes the needed size into MaximumLength — retry once
        if st == STATUS_INFO_LENGTH_MISMATCH && info.name.maximum_length > max {
            cap = info.name.maximum_length as usize / 2;
            continue;
        }
        if st < 0 || info.name.length == 0 {
            return None;
        }
        buf.truncate(info.name.length as usize / 2);
        return Some(String::from_utf16_lossy(&buf));
    }
    None
}

/// Process creation time rounded to the precision of a double (loses < 1 µs).
/// The process key (PID, creation time) travels through JSON to the JavaScript window, where integers
/// above 2^53 get distorted — after rounding the value is the same for all participants.
pub fn js_safe(filetime: i64) -> i64 {
    filetime as f64 as i64
}
