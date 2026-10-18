//! System-wide metrics: CPU load, memory, number of logical processors.

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{GetActiveProcessorCount, GetSystemTimes};

/// The named “single instance” mutex. The pipe check did not prevent a simultaneous
/// start: both processes managed to ask “is anyone running?” before either opened the pipe.
/// The mutex is created atomically — exactly one becomes first. The handle lives until the
/// process exits; after a crash Windows releases it itself.
pub struct InstanceLock(windows_sys::Win32::Foundation::HANDLE);

impl InstanceLock {
    /// `Some((lock, true))` — we are first; `Some((lock, false))` — an instance already exists;
    /// `None` — the mutex could not be created (then we rely on the pipe check).
    pub fn acquire(name: &str) -> Option<(Self, bool)> {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::System::Threading::CreateMutexW;
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let h = unsafe { CreateMutexW(std::ptr::null(), 1, w.as_ptr()) };
        if h.is_null() {
            return None;
        }
        let first = unsafe { GetLastError() } != ERROR_ALREADY_EXISTS;
        Some((Self(h), first))
    }

    /// Wait until the previous owner exits and take the mutex.
    pub fn wait(&self, timeout: std::time::Duration) -> bool {
        use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        let r = unsafe { WaitForSingleObject(self.0, timeout.as_millis().min(u32::MAX as u128 - 1) as u32) };
        r == WAIT_OBJECT_0 || r == WAIT_ABANDONED
    }
}

pub fn logical_cpus() -> u32 {
    unsafe { GetActiveProcessorCount(0xFFFF) }.max(1) // ALL_PROCESSOR_GROUPS
}

pub fn uptime_ms() -> u64 {
    unsafe { GetTickCount64() }
}

/// The current time as FILETIME (100 ns since 1601) — on the same scale as process creation time.
pub fn filetime_now() -> i64 {
    let mut f = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    unsafe { windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut f) };
    (((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64) as i64
}

#[derive(Clone, Copy, Default)]
pub struct CpuTimes {
    idle: u64,
    kernel: u64, // includes idle
    user: u64,
}

pub fn cpu_times() -> CpuTimes {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut i, mut k, mut u) = (z, z, z);
    unsafe { GetSystemTimes(&mut i, &mut k, &mut u) };
    let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    CpuTimes { idle: ft(i), kernel: ft(k), user: ft(u) }
}

/// CPU load in percent between two samples.
pub fn cpu_busy(prev: CpuTimes, cur: CpuTimes) -> f32 {
    let total = cur.kernel.saturating_sub(prev.kernel) + cur.user.saturating_sub(prev.user);
    let idle = cur.idle.saturating_sub(prev.idle);
    if total == 0 {
        return 0.0;
    }
    (total.saturating_sub(idle) as f64 * 100.0 / total as f64) as f32
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Memory {
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub commit_used: u64,
    pub commit_limit: u64,
    pub load_pct: u32,
}

pub fn memory() -> Memory {
    let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut m) };
    Memory {
        total: m.ullTotalPhys,
        available: m.ullAvailPhys,
        used: m.ullTotalPhys.saturating_sub(m.ullAvailPhys),
        commit_used: m.ullTotalPageFile.saturating_sub(m.ullAvailPageFile),
        commit_limit: m.ullTotalPageFile,
        load_pct: m.dwMemoryLoad,
    }
}


/// Runs a command line without handle inheritance. `cwd` — the working folder.
pub fn spawn(cmdline: &str, cwd: Option<&std::path::Path>, flags: u32) -> std::io::Result<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    let mut wcmd: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let wcwd: Option<Vec<u16>> = cwd.map(|p| p.as_os_str().to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect());
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            wcmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0, // bInheritHandles = FALSE
            flags,
            std::ptr::null(),
            wcwd.as_ref().map_or(std::ptr::null(), |w| w.as_ptr()),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(pi.dwProcessId)
}

/// Starts a process fully detached: without a console, outside the parent’s job and,
/// most importantly, without inherited handles — otherwise it would keep the parent’s output
/// pipes open, and `tm daemon start | ...` would never finish.
pub fn spawn_detached(exe: &std::path::Path, args: &[&str]) -> std::io::Result<u32> {
    use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
    let mut cmd = format!("\"{}\"", exe.display());
    for a in args {
        cmd.push(' ');
        cmd.push_str(a);
    }
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // breaking away from the job is not always allowed — then we start inside it
    spawn(&cmd, None, base | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(&cmd, None, base))
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ShellExecute: open a file, folder or link “as with a double-click” (`verb` = "open")
/// or run with an administrator rights prompt (`verb` = "runas").
pub fn shell_execute(verb: &str, file: &str, params: &str) -> std::io::Result<()> {
    shell_execute_from(0, verb, file, params)
}

/// Like `shell_execute`, but on behalf of the `parent` window (HWND). For "runas" this matters: without an owner window
/// Windows does not show the UAC prompt right away, it only flashes a shield on the taskbar — “clicked and nothing happened”.
pub fn shell_execute_from(parent: isize, verb: &str, file: &str, params: &str) -> std::io::Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let r = unsafe {
        ShellExecuteW(
            parent as _,
            wide(verb).as_ptr(),
            wide(file).as_ptr(),
            if params.is_empty() { std::ptr::null() } else { wide(params).as_ptr() },
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // per the documentation, values ≤ 32 are errors
    if (r as isize) <= 32 {
        let code = r as isize;
        return Err(if code == 5 || code == 1223 {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "launch cancelled or denied")
        } else {
            std::io::Error::other(format!("ShellExecute: code {code}"))
        });
    }
    Ok(())
}

/// Opens Explorer with the file selected.
pub fn reveal_in_explorer(path: &str) -> std::io::Result<()> {
    shell_execute("open", "explorer.exe", &format!("/select,\"{path}\""))
}

/// A string value from HKLM (for example, the CPU model).
pub fn reg_hklm(subkey: &str, value: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let mut buf = vec![0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, wide(subkey).as_ptr(), wide(value).as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
    };
    if r != 0 {
        return None;
    }
    let n = (len as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]).trim().to_string())
}

/// Whether the current process runs with administrator rights.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut te = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(token, TokenElevation, (&mut te as *mut TOKEN_ELEVATION).cast(), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len)
    };
    unsafe { CloseHandle(token) };
    ok != 0 && te.TokenIsElevated != 0
}

/// The process owner SID as a string (“S-1-5-21-…”); needs a handle with PROCESS_QUERY_LIMITED_INFORMATION.
pub fn process_user_sid(process: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut buf = vec![0u64; 64];
    let mut len = 0u32;
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len) };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return None;
    }
    // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER struct, the SID is in it too.
    let tu: TOKEN_USER = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
    let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(tu.User.Sid, &mut s) } == 0 || s.is_null() {
        return None;
    }
    let n = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, n) });
    unsafe { LocalFree(s.cast()) };
    Some(out)
}

/// The SID of the user tm runs as.
pub fn current_user_sid() -> Option<String> {
    process_user_sid(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() })
}

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// The “Startup” marks of the Windows Task Manager and Settings: 12 bytes, an even first byte —
/// enabled, an odd one (03, 07) — the user turned it off. The Run entry stays in place.
const APPROVED_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

/// Whether autostart was turned off by the user in Windows “Startup apps” (the Run entry exists but does not work).
pub fn autostart_disabled_by_user(name: &str) -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_BINARY};
    // usually 12 bytes, but can be longer — a short buffer would make the read fail
    let mut buf = [0u8; 64];
    let mut len = buf.len() as u32;
    let r = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, wide(APPROVED_KEY).as_ptr(), wide(name).as_ptr(), RRF_RT_REG_BINARY, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
    };
    r == 0 && len >= 1 && buf[0] & 1 == 1
}

/// Whether autostart actually works: the Run entry exists and is not turned off in “Startup apps”.
pub fn autostart_enabled(name: &str) -> bool {
    autostart_get(name).is_some() && !autostart_disabled_by_user(name)
}

/// The current user’s autostart command (HKCU\…\Run), if there is one.
pub fn autostart_get(name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};
    let mut buf = vec![0u16; 1024];
    let mut len = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), wide(name).as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
    };
    if r != 0 {
        return None;
    }
    let n = (len as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

/// Enables (`Some(command)`) or disables (`None`) autostart for the current user.
/// HKCU only — no administrator rights and no system settings changes.
pub fn autostart_set(name: &str, cmd: Option<&str>) -> std::io::Result<()> {
    use windows_sys::Win32::System::Registry::{RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};
    use windows_sys::Win32::System::Registry::REG_BINARY;
    let r = match cmd {
        Some(c) => {
            let data = wide(c);
            let r = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), wide(name).as_ptr(), REG_SZ, data.as_ptr().cast(), (data.len() * 2) as u32) };
            // enabling it in the window is an explicit wish of the user: also clear the “disabled” mark from
            // “Startup apps”, otherwise the Run entry would exist but nothing would start
            if r == 0 && autostart_disabled_by_user(name) {
                let on = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let w = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, wide(APPROVED_KEY).as_ptr(), wide(name).as_ptr(), REG_BINARY, on.as_ptr().cast(), on.len() as u32) };
                if w != 0 {
                    crate::logs::warn(format!("autostart: could not clear the “disabled” mark ({w})"));
                }
            }
            r
        }
        None => {
            // remove the mark too, so no empty row is left in “Startup apps”
            unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, wide(APPROVED_KEY).as_ptr(), wide(name).as_ptr()) };
            match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), wide(name).as_ptr()) } {
                2 => 0, // not there anyway
                r => r,
            }
        }
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(r as i32))
    }
}
