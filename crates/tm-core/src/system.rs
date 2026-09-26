//! Общесистемные показатели: загрузка ЦП, память, число логических процессоров.

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{GetActiveProcessorCount, GetSystemTimes};

pub fn logical_cpus() -> u32 {
    unsafe { GetActiveProcessorCount(0xFFFF) }.max(1) // ALL_PROCESSOR_GROUPS
}

pub fn uptime_ms() -> u64 {
    unsafe { GetTickCount64() }
}

/// Текущее время как FILETIME (100 нс с 1601 г.) — в той же шкале, что время создания процесса.
pub fn filetime_now() -> i64 {
    let mut f = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    unsafe { windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime(&mut f) };
    (((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64) as i64
}

#[derive(Clone, Copy, Default)]
pub struct CpuTimes {
    idle: u64,
    kernel: u64, // включает idle
    user: u64,
}

pub fn cpu_times() -> CpuTimes {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut i, mut k, mut u) = (z, z, z);
    unsafe { GetSystemTimes(&mut i, &mut k, &mut u) };
    let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    CpuTimes { idle: ft(i), kernel: ft(k), user: ft(u) }
}

/// Загрузка ЦП в процентах между двумя замерами.
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


/// Запускает командную строку без наследования дескрипторов. `cwd` — рабочая папка.
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

/// Запускает процесс полностью отвязанным: без консоли, вне задания (job) родителя и,
/// главное, без унаследованных дескрипторов — иначе он держал бы открытыми каналы вывода
/// родителя, и `tm daemon start | ...` никогда бы не завершился.
pub fn spawn_detached(exe: &std::path::Path, args: &[&str]) -> std::io::Result<u32> {
    use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
    let mut cmd = format!("\"{}\"", exe.display());
    for a in args {
        cmd.push(' ');
        cmd.push_str(a);
    }
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // выход из задания разрешён не всегда — тогда запускаемся внутри него
    spawn(&cmd, None, base | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(&cmd, None, base))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ShellExecute: открыть файл, папку или ссылку «как двойным щелчком» (`verb` = "open")
/// или запустить с запросом прав администратора (`verb` = "runas").
pub fn shell_execute(verb: &str, file: &str, params: &str) -> std::io::Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide(verb).as_ptr(),
            wide(file).as_ptr(),
            if params.is_empty() { std::ptr::null() } else { wide(params).as_ptr() },
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // по документации значения ≤ 32 — ошибка
    if (r as isize) <= 32 {
        let code = r as isize;
        return Err(if code == 5 || code == 1223 {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "запуск отменён или запрещён")
        } else {
            std::io::Error::other(format!("ShellExecute: код {code}"))
        });
    }
    Ok(())
}

/// Открывает Проводник с выделенным файлом.
pub fn reveal_in_explorer(path: &str) -> std::io::Result<()> {
    shell_execute("open", "explorer.exe", &format!("/select,\"{path}\""))
}

/// Строковое значение из HKLM (например, модель процессора).
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

/// Запущен ли текущий процесс с правами администратора.
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
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Команда автозапуска текущего пользователя (HKCU\…\Run), если она есть.
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

/// Включает (`Some(команда)`) или выключает (`None`) автозапуск для текущего пользователя.
/// Только HKCU — без прав администратора и без изменения системных настроек.
pub fn autostart_set(name: &str, cmd: Option<&str>) -> std::io::Result<()> {
    use windows_sys::Win32::System::Registry::{RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};
    let r = match cmd {
        Some(c) => {
            let data = wide(c);
            unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), wide(name).as_ptr(), REG_SZ, data.as_ptr().cast(), (data.len() * 2) as u32) }
        }
        None => match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), wide(name).as_ptr()) } {
            2 => 0, // и так нет
            r => r,
        },
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(r as i32))
    }
}
