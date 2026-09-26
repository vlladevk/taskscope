//! Дескриптор процесса, который гарантированно закрывается (RAII) — утечь не может.

use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess};

pub struct ProcHandle(HANDLE);

impl ProcHandle {
    /// Открывает процесс и проверяет, что это тот же процесс (PID мог быть переиспользован).
    pub fn open(pid: u32, access: u32, create_time: Option<i64>) -> io::Result<Self> {
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let this = Self(h);
        if let Some(expected) = create_time {
            if this.create_time()? != expected {
                return Err(io::Error::new(io::ErrorKind::NotFound, "процесс с этим PID уже завершился (PID занят другим процессом)"));
            }
        }
        Ok(this)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    pub fn create_time(&self) -> io::Result<i64> {
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        if unsafe { GetProcessTimes(self.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(crate::nt::js_safe(((c.dwHighDateTime as i64) << 32) | c.dwLowDateTime as i64))
    }
}

impl Drop for ProcHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
