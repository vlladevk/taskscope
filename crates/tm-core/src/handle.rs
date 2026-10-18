//! A process handle that is guaranteed to be closed (RAII) — it cannot leak.

use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess};

pub struct ProcHandle(HANDLE);

impl ProcHandle {
    /// Opens the process and checks that it is the same process (the PID may have been reused).
    pub fn open(pid: u32, access: u32, create_time: Option<i64>) -> io::Result<Self> {
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let this = Self(h);
        if let Some(expected) = create_time {
            if this.create_time()? != expected {
                return Err(io::Error::new(io::ErrorKind::NotFound, "the process with this PID has already exited (the PID belongs to another process)"));
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
