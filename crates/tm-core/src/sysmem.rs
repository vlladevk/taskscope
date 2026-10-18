//! What the memory that is in use but not owned by any single process consists of:
//! kernel pools (driver memory), the file cache, kernel and driver code, modified pages.
//! Plus the page lists: standby, free, compressed.
//! The remainder is shared program memory (DLLs, shared buffers of browsers and Electron apps,
//! page tables): it is not part of the processes’ “private memory”.
//!
//! The source is the “Memory” counters (no administrator rights needed). The sample is cheap: one
//! PDH call for all counters.

use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryW, PDH_FMT_COUNTERVALUE, PDH_FMT_LARGE,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemDetail {
    /// Non-paged kernel pool — driver memory, always in RAM. Usually 0.2–0.6 GB.
    pub pool_nonpaged: u64,
    /// Paged kernel pool, partly in RAM.
    pub pool_paged: u64,
    /// The system file cache (its working set).
    pub cache: u64,
    /// Kernel and driver code in RAM.
    pub kernel_code: u64,
    /// Modified pages: waiting to be written to disk, then they are freed.
    pub modified: u64,
    /// Standby: a cache of recently used pages. Not counted as used memory —
    /// Windows hands it to programs on first request.
    #[serde(default)]
    pub standby: u64,
    /// Free and zeroed memory — not used by anything at all.
    #[serde(default)]
    pub free: u64,
    /// Compressed memory: the working set of the “Memory Compression” process (filled in by the engine).
    #[serde(default)]
    pub compressed: u64,
}

const COUNTERS: [&str; 10] = [
    r"\Memory\Pool Nonpaged Bytes",
    r"\Memory\Pool Paged Resident Bytes",
    r"\Memory\System Cache Resident Bytes",
    r"\Memory\System Driver Resident Bytes",
    r"\Memory\System Code Resident Bytes",
    r"\Memory\Modified Page List Bytes",
    r"\Memory\Standby Cache Core Bytes",
    r"\Memory\Standby Cache Normal Priority Bytes",
    r"\Memory\Standby Cache Reserve Bytes",
    r"\Memory\Free & Zero Page List Bytes",
];

pub struct MemSampler {
    query: isize,
    counters: Vec<isize>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl MemSampler {
    pub fn new() -> Option<Self> {
        let mut query = 0isize;
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let mut counters = Vec::new();
        for path in COUNTERS {
            let mut c = 0isize;
            // an unavailable counter stays zero, the others keep working
            let _ = unsafe { PdhAddEnglishCounterW(query, wide(path).as_ptr(), 0, &mut c) };
            counters.push(c);
        }
        Some(Self { query, counters })
    }

    pub fn sample(&mut self) -> MemDetail {
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return MemDetail::default();
        }
        let v: Vec<u64> = self
            .counters
            .iter()
            .map(|&c| {
                if c == 0 {
                    return 0;
                }
                let mut val: PDH_FMT_COUNTERVALUE = unsafe { std::mem::zeroed() };
                if unsafe { PdhGetFormattedCounterValue(c, PDH_FMT_LARGE, std::ptr::null_mut(), &mut val) } != 0 || val.CStatus > 1 {
                    return 0;
                }
                unsafe { val.Anonymous.largeValue }.max(0) as u64
            })
            .collect();
        MemDetail {
            pool_nonpaged: v[0],
            pool_paged: v[1],
            cache: v[2],
            kernel_code: v[3] + v[4],
            modified: v[5],
            standby: v[6] + v[7] + v[8],
            free: v[9],
            compressed: 0,
        }
    }
}

impl Drop for MemSampler {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.query) };
    }
}
