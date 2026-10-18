//! GPUs: load and video memory — total and per process.
//!
//! The source is the “GPU Engine”, “GPU Process Memory” and
//! “GPU Adapter Memory” performance counters (the Windows Task Manager shows the same). No administrator rights needed.
//! A process’s load is the busiest of the GPU engines it uses;
//! a GPU’s load is the busiest engine (3D, copy, video codec…) summed over processes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW, PDH_FMT_COUNTERVALUE_ITEM_W,
    PDH_FMT_DOUBLE, PDH_FMT_LARGE,
};

type PdhQuery = isize;
type PdhCounter = isize;
const PDH_FMT_NOCAP100: u32 = 0x8000;

const PDH_MORE_DATA: u32 = 0x8000_07D2;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GpuStat {
    /// Adapter LUID in the counter record: `0x00000000_0x0000D1F2`.
    pub key: String,
    pub name: String,
    /// Load, % (the busiest engine).
    pub util: f32,
    /// Which engine is the busiest: 3D, Copy, VideoDecode, Compute…
    pub engine: String,
    pub mem_used: u64,
    pub mem_total: u64,
    pub shared_used: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ProcGpu {
    pub util: f32,
    pub mem: u64,
    /// GPU LUID → the process’s busiest engine on it, %.
    pub by: Vec<(String, f32)>,
}

#[derive(Default)]
pub struct GpuSample {
    pub adapters: Vec<GpuStat>,
    pub procs: HashMap<u32, ProcGpu>,
}

pub struct GpuSampler {
    query: PdhQuery,
    engine: PdhCounter,
    proc_mem: PdhCounter,
    dedicated: PdhCounter,
    shared: PdhCounter,
    /// LUID → (name, video memory size) from the DirectX registry.
    names: HashMap<String, (String, u64)>,
    buf: Vec<u64>,
}


fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

/// “pid_1234_luid_0x00000000_0x0000D1F2_phys_0_eng_3_engtype_VideoDecode” → parts.
struct Inst<'a> {
    pid: Option<u32>,
    luid: &'a str,
    eng: &'a str,
    engtype: &'a str,
}

fn parse(name: &str) -> Inst<'_> {
    let field = |key: &str| -> Option<&str> {
        let i = name.find(key)? + key.len();
        let rest = &name[i..];
        Some(rest)
    };
    let pid = field("pid_").and_then(|r| r.split('_').next()).and_then(|s| s.parse().ok());
    let luid = field("luid_").map(|r| {
        // “0x00000000_0x0000D1F2” — two parts
        let end = r.match_indices('_').nth(1).map_or(r.len(), |(i, _)| i);
        &r[..end]
    });
    let eng = field("_eng_").and_then(|r| r.split('_').next()).unwrap_or("");
    let engtype = field("engtype_").unwrap_or("");
    Inst { pid, luid: luid.unwrap_or(""), eng, engtype }
}

/// GPU names from HKLM\SOFTWARE\Microsoft\DirectX\{…}: Description and AdapterLuid.
fn adapter_names() -> HashMap<String, (String, u64)> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_QWORD, RRF_RT_REG_SZ,
    };
    let mut out = HashMap::new();
    let mut root: HKEY = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(r"SOFTWARE\Microsoft\DirectX").as_ptr(), 0, KEY_READ, &mut root) } != 0 {
        return out;
    }
    for i in 0.. {
        let mut name = [0u16; 128];
        let mut len = name.len() as u32;
        let r = unsafe {
            RegEnumKeyExW(root, i, name.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if r != 0 {
            break;
        }
        let sub = &name[..len as usize];
        let mut sub_z = sub.to_vec();
        sub_z.push(0);
        let qword = |value: &str| -> Option<u64> {
            let mut v = 0u64;
            let mut n = 8u32;
            let r = unsafe { RegGetValueW(root, sub_z.as_ptr(), wide(value).as_ptr(), RRF_RT_REG_QWORD, std::ptr::null_mut(), (&mut v as *mut u64).cast(), &mut n) };
            (r == 0).then_some(v)
        };
        let Some(luid) = qword("AdapterLuid") else { continue };
        let mut buf = [0u16; 256];
        let mut n = (buf.len() * 2) as u32;
        let r = unsafe { RegGetValueW(root, sub_z.as_ptr(), wide("Description").as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut n) };
        if r != 0 {
            continue;
        }
        let desc = String::from_utf16_lossy(&buf[..(n as usize / 2).saturating_sub(1)]);
        let key = format!("0x{:08X}_0x{:08X}", luid >> 32, luid & 0xFFFF_FFFF);
        out.insert(key, (desc, qword("DedicatedVideoMemory").unwrap_or(0)));
    }
    unsafe { RegCloseKey(root) };
    out
}

impl GpuSampler {
    /// `None` — the system has no GPU counters (old Windows, a remote session without a GPU).
    pub fn new() -> Option<Self> {
        let mut query: PdhQuery = 0;
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let add = |path: &str| -> Option<PdhCounter> {
            let mut c: PdhCounter = 0;
            (unsafe { PdhAddEnglishCounterW(query, wide(path).as_ptr(), 0, &mut c) } == 0).then_some(c)
        };
        let (Some(engine), Some(proc_mem), Some(dedicated), Some(shared)) = (
            add(r"\GPU Engine(*)\Utilization Percentage"),
            add(r"\GPU Process Memory(*)\Dedicated Usage"),
            add(r"\GPU Adapter Memory(*)\Dedicated Usage"),
            add(r"\GPU Adapter Memory(*)\Shared Usage"),
        ) else {
            unsafe { PdhCloseQuery(query) };
            return None;
        };
        unsafe { PdhCollectQueryData(query) }; // the baseline for the load: this is a rate counter
        Some(Self { query, engine, proc_mem, dedicated, shared, names: adapter_names(), buf: Vec::new() })
    }

    /// All values of a counter: (instance name, number).
    fn read(&mut self, c: PdhCounter, fmt: u32, mut f: impl FnMut(&str, f64)) {
        let mut size = 0u32;
        let mut count = 0u32;
        let r = unsafe { PdhGetFormattedCounterArrayW(c, fmt, &mut size, &mut count, std::ptr::null_mut()) };
        if r != PDH_MORE_DATA || size == 0 {
            return;
        }
        self.buf.resize(size as usize / 8 + 1, 0);
        let items = self.buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
        if unsafe { PdhGetFormattedCounterArrayW(c, fmt, &mut size, &mut count, items) } != 0 {
            return;
        }
        for i in 0..count as usize {
            let it = unsafe { &*items.add(i) };
            if it.FmtValue.CStatus > 1 {
                continue; // PDH_CSTATUS_VALID_DATA = 0, NEW_DATA = 1
            }
            let name = unsafe { pwstr(it.szName) };
            let v = if fmt & PDH_FMT_LARGE != 0 { unsafe { it.FmtValue.Anonymous.largeValue as f64 } } else { unsafe { it.FmtValue.Anonymous.doubleValue } };
            f(&name, v);
        }
    }

    pub fn sample(&mut self) -> GpuSample {
        let mut out = GpuSample::default();
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return out;
        }
        // (luid, engine) → total over processes; process → its busiest engine
        let mut engines: HashMap<(String, String), (f64, String)> = HashMap::new();
        let engine = self.engine;
        self.read(engine, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, |name, v| {
            let i = parse(name);
            let e = engines.entry((i.luid.to_string(), i.eng.to_string())).or_insert((0.0, i.engtype.to_string()));
            e.0 += v;
            if let Some(pid) = i.pid {
                let p = out.procs.entry(pid).or_default();
                p.util = p.util.max(v as f32);
                match p.by.iter_mut().find(|(k, _)| k == i.luid) {
                    Some(b) => b.1 = b.1.max(v as f32),
                    None => p.by.push((i.luid.to_string(), v as f32)),
                }
            }
        });
        let proc_mem = self.proc_mem;
        self.read(proc_mem, PDH_FMT_LARGE, |name, v| {
            if let Some(pid) = parse(name).pid {
                out.procs.entry(pid).or_default().mem += v as u64;
            }
        });
        let mut adapters: HashMap<String, GpuStat> = HashMap::new();
        let dedicated = self.dedicated;
        self.read(dedicated, PDH_FMT_LARGE, |name, v| {
            adapters.entry(parse(name).luid.to_string()).or_default().mem_used += v as u64;
        });
        let shared = self.shared;
        self.read(shared, PDH_FMT_LARGE, |name, v| {
            adapters.entry(parse(name).luid.to_string()).or_default().shared_used += v as u64;
        });
        for ((luid, _), (util, kind)) in engines {
            let a = adapters.entry(luid).or_default();
            let u = (util as f32).min(100.0);
            if a.engine.is_empty() || u > a.util {
                a.util = u;
                a.engine = kind;
            }
        }
        for (key, mut a) in adapters {
            // the software “Microsoft Basic Render Driver” and other adapters without a name are not shown
            let Some((name, total)) = self.names.get(&key) else { continue };
            if name.contains("Basic Render") {
                continue;
            }
            a.key = key;
            a.name = name.clone();
            a.mem_total = *total;
            out.adapters.push(a);
        }
        out.adapters.sort_by(|a, b| b.mem_total.cmp(&a.mem_total));
        for p in out.procs.values_mut() {
            p.util = p.util.min(100.0);
            // only the shown GPUs and only noticeable load — the rest is not sent in every frame
            p.by.retain(|(k, u)| *u >= 0.05 && out.adapters.iter().any(|a| &a.key == k));
            for b in &mut p.by {
                b.1 = b.1.min(100.0);
            }
        }
        out
    }
}

impl Drop for GpuSampler {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.query) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_instance_names() {
        let i = parse("pid_1234_luid_0x00000000_0x0000D1F2_phys_0_eng_3_engtype_VideoDecode");
        assert_eq!(i.pid, Some(1234));
        assert_eq!(i.luid, "0x00000000_0x0000D1F2");
        assert_eq!(i.eng, "3");
        assert_eq!(i.engtype, "VideoDecode");
        let a = parse("luid_0x00000000_0x0001A2B3_phys_0");
        assert_eq!(a.pid, None);
        assert_eq!(a.luid, "0x00000000_0x0001A2B3");
    }
}
