//! Kernel pool by tag — the memory the kernel and drivers take for their objects.
//!
//! Every pool allocation is tagged with four letters: `Toke` — security tokens,
//! `Thre` — threads, `NVRM` — the NVIDIA driver… Windows reports sizes by tag without administrator
//! rights (`NtQuerySystemInformation`, class 22) — it is one cheap call,
//! the engine makes it once a minute.
//!
//! A kernel leak is not visible in any process — it is visible only here, as a tag
//! that keeps growing. Whose tag it is — we search the files of loaded drivers
//! (`start_owner_scan`): the tag is baked into the driver code as the same four bytes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

const CLASS_POOLTAG: i32 = 22;
const CLASS_MODULES: i32 = 11;

/// Once a minute, for an hour — for a fresh rate and the chart.
const FINE_EVERY: u64 = 60_000;
const FINE_CAP: usize = 61;
/// Once every 10 minutes, for a day — for slow leaks.
const COARSE_EVERY: u64 = 10 * 60_000;
const COARSE_CAP: usize = 145;
/// We watch tags from 1 MB: there are thousands of small ones, and they will not turn into a leak unnoticed.
const TRACK_MIN: u64 = 1 << 20;

/// A home computer never has more tokens than this without a reference leak.
const TOKENS_HIGH: u64 = 30_000;
const ZOMBIE_PROCS_HIGH: i64 = 300;
const ZOMBIE_THREADS_HIGH: i64 = 3_000;

#[derive(Clone, Copy, Debug, Default)]
pub struct Raw {
    pub paged: u64,
    pub nonpaged: u64,
    /// Live allocations (allocated − freed).
    pub paged_live: u64,
    pub nonpaged_live: u64,
}

impl Raw {
    fn bytes(&self) -> u64 {
        self.paged + self.nonpaged
    }
    fn count(&self) -> u64 {
        self.paged_live + self.nonpaged_live
    }
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// The tag as a number — in the byte order it has in memory and in the driver code.
pub fn tag_id(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

pub fn tag_str(t: u32) -> String {
    t.to_le_bytes().iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' }).collect::<String>().trim_end().to_string()
}

/// All pool tags now. The `SYSTEM_POOLTAG_INFORMATION` layout on x64: the tag count,
/// then from byte 8 entries of 40 bytes — the tag, allocations/frees and bytes
/// of the paged pool, then the same for the non-paged one.
pub fn query() -> std::io::Result<HashMap<u32, Raw>> {
    let b = crate::nt::query_system(CLASS_POOLTAG, 256 << 10)?;
    let n = rd32(&b, 0) as usize;
    let mut m = HashMap::with_capacity(n);
    for i in 0..n {
        let o = 8 + i * 40;
        if o + 40 > b.len() {
            break;
        }
        // the counters are 32-bit and overflow; the difference modulo 2^32 stays correct
        let live = |a: u32, f: u32| a.wrapping_sub(f) as u64;
        m.insert(
            rd32(&b, o),
            Raw { paged: rd64(&b, o + 16), nonpaged: rd64(&b, o + 32), paged_live: live(rd32(&b, o + 4), rd32(&b, o + 8)), nonpaged_live: live(rd32(&b, o + 24), rd32(&b, o + 28)) },
        );
    }
    Ok(m)
}

/// What the tag is — for the most common and important ones. For the rest the driver search will tell.
pub fn about(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "Toke" => "Security tokens — program “passes”: whose identity they run under and what they may do",
        "SeAt" => "Token attributes: groups and privileges",
        "SeTl" => "Token bookkeeping records",
        "Proc" => "Process objects, including exited ones that handles still point to",
        "Thre" => "Thread objects, including exited ones that handles still point to",
        "File" => "Open files",
        "Even" => "Events — program synchronisation objects",
        "Sema" => "Semaphores — synchronisation objects",
        "Muta" => "Mutexes — synchronisation objects",
        "Key" => "Open registry keys",
        "ObNm" => "Kernel object names",
        "ObDi" => "Kernel object directories",
        "AlMs" => "ALPC messages — communication between programs and services",
        "smNp" | "smCB" | "smBt" | "smCo" => "Memory compression: the compressed page store",
        "EtwB" => "Event tracing (ETW) buffers — logs written by Windows and programs",
        "EtwR" => "Event tracing (ETW) records",
        "MmSt" => "Memory-mapped file tables",
        "MmCa" => "Memory-mapped file sections",
        "MmRe" => "Memory management: resources",
        "Vad" | "VadS" | "Vadl" => "Process memory maps (VAD)",
        "FMfn" => "File name cache of filter drivers (antivirus, cloud drives, backup)",
        "FMsl" => "Filter drivers: file records",
        "FMsc" => "Filter drivers: open file contexts",
        "FMic" => "Filter drivers: instance contexts",
        "NtfF" => "NTFS: open file records",
        "Ntff" => "NTFS: file control blocks",
        "NtFs" => "NTFS: internal data",
        "CM31" | "CM25" | "CM16" | "CM29" | "CM32" => "Windows registry",
        "DxgK" => "DirectX: graphics kernel",
        "NVRM" => "NVIDIA graphics driver",
        "AfdB" | "AfdE" => "Network sockets (AFD)",
        "TcpE" | "TcpL" | "TcpR" => "TCP connections",
        "Irp" => "I/O requests to drivers",
        "Pool" => "The pool’s own tables",
        "VdMm" => "Hyper-V: virtual machines (WSL, Docker, Sandbox)",
        "Wfp" | "WfpL" => "Windows Firewall (WFP)",
        "Cont" => "Contiguous physical memory for devices",
        "HalD" => "HAL: memory for devices (DMA)",
        "MmCm" => "Contiguous memory for drivers",
        "Gh05" | "Gla5" | "Gpbm" => "Graphics subsystem (win32k)",
        _ => return None,
    })
}

// ───────────────────────────── tracking ─────────────────────────────

#[derive(Clone, Copy)]
struct Pt {
    t: u64,
    bytes: u64,
    count: u64,
}

#[derive(Default)]
struct Series {
    fine: VecDeque<Pt>,
    coarse: VecDeque<Pt>,
}

/// Growth rate per hour by least squares. `None` while there is less than 10 minutes of data.
fn slope(pts: &VecDeque<Pt>, f: fn(&Pt) -> u64) -> Option<(f64, u64)> {
    if pts.len() < 3 {
        return None;
    }
    let span = pts.back()?.t - pts.front()?.t;
    if span < 10 * 60_000 {
        return None;
    }
    let n = pts.len() as f64;
    let t0 = pts[0].t as f64;
    let mx = pts.iter().map(|p| (p.t as f64 - t0) / 3.6e6).sum::<f64>() / n;
    let my = pts.iter().map(|p| f(p) as f64).sum::<f64>() / n;
    let (mut sxy, mut sxx) = (0.0, 0.0);
    for p in pts {
        let x = (p.t as f64 - t0) / 3.6e6 - mx;
        sxy += x * (f(p) as f64 - my);
        sxx += x * x;
    }
    (sxx > 0.0).then(|| (sxy / sxx, span))
}

/// The share of steps on which the value did not decrease.
fn ups(pts: &VecDeque<Pt>, f: fn(&Pt) -> u64) -> f64 {
    if pts.len() < 2 {
        return 0.0;
    }
    let up = pts.iter().zip(pts.iter().skip(1)).filter(|(a, b)| f(b) >= f(a)).count();
    up as f64 / (pts.len() - 1) as f64
}

impl Series {
    fn best(&self) -> &VecDeque<Pt> {
        let span = |v: &VecDeque<Pt>| v.back().map_or(0, |b| b.t - v[0].t);
        if span(&self.coarse) >= 60 * 60_000 {
            &self.coarse
        } else {
            &self.fine
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolAlert {
    pub tag: String,
    /// red | yel
    pub level: String,
    /// leak | tokens | zombie_procs | zombie_threads
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TagReport {
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    pub paged: u64,
    pub nonpaged: u64,
    /// Live allocations (for kernel objects — the object count).
    pub count: u64,
    /// Growth, bytes per hour; `None` — observed for less than 10 minutes.
    #[serde(default)]
    pub rate: Option<f64>,
    /// Growth of the allocation count per hour.
    #[serde(default)]
    pub count_rate: Option<f64>,
    /// Over what span the growth was computed, ms.
    #[serde(default)]
    pub rate_window_ms: u64,
    /// Size (bytes) over time — for the chart; step `spark_step_ms`.
    #[serde(default)]
    pub spark: Vec<u64>,
    #[serde(default)]
    pub spark_step_ms: u64,
    /// Driver files whose code contains the tag (after the search).
    #[serde(default)]
    pub owners: Vec<String>,
    #[serde(default)]
    pub alert: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OwnersStatus {
    /// idle | running | done
    pub state: String,
    pub scanned: usize,
    pub total: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolReport {
    pub at_ms: u64,
    /// How long we have been observing (the growth rate gets more precise every hour).
    pub watching_ms: u64,
    pub paged: u64,
    pub nonpaged: u64,
    pub tags: Vec<TagReport>,
    pub alerts: Vec<PoolAlert>,
    /// Exited processes and threads still kept in memory (more objects than live ones).
    pub zombie_procs: i64,
    pub zombie_threads: i64,
    pub owners: OwnersStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Default)]
pub struct PoolWatch {
    series: HashMap<u32, Series>,
    last: HashMap<u32, Raw>,
    at_ms: u64,
    started_ms: u64,
    coarse_at: u64,
    alerts: Vec<PoolAlert>,
    zombie_procs: i64,
    zombie_threads: i64,
    error: Option<String>,
}

fn mb(b: f64) -> String {
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} GB", b / (1u64 << 30) as f64)
    } else if b >= 10.0 * 1024.0 * 1024.0 {
        format!("{:.0} MB", b / (1u64 << 20) as f64)
    } else {
        format!("{:.1} MB", b / (1u64 << 20) as f64)
    }
}

fn span_text(ms: u64) -> String {
    let min = ms / 60_000;
    if min < 90 {
        format!("{min} min")
    } else {
        format!("{} h", (min + 30) / 60)
    }
}

/// File cache metadata: grows from any file reads and is returned to the system by itself.
fn is_cache_tag(tag: &str) -> bool {
    matches!(tag, "MmSt" | "MmCa" | "File" | "NtfF" | "Ntff" | "NtFs" | "FMfn" | "FMsl" | "FMsc" | "CcSc" | "Vacb" | "FSfm" | "FSim")
}

fn thousands(n: f64) -> String {
    let n = n.round() as i64;
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("−{out}")
    } else {
        out
    }
}

impl PoolWatch {
    /// Whether it is time to sample the pool again (once a minute).
    pub fn due(&self, t: u64) -> bool {
        self.at_ms == 0 || t.saturating_sub(self.at_ms) >= FINE_EVERY
    }

    /// Takes a sample. Returns log entries: problems that appeared and went away.
    pub fn ingest(&mut self, t: u64, raw: std::io::Result<HashMap<u32, Raw>>, procs: usize, threads: u64) -> Vec<(&'static str, String)> {
        let raw = match raw {
            Ok(r) => r,
            Err(e) => {
                self.error = Some(e.to_string());
                self.at_ms = t;
                return Vec::new();
            }
        };
        self.error = None;
        if self.started_ms == 0 {
            self.started_ms = t;
        }
        self.at_ms = t;
        let coarse = t.saturating_sub(self.coarse_at) >= COARSE_EVERY || self.coarse_at == 0;
        if coarse {
            self.coarse_at = t;
        }
        for (&tag, r) in &raw {
            if r.bytes() < TRACK_MIN && !self.series.contains_key(&tag) {
                continue;
            }
            let s = self.series.entry(tag).or_default();
            let p = Pt { t, bytes: r.bytes(), count: r.count() };
            s.fine.push_back(p);
            while s.fine.len() > FINE_CAP {
                s.fine.pop_front();
            }
            if coarse {
                s.coarse.push_back(p);
                while s.coarse.len() > COARSE_CAP {
                    s.coarse.pop_front();
                }
            }
        }
        // the tag disappeared or has long been small — stop watching
        self.series.retain(|tag, s| raw.get(tag).is_some_and(|r| r.bytes() >= TRACK_MIN / 4) || s.fine.iter().any(|p| p.bytes >= TRACK_MIN));

        let obj = |name: &str| raw.get(&tag_id(name)).map_or(0, |r| r.count()) as i64;
        self.zombie_procs = (obj("Proc") - procs as i64).max(0);
        self.zombie_threads = (obj("Thre") - threads as i64).max(0);
        self.last = raw;

        let alerts = self.find_alerts();
        let mut out = Vec::new();
        for a in &alerts {
            if !self.alerts.iter().any(|o| o.tag == a.tag && o.kind == a.kind) {
                out.push((if a.level == "red" { "red" } else { "yel" }, format!("Kernel: {}", a.text)));
            }
        }
        for o in &self.alerts {
            if !alerts.iter().any(|a| a.tag == o.tag && a.kind == o.kind) {
                out.push(("ok", format!("Kernel: tag {} no longer grows", o.tag)));
            }
        }
        self.alerts = alerts;
        out
    }

    fn find_alerts(&self) -> Vec<PoolAlert> {
        let mut out = Vec::new();
        let toke = self.last.get(&tag_id("Toke")).copied().unwrap_or_default();
        if toke.count() >= TOKENS_HIGH {
            let rate = self.series.get(&tag_id("Toke")).and_then(|s| slope(s.best(), |p| p.count)).map(|r| r.0);
            let growing = rate.filter(|&r| r >= 100.0).map(|r| format!(", growing by ~{} per hour", thousands(r))).unwrap_or_default();
            out.push(PoolAlert {
                tag: "Toke".into(),
                level: "red".into(),
                kind: "tokens".into(),
                text: format!(
                    "{} security tokens have piled up ({}){growing}. Usually there are a few thousand: some program or driver does not release references. Most often the culprit is a program that starts processes every few seconds. A reboot frees them.",
                    thousands(toke.count() as f64),
                    mb(toke.bytes() as f64)
                ),
            });
        }
        if self.zombie_procs >= ZOMBIE_PROCS_HIGH {
            out.push(PoolAlert {
                tag: "Proc".into(),
                level: "yel".into(),
                kind: "zombie_procs".into(),
                text: format!("{} exited processes are still in memory — some program holds handles to them", thousands(self.zombie_procs as f64)),
            });
        }
        if self.zombie_threads >= ZOMBIE_THREADS_HIGH {
            out.push(PoolAlert {
                tag: "Thre".into(),
                level: "yel".into(),
                kind: "zombie_threads".into(),
                text: format!("{} exited threads are still in memory — some program holds handles to them", thousands(self.zombie_threads as f64)),
            });
        }
        for (&tag, s) in &self.series {
            let name = tag_str(tag);
            if name == "Toke" && out.iter().any(|a| a.kind == "tokens") {
                continue;
            }
            // file cache tags grow along with file reads (indexer, builds, antivirus)
            // and are freed by themselves — alarm only if the growth lasts half a day and adds up to a lot
            let cache = is_cache_tag(&name);
            // slow leak: 3+ hours with almost no drops, +1 MB/h or more
            let slow = s.coarse.len() >= if cache { 73 } else { 19 } && ups(&s.coarse, |p| p.bytes) >= 0.85;
            // fast: half an hour with almost no drops and already +50 MB
            let fast = !cache && s.fine.len() >= 31 && ups(&s.fine, |p| p.bytes) >= 0.9;
            let pts = if slow { &s.coarse } else { &s.fine };
            let grown = pts.back().map_or(0, |b| b.bytes.saturating_sub(pts[0].bytes));
            let Some((rate, span)) = slope(pts, |p| p.bytes) else { continue };
            let leak = (slow && rate >= (1 << 20) as f64 && grown >= if cache { 200 << 20 } else { 5 << 20 }) || (fast && grown >= 50 << 20);
            if !leak {
                continue;
            }
            let now = pts.back().map_or(0, |b| b.bytes) as f64;
            let what = about(&name).map(|a| format!(" ({})", a.split(" — ").next().unwrap_or(a).to_lowercase())).unwrap_or_default();
            out.push(PoolAlert {
                tag: name.clone(),
                level: if rate >= (20 << 20) as f64 || now >= (300 << 20) as f64 { "red" } else { "yel" }.into(),
                kind: "leak".into(),
                text: format!("tag {name}{what} has kept growing for {}: +{}/h, now {} — looks like a driver leak", span_text(span), mb(rate), mb(now)),
            });
        }
        out.sort_by(|a, b| (a.level != "red").cmp(&(b.level != "red")).then(a.tag.cmp(&b.tag)));
        out
    }

    pub fn alerts(&self) -> &[PoolAlert] {
        &self.alerts
    }

    /// Report: `n` tags by size (`by` = "size") or by growth ("growth"), plus all with an alarm.
    pub fn report(&self, n: usize, by: &str) -> PoolReport {
        let owners = owners().lock().unwrap();
        let mut tags: Vec<TagReport> = self
            .last
            .iter()
            .map(|(&tag, r)| {
                let name = tag_str(tag);
                let s = self.series.get(&tag);
                let pts = s.map(Series::best);
                let rate = pts.and_then(|p| slope(p, |x| x.bytes));
                let count_rate = pts.and_then(|p| slope(p, |x| x.count)).map(|r| r.0);
                let (spark, step) = match pts {
                    Some(p) if p.len() >= 2 => (p.iter().map(|x| x.bytes).collect(), if std::ptr::eq(p, &s.unwrap().coarse) { COARSE_EVERY } else { FINE_EVERY }),
                    _ => (Vec::new(), 0),
                };
                TagReport {
                    alert: self.alerts.iter().any(|a| a.tag == name),
                    about: about(&name).map(str::to_string),
                    paged: r.paged,
                    nonpaged: r.nonpaged,
                    count: r.count(),
                    rate: rate.map(|r| r.0),
                    count_rate,
                    rate_window_ms: rate.map_or(0, |r| r.1),
                    spark,
                    spark_step_ms: step,
                    owners: owners.map.get(&tag).cloned().unwrap_or_default(),
                    tag: name,
                }
            })
            .collect();
        let size = |t: &TagReport| t.paged + t.nonpaged;
        if by == "growth" {
            tags.sort_by(|a, b| b.rate.unwrap_or(f64::MIN).total_cmp(&a.rate.unwrap_or(f64::MIN)).then(size(b).cmp(&size(a))));
        } else {
            tags.sort_by(|a, b| size(b).cmp(&size(a)));
        }
        let mut out: Vec<TagReport> = Vec::with_capacity(n + self.alerts.len());
        let mut rest = Vec::new();
        for (i, t) in tags.into_iter().enumerate() {
            if i < n || t.alert {
                out.push(t);
            } else {
                rest.push(t);
            }
        }
        PoolReport {
            at_ms: self.at_ms,
            watching_ms: self.at_ms.saturating_sub(self.started_ms),
            paged: self.last.values().map(|r| r.paged).sum(),
            nonpaged: self.last.values().map(|r| r.nonpaged).sum(),
            tags: out,
            alerts: self.alerts.clone(),
            zombie_procs: self.zombie_procs,
            zombie_threads: self.zombie_threads,
            owners: owners.status.clone(),
            error: self.error.clone(),
        }
    }

    /// Tags we watch (for the driver search).
    pub fn tracked(&self) -> Vec<u32> {
        self.series.keys().copied().collect()
    }
}

// ───────────────────────────── whose tag ─────────────────────────────

#[derive(Default)]
struct Owners {
    status: OwnersStatus,
    map: HashMap<u32, Vec<String>>,
}

fn owners() -> &'static Mutex<Owners> {
    static O: OnceLock<Mutex<Owners>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(Owners { status: OwnersStatus { state: "idle".into(), ..Default::default() }, map: HashMap::new() }))
}

pub fn owners_status() -> OwnersStatus {
    owners().lock().unwrap().status.clone()
}

/// Loaded drivers: file paths. Addresses are hidden without administrator rights, but the names are visible.
pub fn loaded_drivers() -> Vec<std::path::PathBuf> {
    let Ok(b) = crate::nt::query_system(CLASS_MODULES, 128 << 10) else { return Vec::new() };
    let n = rd32(&b, 0) as usize;
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut out = Vec::new();
    for i in 0..n {
        let o = 8 + i * 296;
        if o + 296 > b.len() {
            break;
        }
        let raw = &b[o + 40..o + 296];
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        let p = String::from_utf8_lossy(&raw[..end]).to_string();
        let lower = p.to_ascii_lowercase();
        let path = if lower.starts_with(r"\systemroot\") {
            format!("{root}{}", &p[r"\SystemRoot".len()..])
        } else if let Some(rest) = p.strip_prefix(r"\??\") {
            rest.to_string()
        } else if lower.starts_with(r"\windows\") {
            format!("{}{}", &root[..2], p)
        } else if !p.contains(':') {
            format!(r"{root}\{}", p.trim_start_matches('\\'))
        } else {
            p
        };
        out.push(std::path::PathBuf::from(path));
    }
    out
}

/// Which of the tags occur in the file. In code a tag is an immediate operand of an instruction
/// (`mov r8d, 'ekoT'`), surrounded by instruction bytes; a match in the middle of text (“Token” in a string)
/// does not count — otherwise any driver with the word Token would “allocate” the `Toke` tag.
fn tags_in(data: &[u8], want: &HashSet<u32>, first: &[bool; 256]) -> HashSet<u32> {
    let text = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b' ';
    let mut hit = HashSet::new();
    for i in 0..data.len().saturating_sub(3) {
        if !first[data[i] as usize] {
            continue;
        }
        let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if !want.contains(&v) || hit.contains(&v) {
            continue;
        }
        let before = i.checked_sub(1).map(|j| data[j]);
        let after = data.get(i + 4).copied();
        if before.is_some_and(text) && after.is_some_and(text) {
            continue;
        }
        hit.insert(v);
    }
    hit
}

/// Searches for tags in the files of loaded drivers — in the background, with low disk priority.
/// A match means that the driver (most likely) allocates memory with this tag.
pub fn start_owner_scan(tags: Vec<u32>) -> OwnersStatus {
    {
        let mut o = owners().lock().unwrap();
        if o.status.state == "running" {
            return o.status.clone();
        }
        o.status = OwnersStatus { state: "running".into(), ..Default::default() };
    }
    let spawned = std::thread::Builder::new().name("tm-pool-owners".into()).spawn(move || {
        use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN};
        unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) };
        scan_owners(&tags, |scanned, total| {
            let mut o = owners().lock().unwrap();
            o.status.scanned = scanned;
            o.status.total = total;
        });
    });
    if let Err(e) = spawned {
        let mut o = owners().lock().unwrap();
        o.status = OwnersStatus { state: "idle".into(), error: Some(e.to_string()), ..Default::default() };
    }
    owners_status()
}

/// The same, synchronously (for the CLI). The result goes into the shared cache and the reports.
pub fn scan_owners(tags: &[u32], progress: impl Fn(usize, usize)) {
    let files = loaded_drivers();
    let want: HashSet<u32> = tags.iter().copied().collect();
    let mut first = [false; 256];
    for t in &want {
        first[(t & 0xff) as usize] = true;
    }
    let mut found: HashMap<u32, Vec<String>> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        progress(i, files.len());
        let Ok(data) = std::fs::read(f) else { continue };
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for t in tags_in(&data, &want, &first) {
            found.entry(t).or_default().push(name.clone());
        }
    }
    // not found among the loaded ones — search the other drivers of the system: an unloaded driver
    // that did not return its memory leaves its tag in the pool until a reboot
    let missing: HashSet<u32> = want.iter().copied().filter(|t| !found.contains_key(t)).collect();
    if !missing.is_empty() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let loaded: HashSet<String> = files.iter().filter_map(|f| f.file_name()).map(|n| n.to_string_lossy().to_ascii_lowercase()).collect();
        let rest: Vec<std::path::PathBuf> = std::fs::read_dir(format!(r"{root}\System32\drivers"))
            .map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter(|p| {
                let n = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                n.ends_with(".sys") && !loaded.contains(&n)
            })
            .collect();
        let mut first = [false; 256];
        for t in &missing {
            first[(t & 0xff) as usize] = true;
        }
        for (i, f) in rest.iter().enumerate() {
            progress(files.len() + i, files.len() + rest.len());
            let Ok(data) = std::fs::read(f) else { continue };
            let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            for t in tags_in(&data, &missing, &first) {
                found.entry(t).or_default().push(format!("{name} (not loaded)"));
            }
        }
    }
    // the kernel first: its tags also occur in drivers that merely call its functions
    for v in found.values_mut() {
        v.sort_by_key(|n| (!n.eq_ignore_ascii_case("ntoskrnl.exe"), n.to_ascii_lowercase()));
    }
    let mut o = owners().lock().unwrap();
    for t in tags {
        o.map.insert(*t, found.remove(t).unwrap_or_default());
    }
    o.status = OwnersStatus { state: "done".into(), scanned: files.len(), total: files.len(), error: None };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip() {
        assert_eq!(tag_str(tag_id("Toke")), "Toke");
        assert_eq!(tag_str(tag_id("Key")), "Key");
        assert_eq!(tag_id("Toke"), 0x656B_6F54);
    }

    #[test]
    fn tag_in_code_not_in_text() {
        let want: HashSet<u32> = [tag_id("Toke")].into_iter().collect();
        let mut first = [false; 256];
        first[b'T' as usize] = true;
        // the string “Token” in data is not a tag
        assert!(tags_in(b"\x00GetTokenInformation\x00", &want, &first).is_empty());
        // mov r8d, 'ekoT' — a tag
        assert_eq!(tags_in(b"\x41\xB8Toke\x48\x8B", &want, &first).len(), 1);
    }

    #[test]
    fn slope_per_hour() {
        let pts: VecDeque<Pt> = (0..31).map(|i| Pt { t: i * 60_000, bytes: 1000 + i * 100, count: i }).collect();
        let (r, span) = slope(&pts, |p| p.bytes).unwrap();
        assert!((r - 6000.0).abs() < 1e-6, "{r}");
        assert_eq!(span, 30 * 60_000);
    }

    #[test]
    fn detects_token_pileup() {
        let mut w = PoolWatch::default();
        let mut raw = HashMap::new();
        raw.insert(tag_id("Toke"), Raw { paged: 190 << 20, paged_live: 87_000, ..Default::default() });
        let ev = w.ingest(1_000, Ok(raw), 500, 9_000);
        assert_eq!(w.alerts().len(), 1);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].1.contains("87"));
    }

    #[test]
    fn file_cache_growth_is_not_a_leak() {
        let mut w = PoolWatch::default();
        for i in 0..=40u64 {
            let mut raw = HashMap::new();
            raw.insert(tag_id("MmSt"), Raw { paged: (20 << 20) + i * (3 << 20), ..Default::default() });
            raw.insert(tag_id("Xdrv"), Raw { nonpaged: (20 << 20) + i * (3 << 20), ..Default::default() });
            w.ingest(i * FINE_EVERY, Ok(raw), 300, 3_000);
        }
        let tags: Vec<_> = w.alerts().iter().map(|a| a.tag.as_str()).collect();
        assert_eq!(tags, ["Xdrv"]);
        assert!(w.alerts()[0].text.contains("40 min"), "{}", w.alerts()[0].text);
    }
}
