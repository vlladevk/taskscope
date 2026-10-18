//! The watcher: finds problem processes and keeps an event log.
//!
//! The rules are deliberately simple and explainable:
//! - “runaway loop” (red): the process holds exactly one core without a break for 3+ minutes;
//! - “memory leak” (red): memory only grows for 20+ minutes, faster than 10 MB/min;
//! - “high load” (yellow): the process takes 30 %+ of the whole CPU for longer than 20 seconds.
//! The log records the start and end of problems and episodes of whole-system overload
//! with the main culprit — so you can see later who slowed the computer down at night.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{AppStat, Frame, ProcKey};

const RUNAWAY_MS: u64 = 3 * 60_000;
const HOT_MS: u64 = 20_000;
const HOT_CPU: f32 = 30.0;
const LEAK_WINDOW: usize = 21; // samples once a minute → 20 minutes
const LEAK_MIN_GROWTH: u64 = 300 << 20;
const LEAK_MIN_RATE: f64 = 10.0 * (1 << 20) as f64; // bytes/min
const SYS_CPU_HIGH: f32 = 90.0;
const SYS_MEM_HIGH: u32 = 90;
const SYS_EPISODE_MS: u64 = 30_000;
const EVENTS_CAP: usize = 500;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issue {
    pub pid: u32,
    pub create_time: i64,
    pub name: String,
    /// red | yel
    pub level: String,
    /// runaway | leak | hot
    pub kind: String,
    pub text: String,
    pub since_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub at_ms: u64,
    /// red | yel | info | ok
    pub level: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_time: Option<i64>,
}

#[derive(Default)]
struct ProcWatch {
    core_since: Option<u64>,
    hot_since: Option<u64>,
    hot_peak: f32,
    mem: VecDeque<u64>,
    mem_at: u64,
}

#[derive(Default)]
struct Episode {
    since: Option<u64>,
    logged: bool,
    peak: f32,
    culprit: HashMap<String, f64>,
}

#[derive(Default)]
pub struct Watch {
    procs: HashMap<ProcKey, ProcWatch>,
    issues: Vec<Issue>,
    events: VecDeque<Event>,
    seq: u64,
    cpu_ep: Episode,
    mem_ep: Episode,
}

fn dur(ms: u64) -> String {
    let s = ms / 1000;
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min", s / 60)
    } else {
        format!("{} h {} min", s / 3600, s / 60 % 60)
    }
}

fn mb(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else {
        format!("{} MB", b >> 20)
    }
}

fn pct(v: f32) -> String {
    if v < 10.0 {
        format!("{v:.1}%")
    } else {
        format!("{v:.0}%")
    }
}

impl Watch {
    pub fn log(&mut self, at_ms: u64, level: &str, text: String, who: Option<(u32, i64)>) {
        self.seq += 1;
        self.events.push_back(Event {
            seq: self.seq,
            at_ms,
            level: level.into(),
            text,
            pid: who.map(|w| w.0),
            create_time: who.map(|w| w.1),
        });
        while self.events.len() > EVENTS_CAP {
            self.events.pop_front();
        }
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Events newer than `after` (by sequence number), oldest first.
    pub fn events_after(&self, after: u64) -> Vec<Event> {
        self.events.iter().filter(|e| e.seq > after).cloned().collect()
    }

    pub fn update(&mut self, t: u64, frame: &Frame, apps: &[AppStat]) {
        let ncpu = frame.system.logical_cpus.max(1) as f32;
        let core = 100.0 / ncpu;
        let mut issues = Vec::new();
        let mut alive = std::collections::HashSet::with_capacity(frame.procs.len());

        for p in &frame.procs {
            // pseudo-processes (interrupts, DPC) are not programs: “runaway loop” does not apply to them
            if p.pid <= 4 || crate::sampler::is_pseudo(p.pid) {
                continue;
            }
            let key = p.key();
            alive.insert(key);
            let w = self.procs.entry(key).or_default();

            // exactly one core: that is what a thread stuck in an infinite loop looks like
            let one_core = ncpu >= 2.0 && p.cpu >= core * 0.8 && p.cpu <= core * 1.2;
            w.core_since = if one_core { w.core_since.or(Some(t)) } else { None };
            if let Some(s) = w.core_since {
                if t - s >= RUNAWAY_MS {
                    issues.push(Issue {
                        pid: p.pid,
                        create_time: p.create_time,
                        name: p.name.clone(),
                        level: "red".into(),
                        kind: "runaway".into(),
                        text: format!(
                            "Exactly one core ({} CPU) without a break for {}. This looks like a runaway loop — the process is most likely doing nothing useful.",
                            pct(core),
                            dur(t - s)
                        ),
                        since_ms: s,
                    });
                }
            }

            if p.cpu >= HOT_CPU {
                w.hot_since.get_or_insert(t);
                w.hot_peak = w.hot_peak.max(p.cpu);
            } else {
                w.hot_since = None;
                w.hot_peak = 0.0;
            }
            if let Some(s) = w.hot_since {
                if t - s >= HOT_MS && w.core_since.map_or(true, |c| t - c < RUNAWAY_MS) {
                    issues.push(Issue {
                        pid: p.pid,
                        create_time: p.create_time,
                        name: p.name.clone(),
                        level: "yel".into(),
                        kind: "hot".into(),
                        text: format!("Load {} CPU for {} (peak {}).", pct(p.cpu), dur(t - s), pct(w.hot_peak)),
                        since_ms: s,
                    });
                }
            }

            // memory: sampled once a minute, 20-minute window
            if t.saturating_sub(w.mem_at) >= 60_000 {
                w.mem_at = t;
                w.mem.push_back(p.mem);
                while w.mem.len() > LEAK_WINDOW {
                    w.mem.pop_front();
                }
            }
            if w.mem.len() == LEAK_WINDOW {
                let first = w.mem[0];
                let last = *w.mem.back().unwrap();
                let ups = w.mem.iter().zip(w.mem.iter().skip(1)).filter(|(a, b)| b >= a).count();
                let rate = last.saturating_sub(first) as f64 / (LEAK_WINDOW - 1) as f64;
                if last > first + LEAK_MIN_GROWTH && ups * 10 >= (LEAK_WINDOW - 1) * 9 && rate >= LEAK_MIN_RATE {
                    issues.push(Issue {
                        pid: p.pid,
                        create_time: p.create_time,
                        name: p.name.clone(),
                        level: "red".into(),
                        kind: "leak".into(),
                        text: format!(
                            "Memory only grows: ~{} MB/min over the last 20 min, now {}. Looks like a leak — a restart will free the memory.",
                            (rate / (1 << 20) as f64).round(),
                            mb(last)
                        ),
                        since_ms: t - 20 * 60_000,
                    });
                }
            }
        }
        self.procs.retain(|k, _| alive.contains(k));

        // start and end of problems — into the log
        for i in &issues {
            if !self.issues.iter().any(|o| o.pid == i.pid && o.create_time == i.create_time && o.kind == i.kind) {
                let what = match i.kind.as_str() {
                    "runaway" => "looks stuck in a loop",
                    "leak" => "memory keeps growing",
                    _ => "high CPU load",
                };
                self.log(t, &i.level, format!("{}: {what}", i.name), Some((i.pid, i.create_time)));
            }
        }
        for o in &self.issues {
            if o.kind != "hot" && !issues.iter().any(|i| i.pid == o.pid && i.create_time == o.create_time && i.kind == o.kind) {
                let gone = !alive.contains(&(o.pid, o.create_time));
                let text = if gone { format!("{}: process exited", o.name) } else { format!("{}: problem is gone", o.name) };
                self.events.push_back(Event {
                    seq: self.seq + 1,
                    at_ms: t,
                    level: "ok".into(),
                    text,
                    pid: Some(o.pid),
                    create_time: Some(o.create_time),
                });
                self.seq += 1;
            }
        }
        self.issues = issues;

        // whole-system overload episodes
        let top_app = |by: fn(&AppStat) -> f64| apps.iter().max_by(|a, b| by(a).total_cmp(&by(b))).map(|a| (a.title.clone(), by(a)));
        let cpu = frame.system.cpu;
        let cpu_top = top_app(|a| a.cpu as f64);
        episode(&mut self.cpu_ep, cpu >= SYS_CPU_HIGH, cpu, t, cpu_top.as_ref());
        let memp = frame.system.memory.load_pct;
        let mem_top = top_app(|a| a.mem as f64);
        episode(&mut self.mem_ep, memp >= SYS_MEM_HIGH, memp as f32, t, mem_top.as_ref());
        let mut out = Vec::new();
        for (ep, what, unit) in [(&mut self.cpu_ep, "CPU at", "CPU"), (&mut self.mem_ep, "Memory at", "Memory")] {
            if let Some(s) = ep.since {
                if !ep.logged && t - s >= SYS_EPISODE_MS {
                    ep.logged = true;
                    let who = culprit(ep).map(|c| format!(" — top consumer {c}")).unwrap_or_default();
                    out.push(("yel", format!("{what} {}{who}", pct(ep.peak))));
                }
            } else if ep.logged {
                ep.logged = false;
                let who = culprit(ep).map(|c| format!(", main culprit — {c}")).unwrap_or_default();
                out.push(("info", format!("{unit} overload ended (peak {}{who})", pct(ep.peak))));
                ep.culprit.clear();
                ep.peak = 0.0;
            }
        }
        for (lvl, text) in out {
            self.log(t, lvl, text, None);
        }
    }
}

fn episode(ep: &mut Episode, high: bool, v: f32, t: u64, top: Option<&(String, f64)>) {
    if high {
        ep.since.get_or_insert(t);
        ep.peak = ep.peak.max(v);
        if let Some((name, val)) = top {
            *ep.culprit.entry(name.clone()).or_default() += val;
        }
    } else {
        ep.since = None;
        if !ep.logged {
            ep.peak = 0.0;
            ep.culprit.clear();
        }
    }
}

fn culprit(ep: &Episode) -> Option<String> {
    ep.culprit.iter().max_by(|a, b| a.1.total_cmp(b.1)).map(|(n, _)| n.clone())
}
