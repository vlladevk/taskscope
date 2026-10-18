//! Grouping processes into “apps”.
//!
//! We walk the ancestor chain from the root: skip system hosts (explorer, services, …),
//! then shells (terminal, pwsh, bash, …). The first process after them is the app root.
//! So `vitest` under `bash` under `claude` under `pwsh` under `WindowsTerminal` lands in the
//! Claude Code app, not in “Terminal” and not in “node”.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::info::InfoCache;
use crate::sampler::ProcStat;
use crate::tree::Tree;

const HOSTS: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "winlogon.exe",
    "explorer.exe", "userinit.exe", "svchost.exe", "sihost.exe", "system idle process",
    // launchers: an IDE or a game they started is a separate app, not part of the launcher
    "jetbrains-toolbox.exe", "steam.exe", "steamwebhelper.exe", "upc.exe", "ubisoftconnect.exe",
    "epicgameslauncher.exe", "battle.net.exe", "galaxyclient.exe", "eadesktop.exe",
];
const SHELLS: &[&str] = &[
    "windowsterminal.exe", "openconsole.exe", "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash.exe", "sh.exe", "zsh.exe", "wsl.exe", "wslhost.exe", "git-bash.exe", "mintty.exe",
];
/// The Windows kernel — one group instead of a dozen small ones.
const CORE: &[&str] = &[
    "system", "registry", "secure system", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe",
    // sampler pseudo-processes: interrupt and DPC handling
    "interrupts", "dpcs",
];

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// The index of the process that is the app root for process `i`.
pub fn app_root(procs: &[ProcStat], tree: &Tree, i: usize) -> usize {
    let mut chain = tree.ancestors(i);
    chain.push(i);
    let is = |list: &[&str], j: usize| list.contains(&lower(&procs[j].name).as_str());
    let Some(start) = chain.iter().position(|&j| !is(HOSTS, j)) else { return i }; // the process itself is a system host
    let rest = &chain[start..];
    rest.iter().copied().find(|&j| !is(SHELLS, j)).unwrap_or(rest[0])
}

/// The app group key: the lower-case executable name of the root.
pub fn app_key(procs: &[ProcStat], root: usize) -> String {
    let n = lower(&procs[root].name);
    if CORE.contains(&n.as_str()) {
        "windows".into()
    } else {
        n
    }
}

/// A human name for the group, if the file description is unavailable or useless.
fn builtin_title(key: &str) -> Option<&'static str> {
    Some(match key {
        "windows" => "Windows (kernel and system processes)",
        "svchost.exe" => "Windows services",
        "explorer.exe" => "File Explorer",
        "vmmemwsl" | "vmmem" => "WSL / Docker virtual machine",
        _ => return None,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppStat {
    /// A stable group key (the root exe name, or "windows").
    pub key: String,
    pub title: String,
    pub root_pid: u32,
    pub path: Option<String>,
    pub count: usize,
    pub cpu: f32,
    pub mem: u64,
    pub io_read_bps: f64,
    pub io_write_bps: f64,
    #[serde(default)]
    pub gpu: f32,
    #[serde(default)]
    pub gpu_mem: u64,
    #[serde(default)]
    pub net_rx_bps: f64,
    #[serde(default)]
    pub net_tx_bps: f64,
    pub pids: Vec<u32>,
    /// CPU of short-lived processes started by the app and missed by the samples (already included in `cpu`).
    #[serde(default)]
    pub short_cpu: f32,
    /// How many processes per second the app starts (smoothed).
    #[serde(default)]
    pub spawn_rate: f32,
    /// What it starts most often: “git”, “grep”, …
    #[serde(default)]
    pub spawn_names: Vec<String>,
    /// Process indices in the frame (internal, not serialised).
    #[serde(skip)]
    pub members: Vec<usize>,
}

/// The app key for every process of the frame.
pub fn keys(procs: &[ProcStat], tree: &Tree) -> Vec<String> {
    (0..procs.len()).map(|i| app_key(procs, app_root(procs, tree, i))).collect()
}

/// Per-app summary. The Idle process (PID 0) is in no group.
pub fn group(procs: &[ProcStat], tree: &Tree, info: &mut InfoCache) -> Vec<AppStat> {
    group_with(procs, tree, info, None)
}

/// Utilities that scripts start by the hundred: when orphaned (the parent already exited) they
/// stay in the parent’s app instead of becoming separate “git” and “xargs”.
const TOOLS: &[&str] = &[
    "git.exe", "grep.exe", "xargs.exe", "find.exe", "sed.exe", "awk.exe", "gawk.exe", "cat.exe", "head.exe",
    "tail.exe", "sort.exe", "uniq.exe", "wc.exe", "cut.exe", "tr.exe", "ls.exe", "rg.exe", "findstr.exe",
    "where.exe", "timeout.exe", "sleep.exe", "env.exe", "cygpath.exe", "uname.exe", "dirname.exe", "basename.exe",
];

/// Memory of recently seen processes: PID → app. Needed for orphans whose parent
/// has already exited: `xargs` from a Claude Code command stays in Claude Code after bash exits.
#[derive(Default)]
pub struct Lineage {
    /// PID → (app, creation time, last seen, ms)
    seen: HashMap<u32, (String, i64, u64)>,
    /// An inherited app is pinned to the process for its whole life
    sticky: HashMap<(u32, i64), String>,
}

impl Lineage {
    fn inherit(&mut self, p: &ProcStat) -> Option<String> {
        if let Some(k) = self.sticky.get(&p.key()) {
            return Some(k.clone());
        }
        let n = lower(&p.name);
        if p.ppid == 0 || !(SHELLS.contains(&n.as_str()) || TOOLS.contains(&n.as_str())) {
            return None;
        }
        // the parent was created before the child — otherwise someone else already took the PID
        let k = self.seen.get(&p.ppid).filter(|(_, ct, _)| *ct <= p.create_time)?.0.clone();
        self.sticky.insert(p.key(), k.clone());
        Some(k)
    }

    /// Remember the apps of live processes; forget those gone for longer than 2 minutes.
    pub fn update(&mut self, procs: &[ProcStat], groups: &[AppStat], now_ms: u64) {
        for g in groups {
            for &i in &g.members {
                let p = &procs[i];
                self.seen.insert(p.pid, (g.key.clone(), p.create_time, now_ms));
            }
        }
        self.seen.retain(|_, v| now_ms.saturating_sub(v.2) < 120_000);
        let alive: std::collections::HashSet<(u32, i64)> = procs.iter().map(|p| p.key()).collect();
        self.sticky.retain(|k, _| alive.contains(k));
    }
}

/// Like `group`, but orphaned utilities inherit the app of their exited parent.
pub fn group_with(procs: &[ProcStat], tree: &Tree, info: &mut InfoCache, mut lineage: Option<&mut Lineage>) -> Vec<AppStat> {
    let mut by_key: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<AppStat> = Vec::new();
    let mut root_depth: Vec<usize> = Vec::new();
    for i in 0..procs.len() {
        let p = &procs[i];
        if p.pid == 0 {
            continue;
        }
        let root = app_root(procs, tree, i);
        // an orphan: the top of the chain without a live parent — find whose the parent was
        let top = tree.ancestors(i).first().copied().unwrap_or(i);
        let inherited = lineage.as_deref_mut().and_then(|l| l.inherit(&procs[top]));
        let key = inherited.clone().unwrap_or_else(|| app_key(procs, root));
        let gi = *by_key.entry(key.clone()).or_insert_with(|| {
            out.push(AppStat {
                key,
                title: String::new(),
                root_pid: procs[root].pid,
                path: None,
                count: 0,
                cpu: 0.0,
                mem: 0,
                io_read_bps: 0.0,
                io_write_bps: 0.0,
                gpu: 0.0,
                gpu_mem: 0,
                net_rx_bps: 0.0,
                net_tx_bps: 0.0,
                pids: Vec::new(),
                short_cpu: 0.0,
                spawn_rate: 0.0,
                spawn_names: Vec::new(),
                members: Vec::new(),
            });
            root_depth.push(usize::MAX);
            out.len() - 1
        });
        let g = &mut out[gi];
        // the group root is the “eldest” process (fewest ancestors)
        // inherited orphans do not become the group root while it has processes of its own
        let depth = if inherited.is_some() { usize::MAX - 1 } else { tree.ancestors(root).len() };
        if depth < root_depth[gi] {
            root_depth[gi] = depth;
            g.root_pid = procs[root].pid;
        }
        // interrupts and DPC are load rows, not processes: they do not count in “N processes”
        if !crate::sampler::is_pseudo(p.pid) {
            g.count += 1;
        }
        g.cpu += p.cpu;
        g.mem += p.mem;
        g.io_read_bps += p.io_read_bps;
        g.io_write_bps += p.io_write_bps;
        g.gpu += p.gpu;
        g.gpu_mem += p.gpu_mem;
        g.net_rx_bps += p.net_rx_bps;
        g.net_tx_bps += p.net_tx_bps;
        g.pids.push(p.pid);
        g.members.push(i);
    }
    let idx: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    for g in &mut out {
        let root = &procs[idx[&g.root_pid]];
        let meta = info.get(root.key());
        g.path = meta.path.clone();
        g.title = builtin_title(&g.key)
            .map(str::to_string)
            .or_else(|| meta.description.clone())
            .unwrap_or_else(|| root.name.trim_end_matches(".exe").to_string());
    }
    out
}

/// Short-lived processes: who starts them and how much CPU they eat unseen by the samples.
#[derive(Default)]
pub struct Spawns {
    /// app → starts per second (smoothed, τ ≈ 8 s)
    rate: HashMap<String, f32>,
    /// app → name of what it starts → rate
    names: HashMap<String, HashMap<String, f32>>,
}

impl Spawns {
    /// Accounts for processes born during the interval and hands out the unseen CPU (machine load minus the sum
    /// over processes) to the apps that start them. The remainder goes to `SystemStat::unseen_cpu`.
    /// `exited_cpu` — CPU of processes that exited during the interval (known exactly and already given to their apps).
    pub fn apply(&mut self, procs: &[ProcStat], groups: &mut [AppStat], sys: &mut crate::SystemStat, dt: f64, exited_cpu: f32) {
        if dt <= 0.0 {
            return;
        }
        let a = 1.0 - (-dt / 8.0).exp() as f32;
        let mut born: HashMap<&str, (f32, HashMap<String, f32>)> = HashMap::new();
        for g in groups.iter() {
            for &i in &g.members {
                let p = &procs[i];
                if p.born {
                    let e = born.entry(g.key.as_str()).or_default();
                    e.0 += 1.0;
                    *e.1.entry(p.name.trim_end_matches(".exe").to_string()).or_default() += 1.0;
                }
            }
        }
        for v in self.rate.values_mut() {
            *v *= 1.0 - a;
        }
        for v in self.names.values_mut() {
            v.values_mut().for_each(|x| *x *= 1.0 - a);
            v.retain(|_, x| *x > 0.01);
        }
        for (k, (n, names)) in born {
            *self.rate.entry(k.to_string()).or_default() += a * n / dt as f32;
            let m = self.names.entry(k.to_string()).or_default();
            for (nm, c) in names {
                *m.entry(nm).or_default() += a * c / dt as f32;
            }
        }
        self.rate.retain(|_, v| *v > 0.01);
        self.names.retain(|k, _| self.rate.contains_key(k));

        let total: f32 = self.rate.values().sum();
        // interrupts and DPC — as pseudo-process rows in procs, exited ones — in exited_cpu:
        // neither is taken for short-lived processes any more
        let seen: f32 = procs.iter().filter(|p| p.pid != 0).map(|p| p.cpu).sum::<f32>() + exited_cpu;
        let unseen = (sys.cpu - seen).max(0.0);
        // a sample catches only a small part of short-lived processes alive, so the rate is several times too low:
        // from 0.5 noticed starts per second the unseen CPU is theirs. The first 1 % is sampling error
        let share = (unseen - 1.0).max(0.0) * (total / 0.5).min(1.0);
        let mut given = 0.0;
        for g in groups.iter_mut() {
            let Some(&r) = self.rate.get(&g.key) else { continue };
            g.spawn_rate = r;
            if let Some(m) = self.names.get(&g.key) {
                let mut v: Vec<(&String, &f32)> = m.iter().collect();
                v.sort_by(|x, y| y.1.total_cmp(x.1));
                g.spawn_names = v.into_iter().take(4).map(|(n, _)| n.clone()).collect();
            }
            if total > 0.0 {
                g.short_cpu = share * r / total;
                g.cpu += g.short_cpu;
                given += g.short_cpu;
            }
        }
        sys.unseen_cpu = unseen - given;
        sys.spawn_rate = total;
    }
}
