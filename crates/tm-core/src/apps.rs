//! Группировка процессов в «приложения».
//!
//! Идём по цепочке предков от корня: пропускаем системные хосты (explorer, services, …),
//! затем оболочки (терминал, pwsh, bash, …). Первый процесс после них — корень приложения.
//! Так `vitest` под `bash` под `claude` под `pwsh` под `WindowsTerminal` попадает в приложение
//! Claude Code, а не в «Терминал» и не в «node».

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::info::InfoCache;
use crate::sampler::ProcStat;
use crate::tree::Tree;

const HOSTS: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "winlogon.exe",
    "explorer.exe", "userinit.exe", "svchost.exe", "sihost.exe", "system idle process",
    // лаунчеры: запущенная ими IDE или игра — отдельное приложение, а не часть лаунчера
    "jetbrains-toolbox.exe", "steam.exe", "steamwebhelper.exe", "upc.exe", "ubisoftconnect.exe",
    "epicgameslauncher.exe", "battle.net.exe", "galaxyclient.exe", "eadesktop.exe",
];
const SHELLS: &[&str] = &[
    "windowsterminal.exe", "openconsole.exe", "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash.exe", "sh.exe", "zsh.exe", "wsl.exe", "wslhost.exe", "git-bash.exe", "mintty.exe",
];
/// Ядро Windows — одна группа вместо десятка мелких.
const CORE: &[&str] = &[
    "system", "registry", "secure system", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe",
];

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Индекс процесса — корня приложения для процесса `i`.
pub fn app_root(procs: &[ProcStat], tree: &Tree, i: usize) -> usize {
    let mut chain = tree.ancestors(i);
    chain.push(i);
    let is = |list: &[&str], j: usize| list.contains(&lower(&procs[j].name).as_str());
    let Some(start) = chain.iter().position(|&j| !is(HOSTS, j)) else { return i }; // сам процесс — системный хост
    let rest = &chain[start..];
    rest.iter().copied().find(|&j| !is(SHELLS, j)).unwrap_or(rest[0])
}

/// Ключ группы приложения: имя исполняемого файла корня в нижнем регистре.
pub fn app_key(procs: &[ProcStat], root: usize) -> String {
    let n = lower(&procs[root].name);
    if CORE.contains(&n.as_str()) {
        "windows".into()
    } else {
        n
    }
}

/// Человеческое имя группы, если описание файла недоступно или бесполезно.
fn builtin_title(key: &str) -> Option<&'static str> {
    Some(match key {
        "windows" => "Windows (ядро и системные процессы)",
        "svchost.exe" => "Службы Windows",
        "explorer.exe" => "Проводник",
        "vmmemwsl" | "vmmem" => "Виртуальная машина WSL / Docker",
        _ => return None,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppStat {
    /// Стабильный ключ группы (имя exe корня, либо "windows").
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
    /// Индексы процессов во фрейме (для внутренних нужд, не сериализуются).
    #[serde(skip)]
    pub members: Vec<usize>,
}

/// Ключ приложения для каждого процесса фрейма.
pub fn keys(procs: &[ProcStat], tree: &Tree) -> Vec<String> {
    (0..procs.len()).map(|i| app_key(procs, app_root(procs, tree, i))).collect()
}

/// Сводка по приложениям. Idle-процесс (PID 0) не входит ни в одну группу.
pub fn group(procs: &[ProcStat], tree: &Tree, info: &mut InfoCache) -> Vec<AppStat> {
    let mut by_key: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<AppStat> = Vec::new();
    let mut root_depth: Vec<usize> = Vec::new();
    for i in 0..procs.len() {
        let p = &procs[i];
        if p.pid == 0 {
            continue;
        }
        let root = app_root(procs, tree, i);
        let key = app_key(procs, root);
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
                members: Vec::new(),
            });
            root_depth.push(usize::MAX);
            out.len() - 1
        });
        let g = &mut out[gi];
        // корнем группы считаем самый «старший» процесс (меньше предков)
        let depth = tree.ancestors(root).len();
        if depth < root_depth[gi] {
            root_depth[gi] = depth;
            g.root_pid = procs[root].pid;
        }
        g.count += 1;
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
