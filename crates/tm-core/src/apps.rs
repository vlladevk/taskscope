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
    // псевдопроцессы сборщика: обработка прерываний и DPC
    "interrupts", "dpcs",
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
    /// ЦП коротких процессов, запущенных приложением и не попавших в замеры (уже входит в `cpu`).
    #[serde(default)]
    pub short_cpu: f32,
    /// Сколько процессов в секунду приложение запускает (сглажено).
    #[serde(default)]
    pub spawn_rate: f32,
    /// Кого чаще всего запускает: «git», «grep», …
    #[serde(default)]
    pub spawn_names: Vec<String>,
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
    group_with(procs, tree, info, None)
}

/// Утилиты, которые скрипты запускают сотнями: осиротев (родитель уже завершился), они
/// остаются в приложении родителя, а не становятся отдельными «git» и «xargs».
const TOOLS: &[&str] = &[
    "git.exe", "grep.exe", "xargs.exe", "find.exe", "sed.exe", "awk.exe", "gawk.exe", "cat.exe", "head.exe",
    "tail.exe", "sort.exe", "uniq.exe", "wc.exe", "cut.exe", "tr.exe", "ls.exe", "rg.exe", "findstr.exe",
    "where.exe", "timeout.exe", "sleep.exe", "env.exe", "cygpath.exe", "uname.exe", "dirname.exe", "basename.exe",
];

/// Память о недавно виденных процессах: PID → приложение. Нужна сиротам, чей родитель
/// уже завершился: `xargs` из команды Claude Code остаётся в Claude Code, когда bash уже вышел.
#[derive(Default)]
pub struct Lineage {
    /// PID → (приложение, время создания, когда видели последний раз, мс)
    seen: HashMap<u32, (String, i64, u64)>,
    /// Унаследованное приложение закреплено за процессом на всю его жизнь
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
        // родитель создан раньше ребёнка — иначе PID уже занял кто-то другой
        let k = self.seen.get(&p.ppid).filter(|(_, ct, _)| *ct <= p.create_time)?.0.clone();
        self.sticky.insert(p.key(), k.clone());
        Some(k)
    }

    /// Запомнить приложения живых процессов; забыть тех, кого нет дольше 2 минут.
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

/// Как `group`, но сироты-утилиты наследуют приложение завершившегося родителя.
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
        // сирота: вершина цепочки без живого родителя — ищем, чьим был родитель
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
        // корнем группы считаем самый «старший» процесс (меньше предков)
        // унаследованные сироты корнем группы не становятся, пока в ней есть свои процессы
        let depth = if inherited.is_some() { usize::MAX - 1 } else { tree.ancestors(root).len() };
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

/// Короткие процессы: кто их запускает и сколько ЦП они съедают невидимо для замеров.
#[derive(Default)]
pub struct Spawns {
    /// приложение → запусков в секунду (сглажено, τ ≈ 8 с)
    rate: HashMap<String, f32>,
    /// приложение → имя запускаемого → частота
    names: HashMap<String, HashMap<String, f32>>,
}

impl Spawns {
    /// Учитывает родившихся за интервал и раздаёт невидимый ЦП (занятость машины минус сумма
    /// по процессам) приложениям-запускальщикам. Остаток — в `SystemStat::unseen_cpu`.
    /// `exited_cpu` — ЦП процессов, завершившихся за интервал (он известен точно и уже роздан их приложениям).
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
        // прерывания и DPC — строками-псевдопроцессами в procs, завершившиеся — в exited_cpu:
        // и то и другое больше не принимается за короткие процессы
        let seen: f32 = procs.iter().filter(|p| p.pid != 0).map(|p| p.cpu).sum::<f32>() + exited_cpu;
        let unseen = (sys.cpu - seen).max(0.0);
        // замер застаёт живыми лишь малую часть коротких процессов, так что частота занижена в разы:
        // от 0,5 замеченного запуска в секунду невидимое — их. Первый 1 % — погрешность замера
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
