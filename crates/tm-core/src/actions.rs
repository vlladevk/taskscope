//! Действия над процессами. Каждое действие проверяет время создания процесса,
//! чтобы не ударить по чужому процессу, получившему тот же PID.
//!
//! Порядок работы: `Guard` знает, что трогать нельзя; `plan` раскрывает цели
//! (дерево, приложение) и отсеивает защищённое; `execute` выполняет план.
//! Правила взяты из System Informer (actions.c): системный процесс — это имя
//! **и** путь в System32 либо флаг критичности от Windows; защищённый корень
//! закрывает всё своё дерево; перезапуск создаёт новый процесс от имени старого.

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetPriorityClass, IsProcessCritical, SetPriorityClass, TerminateProcess, WaitForSingleObject,
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS,
    NORMAL_PRIORITY_CLASS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, REALTIME_PRIORITY_CLASS,
};

use crate::handle::ProcHandle;
use crate::sampler::{ProcKey, ProcStat};
use crate::settings::Settings;
use crate::tree::Tree;

/// Псевдопроцессы ядра — без файла на диске.
const KERNEL: &[&str] = &["system idle process", "system", "registry", "secure system", "memory compression", "interrupts", "dpcs"];
/// Процессы, завершение которых роняет систему или сессию, — если это настоящие файлы из System32.
const CRITICAL_EXE: &[&str] = &["smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe", "winlogon.exe"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Kill,
    Suspend,
    Resume,
    Priority,
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    Realtime,
}

impl Priority {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "idle" | "low" => Self::Idle,
            "below" | "belownormal" => Self::BelowNormal,
            "normal" => Self::Normal,
            "above" | "abovenormal" => Self::AboveNormal,
            "high" => Self::High,
            "realtime" => Self::Realtime,
            _ => return None,
        })
    }

    fn class(self) -> u32 {
        match self {
            Self::Idle => IDLE_PRIORITY_CLASS,
            Self::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
            Self::Normal => NORMAL_PRIORITY_CLASS,
            Self::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
            Self::High => HIGH_PRIORITY_CLASS,
            Self::Realtime => REALTIME_PRIORITY_CLASS,
        }
    }

    fn from_class(c: u32) -> Option<Self> {
        [Self::Idle, Self::BelowNormal, Self::Normal, Self::AboveNormal, Self::High, Self::Realtime]
            .into_iter()
            .find(|p| p.class() == c)
    }
}

/// Результат действия над одним процессом.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Outcome {
    pub pid: u32,
    pub create_time: i64,
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Пояснение к успеху: «закрыто окно», «уже завершился», предупреждение в dry-run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Не выполнено, но можно повторить принудительно (`force`): окно не закрылось, нужно подтверждение.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub can_force: bool,
    /// PID нового процесса после перезапуска.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pid: Option<u32>,
    /// У процесса есть окно: при завершении его сначала попросят закрыться (для окна подтверждения).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub window: bool,
}

impl Outcome {
    fn of(p: &ProcStat) -> Self {
        Self { pid: p.pid, create_time: p.create_time, name: p.name.clone(), ..Default::default() }
    }
    fn result(p: &ProcStat, r: io::Result<()>) -> Self {
        let mut o = Self::of(p);
        match r {
            Ok(()) => o.ok = true,
            Err(e) => o.error = Some(e.to_string()),
        }
        o
    }
    fn refused(p: &ProcStat, why: String) -> Self {
        Self { error: Some(why), ..Self::of(p) }
    }
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

fn denied(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.to_string())
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "процесс уже завершился")
}

/// Путь к файлу процесса и флаг критичности от Windows (одним открытием).
fn probe(p: &ProcStat) -> (Option<String>, bool) {
    match ProcHandle::open(p.pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(p.create_time)) {
        Ok(h) => (crate::info::image_path(&h), is_critical(&h)),
        // не открыть (защищённый процесс, нет прав) — путь всё равно узнаём по PID (класс 88)
        Err(_) => (crate::info::path_by_pid(p.pid), false),
    }
}

fn is_critical(h: &ProcHandle) -> bool {
    let mut crit: BOOL = 0;
    unsafe { IsProcessCritical(h.raw(), &mut crit) != 0 && crit != 0 }
}

/// Папка System32 — у Windows, а не из переменной окружения, которую может подменить пользователь.
fn system32() -> String {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if n > 0 && n < buf.len() { String::from_utf16_lossy(&buf[..n]) } else { r"C:\Windows\System32".into() };
    lower(&format!(r"{}\", dir.trim_end_matches('\\')))
}

/// Что трогать нельзя: ядро и критические процессы Windows, сам tm с его окном (WebView),
/// процессы из списка защищённых в настройках.
pub struct Guard {
    own: HashSet<ProcKey>,
    settings: Settings,
    system32: String,
}

impl Guard {
    /// `procs`/`tree` нужны, чтобы найти потомков tm (WebView2 окна приложения).
    pub fn new(procs: &[ProcStat], tree: &Tree) -> Self {
        Self::with_settings(procs, tree, Settings::load())
    }

    pub fn with_settings(procs: &[ProcStat], tree: &Tree, settings: Settings) -> Self {
        let me = unsafe { GetCurrentProcessId() };
        // наше приложение (tm-app.exe из той же папки) — даже если действие делает CLI или MCP
        let my_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| lower(&d.to_string_lossy())));
        let is_our_app = |p: &ProcStat| {
            lower(&p.name) == "tm-app.exe"
                && probe(p).0.and_then(|x| std::path::Path::new(&x).parent().map(|d| lower(&d.to_string_lossy()))) == my_dir
        };
        let mut own = HashSet::new();
        for i in (0..procs.len()).filter(|&i| procs[i].pid == me || is_our_app(&procs[i])) {
            own.insert(procs[i].key());
            own.extend(tree.descendants(i).into_iter().map(|j| procs[j].key()));
        }
        Self { own, settings, system32: system32() }
    }

    /// Почему процесс нельзя трогать никаким действием (None — можно).
    pub fn reason(&self, p: &ProcStat) -> Option<String> {
        self.reason_for(p, None)
    }

    /// Как `reason`, но с учётом действия: «возобновить» не мешает список защищённых
    /// пользователем — иначе приостановленный, а потом защищённый процесс остался бы замороженным.
    pub fn reason_for(&self, p: &ProcStat, action: Option<Action>) -> Option<String> {
        let n = lower(&p.name);
        if p.pid == 0 || p.pid == 4 || crate::sampler::is_pseudo(p.pid) || KERNEL.contains(&n.as_str()) {
            return Some("часть ядра Windows".into());
        }
        if p.pid == unsafe { GetCurrentProcessId() } {
            return Some("это сам диспетчер задач".into());
        }
        if self.own.contains(&p.key()) {
            return Some("процесс самого диспетчера задач (его окно или WebView)".into());
        }
        let (path, critical) = probe(p);
        if critical {
            return Some("Windows помечает процесс как критический — его завершение приведёт к сбою системы".into());
        }
        if CRITICAL_EXE.contains(&n.as_str()) {
            // настоящий системный файл — или путь недоступен (так ведут себя именно защищённые процессы)
            let sys = path.as_deref().map_or(true, |x| lower(x).starts_with(&self.system32));
            if sys {
                return Some("критический системный процесс — его завершение приведёт к сбою Windows".into());
            }
        }
        if action != Some(Action::Resume) && self.settings.is_protected(&p.name, path.as_deref()) {
            return Some("защищён в настройках диспетчера".into());
        }
        None
    }

    /// Предупреждение: действие допустимо, но заметно ударит по сеансу (нужно подтверждение).
    pub fn warning(&self, p: &ProcStat, action: Action) -> Option<&'static str> {
        let n = lower(&p.name);
        match (action, n.as_str()) {
            (Action::Suspend, "dwm.exe") => Some("экран перестанет обновляться, пока процесс не возобновят"),
            (Action::Suspend, "explorer.exe") => Some("панель задач, рабочий стол и окна Проводника перестанут отвечать"),
            (Action::Suspend, "logonui.exe") => Some("экран входа в систему перестанет отвечать"),
            (Action::Suspend, "ctfmon.exe" | "textinputhost.exe") => Some("перестанет работать ввод с клавиатуры в части программ"),
            (Action::Suspend, "sihost.exe") => Some("меню «Пуск» и уведомления перестанут отвечать"),
            (Action::Kill | Action::Restart, "dwm.exe") => Some("экран погаснет на пару секунд, Windows перезапустит процесс"),
            (Action::Kill, "explorer.exe") => Some("панель задач и рабочий стол исчезнут до перезапуска Проводника"),
            (Action::Kill | Action::Restart, "logonui.exe") => Some("экран входа в систему закроется"),
            _ => None,
        }
    }
}

/// Что именно затрагивает действие.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Только указанные процессы.
    One,
    /// Вместе со всеми потомками.
    Tree,
    /// Всё приложение, к которому относится процесс.
    App,
}

/// Раскрытые цели: что делать (в безопасном порядке), от чего отказаться и почему.
#[derive(Default)]
pub struct Plan {
    /// Индексы процессов: сначала самые глубокие потомки, корень последним.
    pub order: Vec<usize>,
    pub refused: Vec<(usize, String)>,
    /// Процессы из `order`, для которых нужно подтверждение (`force`).
    pub warnings: HashMap<usize, &'static str>,
}

/// Группы, которые нельзя задевать групповыми действиями (`--app`, `--all`): это не одно приложение,
/// а десятки независимых служб и частей Windows.
fn system_group(key: &str) -> Option<&'static str> {
    match key {
        "svchost.exe" => Some("«Службы Windows» — это десятки независимых служб; действуйте по PID конкретного процесса"),
        "windows" => Some("это ядро и системные процессы Windows; действуйте по PID конкретного процесса"),
        _ => None,
    }
}

/// Раскрывает цели по `scope` и проверяет каждую.
/// Защищённый процесс закрывает всё своё поддерево. Групповое действие (`scope == App` или
/// несколько корней) не трогает системные группы — кроме «возобновить», оно безвредно.
pub fn plan(procs: &[ProcStat], tree: &Tree, roots: &[usize], scope: Scope, action: Action, guard: &Guard) -> Plan {
    let bulk = scope == Scope::App || roots.len() > 1;
    let keys = bulk.then(|| crate::apps::keys(procs, tree));
    let mut seen = HashSet::new();
    let mut take = Vec::new();
    let mut plan = Plan::default();
    // перезапуск — только одного процесса, как в System Informer: дочерние процессы
    // (рендеры браузера и т.п.) с прежней командной строкой запустились бы сломанными
    if action == Action::Restart && (scope != Scope::One || roots.len() > 1) {
        for &root in roots {
            plan.refused.push((root, "перезапустить можно только один процесс — без дочерних и не всё приложение".into()));
        }
        return plan;
    }
    for &root in roots {
        let members: Vec<usize> = match (scope, &keys) {
            (Scope::App, Some(keys)) => (0..procs.len()).filter(|&j| keys[j] == keys[root] && procs[j].pid != 0).collect(),
            (Scope::Tree, _) => std::iter::once(root).chain(tree.descendants(root)).collect(),
            _ => vec![root],
        };
        let group = keys.as_ref().filter(|_| action != Action::Resume).and_then(|k| system_group(&k[root]));
        for j in members {
            if !seen.insert(j) {
                continue;
            }
            match group {
                Some(why) => plan.refused.push((j, why.to_string())),
                None => take.push(j),
            }
        }
    }
    // защищённый процесс закрывает всё своё поддерево
    let mut blocked: HashMap<usize, String> = HashMap::new();
    for &i in &take {
        if let Some(why) = guard.reason_for(&procs[i], Some(action)) {
            blocked.insert(i, why);
        }
    }
    let mut ok = Vec::new();
    for i in take {
        if let Some(why) = blocked.get(&i) {
            plan.refused.push((i, why.clone()));
        } else if let Some(why) = (action == Action::Restart).then(|| restart_blocker(&procs[i], procs, tree)).flatten() {
            plan.refused.push((i, why));
        } else if let Some(&a) = tree.ancestors(i).iter().find(|a| blocked.contains_key(a)) {
            plan.refused.push((i, format!("входит в дерево защищённого процесса {} ({})", procs[a].name, procs[a].pid)));
        } else {
            ok.push(i);
        }
    }
    for &i in &ok {
        if let Some(w) = guard.warning(&procs[i], action) {
            plan.warnings.insert(i, w);
        }
    }
    plan.order = deepest_first(tree, &ok);
    plan
}

impl Plan {
    /// Итог без выполнения (dry-run): что будет сделано, что нет и почему.
    pub fn preview(&self, procs: &[ProcStat], action: Action) -> Vec<Outcome> {
        let wins = if action == Action::Kill { with_windows(procs, &self.order) } else { HashSet::new() };
        let mut v: Vec<Outcome> = self
            .order
            .iter()
            .map(|&i| Outcome {
                ok: true,
                note: self.warnings.get(&i).map(|w| format!("внимание: {w}")),
                window: wins.contains(&procs[i].pid),
                ..Outcome::of(&procs[i])
            })
            .collect();
        v.extend(self.refused.iter().map(|(i, why)| Outcome::refused(&procs[*i], why.clone())));
        v
    }
}

/// Параметры выполнения.
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    pub priority: Option<Priority>,
    /// Принудительно: без вежливого закрытия окон и без подтверждения предупреждений.
    pub force: bool,
    /// Человек видел предупреждения (в окне подтверждения) и согласился.
    pub confirmed: bool,
    /// Сколько ждать, пока программа закроет окно сама.
    pub close_wait: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Self { priority: None, force: false, confirmed: false, close_wait: Duration::from_secs(5) }
    }
}

/// Выполняет план. Отказы и неподтверждённые предупреждения попадают в результат как неуспех.
pub fn execute(procs: &[ProcStat], tree: &Tree, plan: &Plan, action: Action, opts: Opts) -> Vec<Outcome> {
    let mut out = Vec::new();
    let mut todo = Vec::new();
    for &i in &plan.order {
        match plan.warnings.get(&i) {
            Some(w) if !opts.force && !opts.confirmed => out.push(Outcome { can_force: true, ..Outcome::refused(&procs[i], format!("нужно подтверждение: {w}")) }),
            _ => todo.push(i),
        }
    }
    match action {
        Action::Kill => out.extend(kill_many(procs, tree, &todo, opts)),
        _ => out.extend(todo.iter().map(|&i| {
            let p = &procs[i];
            match action {
                Action::Suspend => Outcome::result(p, suspend(p)),
                Action::Resume => Outcome::result(p, resume(p)),
                Action::Priority => Outcome::result(p, set_priority(p, opts.priority.unwrap_or(Priority::Normal))),
                Action::Restart => match restart(p, procs, tree) {
                    Ok(pid) => Outcome { ok: true, new_pid: Some(pid), ..Outcome::of(p) },
                    Err(e) => Outcome::refused(p, e.to_string()),
                },
                Action::Kill => unreachable!(),
            }
        })),
    }
    out.extend(plan.refused.iter().map(|(i, why)| Outcome::refused(&procs[*i], why.clone())));
    out
}

fn open(p: &ProcStat, access: u32) -> io::Result<ProcHandle> {
    let h = ProcHandle::open(p.pid, access | PROCESS_QUERY_LIMITED_INFORMATION, Some(p.create_time)).map_err(|e| match e.raw_os_error() {
        Some(5) => denied("нет доступа — нужен запуск от имени администратора"),
        Some(87) => gone(),
        _ if e.kind() == io::ErrorKind::NotFound => gone(),
        _ => e,
    })?;
    // последняя проверка перед ударом: флаг мог появиться уже после планирования
    if is_critical(&h) {
        return Err(denied("Windows помечает процесс как критический — его завершение приведёт к сбою"));
    }
    Ok(h)
}

// ───────────────────────────── завершение ─────────────────────────────

/// Видимые окна верхнего уровня без владельца (главные окна программ) по PID.
fn main_windows(pids: &HashSet<u32>) -> HashMap<u32, Vec<HWND>> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindow, GetWindowThreadProcessId, IsWindowVisible, GW_OWNER};
    struct Ctx<'a> {
        pids: &'a HashSet<u32>,
        out: HashMap<u32, Vec<HWND>>,
    }
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
        let ctx = &mut *(lp as *mut Ctx);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if ctx.pids.contains(&pid) && IsWindowVisible(hwnd) != 0 && GetWindow(hwnd, GW_OWNER).is_null() {
            ctx.out.entry(pid).or_default().push(hwnd);
        }
        1
    }
    let mut ctx = Ctx { pids, out: HashMap::new() };
    unsafe { EnumWindows(Some(cb), &mut ctx as *mut Ctx as LPARAM) };
    ctx.out
}

/// PID процесса оболочки (окно рабочего стола).
fn shell_pid() -> Option<u32> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
    let w = unsafe { GetShellWindow() };
    if w.is_null() {
        return None;
    }
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(w, &mut pid) };
    (pid != 0).then_some(pid)
}

/// PID процессов из списка, у которых есть главные окна (их сначала просят закрыться).
pub fn with_windows(procs: &[ProcStat], order: &[usize]) -> HashSet<u32> {
    let shell = shell_pid();
    let pids: HashSet<u32> = order.iter().map(|&i| procs[i].pid).filter(|&pid| Some(pid) != shell).collect();
    main_windows(&pids).into_keys().collect()
}

/// Ждёт завершения процесса не дольше `until`. true — процесс завершился.
fn wait_exit(h: &ProcHandle, until: Instant) -> bool {
    let ms = until.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128) as u32;
    unsafe { WaitForSingleObject(h.raw(), ms) == WAIT_OBJECT_0 }
}

fn terminate(p: &ProcStat) -> io::Result<()> {
    let h = open(p, PROCESS_TERMINATE | PROCESS_SYNCHRONIZE)?;
    if unsafe { TerminateProcess(h.raw(), 1) } == 0 {
        let e = io::Error::last_os_error();
        // уже завершается или завершился (например, вслед за закрытым родителем): Windows
        // отвечает «нет доступа», но цель достигнута
        if unsafe { WaitForSingleObject(h.raw(), 0) } == WAIT_OBJECT_0 {
            return Err(gone());
        }
        return Err(e);
    }
    Ok(())
}

pub fn kill(p: &ProcStat) -> io::Result<()> {
    terminate(p)
}

/// Завершение группы.
/// 1. Программам с окнами — WM_CLOSE (как «Снять задачу»): они сохраняют данные и закрываются сами.
///    Кто не закрылся за `close_wait` (например, спрашивает о сохранении), не трогаем вместе с потомками.
/// 2. Остальных, если их несколько, сначала замораживаем, потом завершаем — так родитель не успевает
///    перезапустить убитых детей; тех, кого завершить не удалось, размораживаем обратно.
fn kill_many(procs: &[ProcStat], tree: &Tree, order: &[usize], opts: Opts) -> Vec<Outcome> {
    let mut out = Vec::new();
    let mut rest: Vec<usize> = order.to_vec();
    if !opts.force {
        use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};
        // оболочке (explorer с рабочим столом и панелью задач) WM_CLOSE не посылаем: закрыть окно
        // рабочего стола — это Alt+F4 на рабочем столе, то есть окно «Завершение работы Windows».
        // System Informer тоже завершает оболочку отдельно
        let shell = shell_pid();
        let pids: HashSet<u32> = order.iter().map(|&i| procs[i].pid).filter(|&pid| Some(pid) != shell).collect();
        let wins = main_windows(&pids);
        let mut asked = Vec::new();
        for &i in order {
            let Some(ws) = wins.get(&procs[i].pid) else { continue };
            // дескриптор до WM_CLOSE: иначе не отличить «закрылся» от «PID занят другим»
            let Ok(h) = open(&procs[i], PROCESS_SYNCHRONIZE) else { continue };
            // окну с более высоким уровнем целостности сообщение не дойдёт (UIPI) — тогда принудительно
            let sent = ws.iter().filter(|&&w| unsafe { PostMessageW(w, WM_CLOSE, 0, 0) } != 0).count();
            if sent > 0 {
                asked.push((i, h));
            }
        }
        if !asked.is_empty() {
            let until = Instant::now() + opts.close_wait;
            let mut stuck = Vec::new();
            for (i, h) in &asked {
                if wait_exit(h, until) {
                    out.push(Outcome { ok: true, note: Some("закрыт через окно".into()), ..Outcome::of(&procs[*i]) });
                } else {
                    stuck.push(*i);
                    out.push(Outcome {
                        can_force: true,
                        ..Outcome::refused(&procs[*i], format!("не закрылся за {} с — возможно, спрашивает о сохранении", opts.close_wait.as_secs()))
                    });
                }
            }
            let asked_set: HashSet<usize> = asked.iter().map(|(i, _)| *i).collect();
            let held: HashMap<usize, usize> = stuck.iter().flat_map(|&s| tree.descendants(s).into_iter().map(move |d| (d, s))).collect();
            rest.retain(|i| !asked_set.contains(i));
            rest.retain(|i| match held.get(i) {
                Some(&s) => {
                    out.push(Outcome { can_force: true, ..Outcome::refused(&procs[*i], format!("ждёт закрытия {}", procs[s].name)) });
                    false
                }
                None => true,
            });
        }
    }
    let frozen: Vec<(usize, bool)> = if rest.len() > 1 { rest.iter().map(|&i| (i, suspend(&procs[i]).is_ok())).collect() } else { Vec::new() };
    for &i in &rest {
        let p = &procs[i];
        match terminate(p) {
            Ok(()) => out.push(Outcome { ok: true, ..Outcome::of(p) }),
            // цель достигнута: процесс закрылся сам (например, вместе с закрытым родителем)
            Err(e) if e.kind() == io::ErrorKind::NotFound => out.push(Outcome { ok: true, note: Some("уже завершился".into()), ..Outcome::of(p) }),
            Err(e) => {
                if frozen.iter().any(|&(j, f)| j == i && f) {
                    let _ = resume(p);
                }
                out.push(Outcome::refused(p, e.to_string()));
            }
        }
    }
    out
}

// ───────────────────────────── перезапуск ─────────────────────────────

/// Почему процесс нельзя перезапустить «как был» (System Informer отказывает в тех же случаях).
/// Проверяется ещё при планировании, чтобы dry-run показал причину.
pub fn restart_blocker(p: &ProcStat, procs: &[ProcStat], tree: &Tree) -> Option<String> {
    let idx = procs.iter().position(|x| x.key() == p.key());
    let parent = idx.and_then(|i| tree.parent[i]).map(|j| lower(&procs[j].name));
    if p.session == 0 || parent.as_deref() == Some("services.exe") {
        return Some("это служба Windows — её перезапускает диспетчер служб, а не процесс".into());
    }
    let h = match open(p, 0) {
        Ok(h) => h,
        Err(e) => return Some(e.to_string()),
    };
    let Some(path) = crate::info::image_path(&h) else { return Some("не удалось узнать путь к программе".into()) };
    if !std::path::Path::new(&path).is_file() {
        return Some(format!("файла программы больше нет: {path}"));
    }
    let lp = lower(&path);
    let packaged = lp.contains(r"\windowsapps\") || lp.contains(r"\systemapps\") || {
        use windows_sys::Win32::Storage::Packaging::Appx::GetPackageFullName;
        let mut len = 0u32;
        // ERROR_INSUFFICIENT_BUFFER (122) — у процесса есть пакет
        unsafe { GetPackageFullName(h.raw(), &mut len, std::ptr::null_mut()) == 122 }
    };
    if packaged {
        return Some("приложение из Microsoft Store (пакет) — запускается только через свою оболочку".into());
    }
    match (crate::system::process_user_sid(h.raw()), crate::system::current_user_sid()) {
        (Some(a), Some(b)) if a == b => None,
        (Some(_), _) => Some("процесс другого пользователя — перезапуск шёл бы с чужими правами".into()),
        _ => Some("не удалось узнать владельца процесса".into()),
    }
}

/// Перезапуск как в System Informer (PhUiRestartProcess): новый процесс создаётся
/// **приостановленным** с тем же файлом, командной строкой, папкой и окружением,
/// а родителем ему назначается старый процесс — от него наследуются права (маркер),
/// задание (job), приоритет. Только после успешного создания старый завершается,
/// и новый размораживается. Если что-то не так — старый остаётся работать.
/// Возвращает PID нового процесса.
fn restart(p: &ProcStat, procs: &[ProcStat], tree: &Tree) -> io::Result<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
        CREATE_DEFAULT_ERROR_MODE, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
        PROCESS_CREATE_PROCESS, PROCESS_INFORMATION, PROCESS_VM_READ, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTF_USESHOWWINDOW,
        STARTUPINFOEXW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    if let Some(why) = restart_blocker(p, procs, tree) {
        return Err(denied(&why));
    }
    let old = open(p, PROCESS_CREATE_PROCESS | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_VM_READ)?;
    let path = crate::info::image_path(&old).ok_or_else(|| denied("не удалось узнать путь к программе"))?;
    let cmdline = crate::nt::command_line(old.raw()).filter(|c| !c.trim().is_empty()).unwrap_or_else(|| format!("\"{path}\""));
    let launch = crate::nt::launch_params(old.raw()).map_err(|e| io::Error::other(format!("не удалось прочитать папку и окружение процесса: {e}")))?;

    // список атрибутов с одним элементом — родитель
    let mut size = 0usize;
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut attr_buf = vec![0u64; size.div_ceil(8)];
    let attrs = attr_buf.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attrs, 1, 0, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let parent = old.raw();
    let set = unsafe {
        UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize, (&parent as *const windows_sys::Win32::Foundation::HANDLE).cast(), std::mem::size_of_val(&parent), std::ptr::null_mut(), std::ptr::null())
    };
    if set == 0 {
        let e = io::Error::last_os_error();
        unsafe { DeleteProcThreadAttributeList(attrs) };
        return Err(e);
    }
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_SHOWNORMAL as u16;
    si.lpAttributeList = attrs;
    let app = crate::system::wide(&path);
    let mut cmd = crate::system::wide(&cmdline);
    // папку передаём как есть: «C:\» без слэша стала бы «текущей папкой диска C» самого tm
    let cwd = crate::system::wide(&launch.cwd);
    let cwd_ptr = if launch.cwd.is_empty() || !std::path::Path::new(&launch.cwd).is_dir() { std::ptr::null() } else { cwd.as_ptr() };
    let env_ptr = if launch.env.is_empty() { std::ptr::null() } else { launch.env.as_ptr().cast() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE,
            env_ptr,
            cwd_ptr,
            &si.StartupInfo,
            &mut pi,
        )
    };
    let err = io::Error::last_os_error();
    unsafe { DeleteProcThreadAttributeList(attrs) };
    if created == 0 {
        return Err(io::Error::new(err.kind(), format!("не удалось создать новый процесс: {err}")));
    }
    // новый готов — завершаем старый и ждём, чтобы новый не упёрся в «уже запущено»
    if unsafe { TerminateProcess(old.raw(), 1) } == 0 {
        let e = io::Error::last_os_error();
        unsafe {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        return Err(io::Error::new(e.kind(), format!("не удалось завершить старый процесс: {e}")));
    }
    // старый уже завершается; если он не успел за 5 с (завис в драйвере), новый всё равно
    // запускаем — иначе программа пропала бы совсем
    let _ = wait_exit(&old, Instant::now() + Duration::from_secs(5));
    let resumed = unsafe { ResumeThread(pi.hThread) } != u32::MAX;
    if !resumed {
        unsafe { TerminateProcess(pi.hProcess, 1) };
    }
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if !resumed {
        return Err(io::Error::other("новый процесс создан, но не запустился — старый уже завершён"));
    }
    Ok(pi.dwProcessId)
}

// ───────────────────────────── остальное ─────────────────────────────

pub fn suspend(p: &ProcStat) -> io::Result<()> {
    crate::nt::suspend(open(p, PROCESS_SUSPEND_RESUME)?.raw())
}

pub fn resume(p: &ProcStat) -> io::Result<()> {
    crate::nt::resume(open(p, PROCESS_SUSPEND_RESUME)?.raw())
}

pub fn set_priority(p: &ProcStat, prio: Priority) -> io::Result<()> {
    if prio == Priority::Realtime {
        return Err(denied("приоритет «реального времени» может подвесить систему — не поддерживается"));
    }
    let h = open(p, PROCESS_SET_INFORMATION)?;
    if unsafe { SetPriorityClass(h.raw(), prio.class()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn get_priority(p: &ProcStat) -> Option<Priority> {
    let h = ProcHandle::open(p.pid, PROCESS_QUERY_LIMITED_INFORMATION, Some(p.create_time)).ok()?;
    Priority::from_class(unsafe { GetPriorityClass(h.raw()) })
}

/// Порядок обработки группы: сначала самые глубокие потомки, корень последним —
/// так родитель не успевает перезапустить убитых детей.
pub fn deepest_first(tree: &Tree, set: &[usize]) -> Vec<usize> {
    let mut v: Vec<(usize, usize)> = set.iter().map(|&i| (tree.ancestors(i).len(), i)).collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v.into_iter().map(|(_, i)| i).collect()
}
