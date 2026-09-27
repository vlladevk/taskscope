//! Понятные подписи процессов: вместо «java», «node», «cmd», «claude» — что именно запущено.
//!
//! - по командной строке: jar или главный класс Java, скрипт или пакет Node и Python, команда cmd,
//!   PowerShell и bash, COM-объект у dllhost;
//! - сессии Claude Code: название сессии (переменная окружения, которую задаёт приложение Claude,
//!   или последнее переименование в файле сессии) и папка проекта;
//! - заголовки окон и вкладки браузеров (UI Automation) — они меняются, поэтому по отдельному запросу.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Аргументы командной строки по правилам Windows (кавычки группируют, сами не входят).
pub fn split_args(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in cmd.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

fn file_name(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

fn stem(p: &str) -> &str {
    let f = file_name(p);
    f.rsplit_once('.').map_or(f, |(s, _)| s)
}

fn short(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>().trim_end())
    }
}

/// Команды, которые Claude Code запускает в оболочке, узнаются по его обёртке.
fn claude_code_shell(cmd: &str) -> bool {
    cmd.contains("claude/shell-snapshots") || cmd.contains(r"claude\shell-snapshots") || cmd.contains("$__claudeCodeScript")
}

/// Подпись по командной строке; `None` — ничего полезнее имени файла нет.
pub fn from_cmdline(exe: &str, cmd: &str) -> Option<String> {
    let exe = exe.to_ascii_lowercase();
    let a = split_args(cmd);
    let rest = a.get(1..).unwrap_or(&[]);
    match exe.as_str() {
        "java.exe" | "javaw.exe" => java(rest),
        "node.exe" | "bun.exe" | "deno.exe" => node(rest),
        "python.exe" | "pythonw.exe" | "py.exe" | "python3.exe" => python(rest),
        "cmd.exe" => {
            if claude_code_shell(cmd) {
                return Some("Команда Claude Code".into());
            }
            let i = rest.iter().position(|t| t.eq_ignore_ascii_case("/c") || t.eq_ignore_ascii_case("/k"))?;
            let prog = rest.get(i + 1)?;
            // «cmd /c "C:\…\java -jar …"» — внутри кавычек вся команда; у программы оставляем только имя.
            // Путь с пробелами («C:\Program Files\…\x.exe») — одна программа, а не несколько слов
            let low = prog.to_ascii_lowercase();
            let end = [".exe", ".bat", ".cmd", ".com", ".ps1"].iter().filter_map(|e| low.find(e).map(|i| i + e.len())).min();
            let mut words: Vec<String> = match end {
                Some(end) if prog[end..].is_empty() || prog[end..].starts_with(' ') => {
                    let mut w = vec![prog[..end].to_string()];
                    w.extend(split_args(&prog[end..]));
                    w
                }
                _ => split_args(prog),
            };
            words.extend(rest.get(i + 2..).unwrap_or(&[]).iter().cloned());
            let first = words.first().map(|w| stem(w).to_string()).unwrap_or_default();
            Some(format!("cmd: {}", short(&format!("{first} {}", words.get(1..).unwrap_or(&[]).join(" ")), 60)))
        }
        "powershell.exe" | "pwsh.exe" => {
            if claude_code_shell(cmd) {
                return Some("Команда Claude Code".into());
            }
            let next = |k: &str| rest.iter().position(|t| t.eq_ignore_ascii_case(k)).and_then(|i| rest.get(i + 1));
            if let Some(f) = next("-File").or_else(|| next("-f")) {
                return Some(format!("PowerShell: {}", file_name(f)));
            }
            if next("-EncodedCommand").or_else(|| next("-enc")).or_else(|| next("-e")).is_some() {
                return Some("PowerShell: закодированная команда".into());
            }
            next("-Command").or_else(|| next("-c")).map(|c| format!("PowerShell: {}", short(c, 50)))
        }
        "bash.exe" | "sh.exe" | "zsh.exe" => {
            if claude_code_shell(cmd) {
                return Some("Команда Claude Code".into());
            }
            let i = rest.iter().position(|t| t == "-c")?;
            rest.get(i + 1).map(|c| format!("{}: {}", stem(&exe), short(c, 50)))
        }
        "dllhost.exe" => {
            let id = rest.iter().find_map(|t| t.to_ascii_lowercase().strip_prefix("/processid:").map(|s| s.to_string()))?;
            com_name(&id).map(|n| format!("COM: {n}"))
        }
        "rundll32.exe" => rest.first().map(|t| format!("rundll32: {}", file_name(t.split(',').next().unwrap_or(t)))),
        "codex.exe" if rest.iter().any(|t| t == "app-server") => Some("Codex: сервер приложения".into()),
        _ => None,
    }
}

fn java(rest: &[String]) -> Option<String> {
    // значения этих ключей — не главный класс
    const WITH_VALUE: &[&str] = &["-cp", "-classpath", "--class-path", "-p", "--module-path", "--add-opens", "--add-exports", "--add-modules", "--add-reads", "-d"];
    let mut i = 0;
    let mut main = None;
    while i < rest.len() {
        let t = rest[i].as_str();
        if t == "-jar" {
            let jar = rest.get(i + 1)?;
            if jar.to_ascii_lowercase().contains("surefire") {
                return Some("Тесты Maven (surefire)".into());
            }
            return Some(format!("Java: {}", file_name(jar)));
        }
        if t == "-m" || t == "--module" {
            main = rest.get(i + 1).map(|m| m.rsplit('/').next().unwrap_or(m).to_string());
            break;
        }
        if WITH_VALUE.contains(&t) {
            i += 2;
            continue;
        }
        if t.starts_with('-') || t.starts_with('@') {
            i += 1;
            continue;
        }
        main = Some(t.to_string());
        break;
    }
    let m = main?;
    let known = [
        ("GradleDaemon", "Gradle (фоновый сборщик)"),
        ("GradleWorkerMain", "Gradle: рабочий процесс"),
        ("GradleWrapperMain", "Gradle"),
        ("KotlinCompileDaemon", "Kotlin: компилятор"),
        ("org.jetbrains.jps", "IntelliJ: сборка проекта"),
        ("com.intellij.rt", "IntelliJ: запуск"),
        ("plexus.classworlds", "Maven"),
        ("MavenWrapperMain", "Maven"),
        ("surefire", "Тесты Maven (surefire)"),
        ("catalina.startup", "Tomcat"),
        ("org.sonarsource", "SonarLint"),
        ("eclipse.jdt.ls", "Java: языковой сервер"),
        ("equinox.launcher", "Java: языковой сервер"),
    ];
    for (k, v) in known {
        if m.contains(k) {
            return Some(v.into());
        }
    }
    Some(format!("Java: {}", m.rsplit('.').next().unwrap_or(&m)))
}

fn node(rest: &[String]) -> Option<String> {
    let i = rest.iter().position(|t| !t.starts_with('-'))?;
    let script = rest[i].replace('/', "\\");
    let args = rest.get(i + 1..).unwrap_or(&[]);
    let arg1 = args.iter().find(|t| !t.starts_with('-')).map(String::as_str).unwrap_or("");
    let low = script.to_ascii_lowercase();
    if low.contains(r"@anthropic-ai\claude-code") {
        return Some("Claude Code".into());
    }
    // пакет — папка сразу после последнего node_modules (с @scope)
    if let Some(p) = low.rfind(r"node_modules\") {
        let tail = &script[p + 13..];
        let mut parts = tail.split('\\');
        let first = parts.next().unwrap_or("");
        let pkg = if first.starts_with('@') { format!("{first}/{}", parts.next().unwrap_or("")) } else { first.to_string() };
        return Some(match pkg.as_str() {
            "npm" => format!("npm {}", short(&args.join(" "), 40)),
            "typescript" if low.contains("tsserver") => "TypeScript (tsserver)".into(),
            _ if arg1.is_empty() => format!("Node: {pkg}"),
            _ => format!("Node: {pkg} {arg1}"),
        });
    }
    let f = file_name(&script);
    // index.js / main.js ничего не говорят — добавляем папку
    let generic = matches!(stem(f).to_ascii_lowercase().as_str(), "index" | "main" | "server" | "app" | "cli");
    let dir = Path::new(&script).parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()).unwrap_or("");
    Some(if generic && !dir.is_empty() { format!("Node: {dir}\\{f}") } else { format!("Node: {f}") })
}

fn python(rest: &[String]) -> Option<String> {
    let mut i = 0;
    while i < rest.len() {
        let t = rest[i].as_str();
        if t == "-m" {
            let m = rest.get(i + 1)?;
            let a = rest.get(i + 2).filter(|a| !a.starts_with('-')).map(|a| format!(" {a}")).unwrap_or_default();
            return Some(format!("Python: {m}{a}"));
        }
        if t == "-c" {
            return Some(format!("Python: {}", short(rest.get(i + 1)?, 40)));
        }
        if t == "-X" || t == "-W" {
            i += 2;
            continue;
        }
        if !t.starts_with('-') {
            let f = file_name(t);
            let a = if matches!(f, "manage.py" | "main.py" | "app.py") { rest.get(i + 1).map(|a| format!(" {a}")).unwrap_or_default() } else { String::new() };
            return Some(format!("Python: {f}{a}"));
        }
        i += 1;
    }
    None
}

/// Имя COM-сервера, который обслуживает dllhost (по AppID, иначе по CLSID).
fn com_name(id: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CLASSES_ROOT, RRF_RT_REG_SZ};
    let id = id.trim().trim_matches(|c| c == '{' || c == '}');
    for base in ["AppID", "CLSID"] {
        let key: Vec<u16> = format!("{base}\\{{{id}}}").encode_utf16().chain([0]).collect();
        let mut buf = vec![0u16; 512];
        let mut len = (buf.len() * 2) as u32;
        let rc = unsafe { RegGetValueW(HKEY_CLASSES_ROOT, key.as_ptr(), std::ptr::null(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) };
        if rc == 0 {
            let s = String::from_utf16_lossy(&buf[..(len as usize / 2).saturating_sub(1)]);
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Оболочка без команды (терминал в редакторе, в Windows Terminal, в приложении) — подпись по
/// папке, в которой она открыта: иначе это десяток одинаковых «Windows PowerShell».
pub fn shell_folder(pid: u32, create_time: i64, exe: &str, cmd: &str) -> Option<String> {
    let name = match exe.to_ascii_lowercase().as_str() {
        "powershell.exe" | "pwsh.exe" => "PowerShell",
        "cmd.exe" => "cmd",
        "bash.exe" => "bash",
        "nu.exe" => "nu",
        _ => return None,
    };
    // только без команды: с командой подпись уже есть
    if split_args(cmd).iter().skip(1).any(|a| !a.starts_with('-') && !a.starts_with('/')) {
        return None;
    }
    let env = crate::inspect::environment(pid, create_time).ok()?;
    let cwd = env.cwd.trim_end_matches('\\');
    (!cwd.is_empty()).then(|| format!("{name}: {}", project_of(cwd)))
}

// ───────────────────────────── Claude Code ─────────────────────────────

/// Процесс — Claude Code (а не окно приложения Claude и не его служебные процессы).
pub fn is_claude_code(exe: &str, path: Option<&str>, cmd: &str) -> bool {
    if cmd.contains(r"@anthropic-ai\claude-code") || cmd.contains("@anthropic-ai/claude-code") {
        return true;
    }
    exe.eq_ignore_ascii_case("claude.exe") && !cmd.contains("--type=") && !path.is_some_and(|p| p.contains(r"\WindowsApps\"))
}

/// «Claude Code: <название сессии>» или «Claude Code: <папка>».
pub fn claude_code(pid: u32, create_time: i64, cmd: &str) -> String {
    let env = crate::inspect::environment(pid, create_time).ok();
    let var = |k: &str| env.as_ref().and_then(|e| e.vars.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone()));
    // название, заданное при запуске; переименование позже записано в файле сессии — оно новее
    let mut title = var("CLAUDE_CODE_SESSION_NAME").filter(|s| !s.trim().is_empty());
    let args = split_args(cmd);
    let id = args.iter().enumerate().find_map(|(i, t)| {
        t.strip_prefix("--resume=")
            .or_else(|| t.strip_prefix("--session-id="))
            .map(str::to_string)
            .or_else(|| if t == "--resume" || t == "-r" || t == "--session-id" { args.get(i + 1).cloned() } else { None })
    });
    if let Some(id) = id.filter(|s| s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')) {
        let home = var("CLAUDE_CONFIG_DIR").map(PathBuf::from).or_else(|| var("USERPROFILE").map(|h| PathBuf::from(h).join(".claude")));
        if let Some(t) = home.and_then(|h| session_title(&h.join("projects"), &id)) {
            title = Some(t);
        }
    }
    if let Some(t) = title {
        return format!("Claude Code: {}", short(&t, 70));
    }
    match env.as_ref().map(|e| e.cwd.trim_end_matches('\\').to_string()) {
        Some(cwd) if !cwd.is_empty() => format!("Claude Code: {}", project_of(&cwd)),
        _ => "Claude Code".into(),
    }
}

/// «D:\code\my app» → «my app»; рабочее дерево «…\Repo\.claude\worktrees\name» → «Repo · name».
fn project_of(cwd: &str) -> String {
    let parts: Vec<&str> = cwd.split('\\').collect();
    if let Some(i) = parts.iter().position(|p| p.eq_ignore_ascii_case(".claude")) {
        if parts.get(i + 1).is_some_and(|w| w.eq_ignore_ascii_case("worktrees")) && i > 0 {
            if let Some(name) = parts.get(i + 2) {
                return format!("{} · {name}", parts[i - 1]);
            }
        }
    }
    parts.last().unwrap_or(&cwd).to_string()
}

/// Последнее название сессии из её файла (записи «custom-title»). Файл бывает в десятки МБ —
/// читаем только конец: переименование дописывается в него при каждом ходе.
fn session_title(projects: &Path, id: &str) -> Option<String> {
    let name = format!("{id}.jsonl");
    let file = std::fs::read_dir(projects).ok()?.flatten().map(|d| d.path().join(&name)).find(|p| p.is_file())?;
    let mut f = std::fs::File::open(file).ok()?;
    let len = f.metadata().ok()?.len();
    let from = len.saturating_sub(1 << 20);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::new();
    f.take(1 << 20).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    text.lines().rev().filter(|l| l.contains("\"custom-title\"")).find_map(|l| {
        let v: serde_json::Value = serde_json::from_str(l).ok()?;
        v.get("customTitle").and_then(|t| t.as_str()).filter(|t| !t.trim().is_empty()).map(str::to_string)
    })
}

// ───────────────────────────── окна ─────────────────────────────

/// Заголовки видимых главных окон по PID (свёрнутые тоже; скрытые и «спрятанные» системой — нет).
pub fn window_titles() -> HashMap<u32, Vec<String>> {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible, GW_OWNER};
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> BOOL {
        let out = &mut *(lp as *mut HashMap<u32, Vec<String>>);
        if IsWindowVisible(hwnd) == 0 || !GetWindow(hwnd, GW_OWNER).is_null() {
            return 1;
        }
        let mut cloaked = 0u32;
        if DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED as u32, (&mut cloaked as *mut u32).cast(), 4) == 0 && cloaked != 0 {
            return 1;
        }
        let n = GetWindowTextLengthW(hwnd);
        if n <= 0 {
            return 1;
        }
        let mut buf = vec![0u16; n as usize + 1];
        let got = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        let t = String::from_utf16_lossy(&buf[..got.max(0) as usize]);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != 0 && !t.trim().is_empty() {
            out.entry(pid).or_default().push(t);
        }
        1
    }
    let mut out: HashMap<u32, Vec<String>> = HashMap::new();
    unsafe { EnumWindows(Some(cb), &mut out as *mut _ as LPARAM) };
    out
}

// ───────────────────────────── вкладки браузера ─────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct Tab {
    pub title: String,
    /// память вкладки, как её показывает сам браузер (МБ); у выгруженной — сколько освобождено
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_mb: Option<f64>,
    /// выгружена браузером для экономии памяти
    pub sleeping: bool,
    pub audio: bool,
    /// номер окна браузера (0, 1, …)
    pub window: usize,
}

/// «… - Memory usage - 697 MB», «… - Inactive tab - 184 MB freed up», «… - Audio playing» —
/// браузер дописывает состояние к имени вкладки; отделяем его.
fn parse_tab(name: &str, window: usize) -> Tab {
    let mut parts: Vec<&str> = name.split(" - ").collect();
    let mut t = Tab { title: String::new(), mem_mb: None, sleeping: false, audio: false, window };
    // «697 MB», «184 MB freed up», «1,2 ГБ» → МБ
    let size = |s: &str| -> Option<f64> {
        let low = s.trim().to_lowercase();
        let (num, unit) = low.split_once(' ')?;
        let v: f64 = num.replace(',', ".").parse().ok()?;
        let unit = unit.split_whitespace().next()?;
        Some(match unit {
            "gb" | "гб" => v * 1024.0,
            "kb" | "кб" => v / 1024.0,
            "mb" | "мб" => v,
            _ => return None,
        })
    };
    while parts.len() > 1 {
        let last = parts[parts.len() - 1].trim();
        let low = last.to_lowercase();
        if let Some(mb) = size(last) {
            // размер — отдельной частью после «Memory usage» / «Inactive tab»
            t.mem_mb = Some(mb);
            if low.contains("freed") || low.contains("освобожд") {
                t.sleeping = true;
            }
        } else if low.contains("memory usage") || low.contains("памят") {
            // подпись к размеру; сам размер уже снят
        } else if low.starts_with("inactive tab") || low.contains("неактивн") {
            t.sleeping = true;
        } else if low.contains("audio playing") || low.contains("воспроизвод") {
            t.audio = true;
        } else if !(low == "muted" || low.contains("звук выключен") || low.contains("crashed") || low.contains("network error")) {
            break;
        }
        parts.pop();
    }
    t.title = parts.join(" - ");
    t
}

/// Открытые вкладки браузера на Chromium (Chrome, Edge, Brave, Opera, Vivaldi …) по PID его главного
/// процесса — через UI Automation, как их видят программы чтения с экрана. Около секунды на
/// десятки вкладок, поэтому только по запросу.
#[derive(Clone, Debug, Serialize)]
pub struct BrowserTabs {
    pub tabs: Vec<Tab>,
    /// заголовки окон браузера по номеру (`Tab::window`): у окна во весь экран полосы вкладок нет,
    /// и видна только открытая вкладка — из заголовка
    pub windows: Vec<String>,
}

pub fn browser_tabs(pid: u32) -> Result<BrowserTabs, String> {
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
    use windows::Win32::UI::Accessibility::{CUIAutomation, IUIAutomation, TreeScope_Descendants, UIA_ControlTypePropertyId, UIA_TabItemControlTypeId};

    let wins: Vec<isize> = {
        use windows_sys::Win32::Foundation::{BOOL, HWND as H, LPARAM};
        use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindow, GetWindowThreadProcessId, IsWindowVisible, GW_OWNER};
        struct Ctx {
            pid: u32,
            out: Vec<isize>,
        }
        unsafe extern "system" fn cb(hwnd: H, lp: LPARAM) -> BOOL {
            let c = &mut *(lp as *mut Ctx);
            let mut p = 0u32;
            GetWindowThreadProcessId(hwnd, &mut p);
            if p == c.pid && IsWindowVisible(hwnd) != 0 && GetWindow(hwnd, GW_OWNER).is_null() {
                c.out.push(hwnd as isize);
            }
            1
        }
        let mut c = Ctx { pid, out: Vec::new() };
        unsafe { EnumWindows(Some(cb), &mut c as *mut Ctx as LPARAM) };
        c.out
    };
    let windows: Vec<String> = wins
        .iter()
        .map(|&w| unsafe {
            use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextW;
            let mut buf = [0u16; 512];
            let n = GetWindowTextW(w as _, buf.as_mut_ptr(), buf.len() as i32);
            String::from_utf16_lossy(&buf[..n.max(0) as usize])
        })
        .collect();
    if wins.is_empty() {
        return Ok(BrowserTabs { tabs: Vec::new(), windows });
    }
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
        let r = (|| -> windows::core::Result<Vec<Tab>> {
            let ua: IUIAutomation = CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)?;
            let cond = ua.CreatePropertyCondition(UIA_ControlTypePropertyId, &VARIANT::from(UIA_TabItemControlTypeId.0))?;
            let mut out = Vec::new();
            for (wi, &w) in wins.iter().enumerate() {
                let Ok(el) = ua.ElementFromHandle(HWND(w as *mut _)) else { continue };
                let Ok(all) = el.FindAll(TreeScope_Descendants, &cond) else { continue };
                for i in 0..all.Length().unwrap_or(0) {
                    let Ok(t) = all.GetElement(i) else { continue };
                    // вкладки самого браузера: «Tab», «BraveTab», «EdgeTab»…; «TabbedPaneTab» и
                    // вкладки внутри веб-страниц — не они
                    let class = t.CurrentClassName().map(|s| s.to_string()).unwrap_or_default();
                    if !class.ends_with("Tab") || class == "TabbedPaneTab" {
                        continue;
                    }
                    let name = t.CurrentName().map(|s| s.to_string()).unwrap_or_default();
                    if !name.trim().is_empty() {
                        out.push(parse_tab(&name, wi));
                    }
                }
            }
            Ok(out)
        })();
        if init {
            CoUninitialize();
        }
        r.map(|tabs| BrowserTabs { tabs, windows }).map_err(|e| e.message().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args() {
        assert_eq!(split_args(r#""C:\a b\x.exe" -c "echo 1" z"#), vec![r"C:\a b\x.exe", "-c", "echo 1", "z"]);
    }

    #[test]
    fn cmdlines() {
        assert_eq!(from_cmdline("java.exe", r"java -Xmx1g -cp a.jar org.gradle.launcher.daemon.bootstrap.GradleDaemon 8.5").as_deref(), Some("Gradle (фоновый сборщик)"));
        assert_eq!(from_cmdline("java.exe", r"java -jar C:\Temp\surefirebooter123.jar x").as_deref(), Some("Тесты Maven (surefire)"));
        assert_eq!(from_cmdline("java.exe", r"java -cp x com.example.App").as_deref(), Some("Java: App"));
        assert_eq!(from_cmdline("node.exe", r#""C:\n\node.exe" "C:\p\node_modules\vite\bin\vite.js" dev"#).as_deref(), Some("Node: vite dev"));
        assert_eq!(from_cmdline("node.exe", r#"node "C:\n\node_modules\npm\bin\npm-cli.js" run dev"#).as_deref(), Some("npm run dev"));
        assert_eq!(from_cmdline("node.exe", r"node C:\proj\server\index.js").as_deref(), Some(r"Node: server\index.js"));
        assert_eq!(from_cmdline("python.exe", r"python -m http.server 8000").as_deref(), Some("Python: http.server 8000"));
        assert_eq!(from_cmdline("python.exe", r"python manage.py runserver").as_deref(), Some("Python: manage.py runserver"));
        assert_eq!(from_cmdline("bash.exe", r#"bash -c "source /c/Users/x/.claude/shell-snapshots/s.sh && ls""#).as_deref(), Some("Команда Claude Code"));
        assert_eq!(from_cmdline("cmd.exe", r#"cmd.exe /X /C "C:\jdkin\java -jar x.jar""#).as_deref(), Some("cmd: java -jar x.jar"));
        assert_eq!(from_cmdline("cmd.exe", r#""C:\WINDOWS\system32\cmd.exe" /C "C:\Program Files\AMD\CNext\AMDRSServ.exe""#).as_deref(), Some("cmd: AMDRSServ"));
        assert_eq!(project_of(r"C:\Users\dev\Projects\Demo\.claude\worktrees\brave-otter-1a2b3c"), "Demo · brave-otter-1a2b3c");
        assert_eq!(project_of(r"D:\code\my app"), "my app");
    }

    #[test]
    fn tabs() {
        let t = parse_tab("Sep 23, 2026 - God of War - YouTube - Audio playing - Memory usage - 697 MB", 0);
        assert_eq!(t.title, "Sep 23, 2026 - God of War - YouTube");
        assert_eq!(t.mem_mb, Some(697.0));
        assert!(t.audio && !t.sleeping);
        let t = parse_tab("YouTube - Inactive tab - 184 MB freed up", 1);
        assert_eq!(t.title, "YouTube");
        assert!(t.sleeping);
        assert_eq!(parse_tab("Commits · octocat/hello-world", 0).title, "Commits · octocat/hello-world");
    }
}
