//! The single entry point to all features: the app window, the CLI (through the pipe),
//! MCP and the HTTP development mode all call the same `Service::call(method, params)`.
//!
//! Methods that change something in the system (`act`, `reveal`, `web`) are marked `is_mutating`:
//! the pipe does not let them through — the client performs actions itself, with its own rights.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::actions::{self, Action, Outcome, Priority};
use crate::engine::{Engine, Snapshot};
use crate::history::{Metric, Query};
use crate::icons::IconCache;
use crate::sampler::norm_key;
use crate::{InfoCache, ProcKey, Sampler, Tree};

pub struct Service {
    pub engine: Engine,
    icons: IconCache,
    info: std::sync::Mutex<InfoCache>,
    /// what browsers report about their processes (the browser task manager): (PID, creation time) → tasks
    btasks: std::sync::Mutex<(Option<std::time::Instant>, bool, std::collections::HashMap<ProcKey, Vec<String>>)>,
    docker: crate::docker::DockerWatch,
}

pub fn is_mutating(method: &str) -> bool {
    matches!(method, "act" | "reveal" | "web" | "docker_act" | "settings_set" | "service_act")
}

/// Methods not executed through the pipe: actions, and also reading other processes
/// from the inside (environment, handles, files they read and write), file signatures and log writes. The engine may run
/// as administrator, while the pipe is open to regular processes of the same user too — otherwise they
/// would read environments and files with administrator rights. The client (tm) does this itself.
pub fn is_local_only(method: &str) -> bool {
    is_mutating(method) || matches!(method, "inspect" | "signature" | "log" | "disk_files")
}

fn arg<T: for<'de> Deserialize<'de>>(params: &Value) -> Result<T, String> {
    serde_json::from_value(params.clone()).map_err(|e| format!("invalid parameters: {e}"))
}

fn snapshot_json(s: &Snapshot) -> Value {
    json!({
        "seq": s.seq,
        "frame": &*s.frame,
        "apps": &*s.apps,
        "nets": &*s.nets,
        "gpus": &*s.gpus,
        "net_per_process": s.net_per_process,
        "mem_detail": &s.mem_detail,
        "issues": &*s.issues,
        "pool_alerts": &*s.pool_alerts,
    })
}

fn fmt_mem(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else {
        format!("{} MB", b >> 20)
    }
}

impl Service {
    pub fn new(engine: Engine) -> Self {
        Self { engine, icons: IconCache::default(), info: Default::default(), btasks: Default::default(), docker: crate::docker::DockerWatch::start() }
    }

    fn wait_first(&self) -> Result<Snapshot, String> {
        self.engine.wait_newer(0, self.engine.interval() * 3).ok_or_else(|| "no data collected yet".to_string())
    }

    pub fn call(&self, method: &str, params: &Value) -> Result<Value, String> {
        let r = self.call_inner(method, params);
        // refused actions go to the error log: “why didn’t it end” can be found out later
        if let Err(e) = &r {
            if is_mutating(method) {
                crate::logs::warn(format!("{method}: {e}"));
            }
        }
        r
    }

    fn call_inner(&self, method: &str, params: &Value) -> Result<Value, String> {
        match method {
            "ping" => Ok(json!("pong")),
            "status" => Ok(self.engine.status()),
            // CLI compatibility: frame only / frame + apps
            "frame" => Ok(serde_json::to_value(&*self.wait_first()?.frame).map_err(|e| e.to_string())?),
            "snapshot" => {
                let s = self.wait_first()?;
                Ok(json!({ "frame": &*s.frame, "apps": &*s.apps, "gpus": &*s.gpus, "nets": &*s.nets, "mem_detail": &s.mem_detail }))
            }
            // the window: wait for the next sample (long poll), together with new log events
            "tick" => {
                #[derive(Deserialize)]
                struct P {
                    #[serde(default)]
                    after: u64,
                    #[serde(default)]
                    after_event: u64,
                }
                let p: P = arg(params)?;
                let s = self.engine.wait_newer(p.after, Duration::from_secs(2)).ok_or("no data collected yet")?;
                let mut v = snapshot_json(&s);
                v["events"] = serde_json::to_value(self.engine.events_after(p.after_event)).unwrap_or_default();
                Ok(v)
            }
            "history" => Ok(serde_json::to_value(self.engine.history(&arg::<Query>(params)?)).map_err(|e| e.to_string())?),
            "sparks" => {
                #[derive(Deserialize)]
                struct P {
                    groups: Vec<Vec<ProcKey>>,
                    #[serde(default = "cpu")]
                    metric: Metric,
                    #[serde(default = "points")]
                    points: usize,
                }
                fn cpu() -> Metric {
                    Metric::Cpu
                }
                fn points() -> usize {
                    120
                }
                let p: P = arg(params)?;
                let groups: Vec<Vec<ProcKey>> = p.groups.into_iter().map(|g| g.into_iter().map(norm_key).collect()).collect();
                Ok(json!(self.engine.procs_t0(&groups, p.metric, p.points)))
            }
            "events" => {
                #[derive(Deserialize)]
                struct P {
                    #[serde(default)]
                    after: u64,
                }
                Ok(json!(self.engine.events_after(arg::<P>(params)?.after)))
            }
            "info" => {
                #[derive(Deserialize)]
                struct P {
                    pid: u32,
                    create_time: i64,
                }
                let mut p: P = arg(params)?;
                p.create_time = crate::nt::js_safe(p.create_time);
                let mut cache = InfoCache::default();
                let info = cache.get((p.pid, p.create_time)).clone();
                let prio = self
                    .engine
                    .snapshot()
                    .and_then(|s| s.frame.procs.iter().find(|x| x.pid == p.pid && x.create_time == p.create_time).cloned())
                    .and_then(|x| actions::get_priority(&x));
                Ok(json!({ "info": info, "priority": prio }))
            }
            // several calls in one pass (the window asks for everything it needs once a second)
            "batch" => {
                let calls = params.as_array().ok_or("batch: an array of calls expected")?;
                Ok(Value::Array(
                    calls
                        .iter()
                        .map(|c| {
                            let m = c["method"].as_str().unwrap_or("");
                            let r = if is_local_only(m) || m == "batch" { Err("batch is read-only".to_string()) } else { self.call(m, &c["params"]) };
                            match r {
                                Ok(v) => json!({ "result": v }),
                                Err(e) => json!({ "error": e }),
                            }
                        })
                        .collect(),
                ))
            }
            // path, description, publisher and role for many processes at once (without command lines)
            "infos" => {
                #[derive(Deserialize)]
                struct P {
                    keys: Vec<ProcKey>,
                }
                let p: P = arg(params)?;
                let mut cache = self.info.lock().unwrap();
                if let Some(s) = self.engine.snapshot() {
                    let alive: Vec<ProcKey> = s.frame.procs.iter().map(|x| x.key()).collect();
                    cache.retain_alive(alive.iter());
                }
                let mut out = serde_json::Map::new();
                for k in p.keys.into_iter().take(2000).map(norm_key) {
                    let i = cache.get(k);
                    out.insert(crate::sampler::key_str(k), json!({ "path": i.path, "description": i.description, "company": i.company, "role": i.role }));
                }
                Ok(Value::Object(out))
            }
            "sysinfo" => {
                let s = self.wait_first()?;
                let build = crate::system::reg_hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild").unwrap_or_default();
                let ver = crate::system::reg_hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion").unwrap_or_default();
                let win = if build.parse::<u32>().unwrap_or(0) >= 22000 { "Windows 11" } else { "Windows 10" };
                Ok(json!({
                    "cpu_name": crate::system::reg_hklm(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"),
                    "logical_cpus": s.frame.system.logical_cpus,
                    "memory_total": s.frame.system.memory.total,
                    "os": format!("{win} {ver} (build {build})"),
                    "computer": std::env::var("COMPUTERNAME").ok(),
                    "elevated": crate::system::is_elevated(),
                }))
            }
            "icons" => {
                #[derive(Deserialize)]
                struct P {
                    paths: Vec<String>,
                }
                let p: P = arg(params)?;
                let mut out = serde_json::Map::new();
                for path in p.paths.into_iter().take(200) {
                    let v = self.icons.get(&path);
                    out.insert(path, json!(v));
                }
                Ok(Value::Object(out))
            }
            // kernel pool by tag: the n largest (by=size) or the fastest growing (by=growth)
            "pool" => {
                #[derive(Deserialize)]
                struct P {
                    #[serde(default = "forty")]
                    n: usize,
                    #[serde(default)]
                    by: Option<String>,
                }
                fn forty() -> usize {
                    40
                }
                let p: P = arg(params)?;
                self.wait_first()?;
                Ok(serde_json::to_value(self.engine.pool_report(p.n.min(2000), p.by.as_deref().unwrap_or("size"))).map_err(|e| e.to_string())?)
            }
            // find drivers by tag (in the background, 10–30 s); the result comes in the next "pool" calls
            "pool_owners" => Ok(serde_json::to_value(crate::pool::start_owner_scan(self.engine.pool_tracked())).map_err(|e| e.to_string())?),
            "act" => self.act(params),
            "settings_get" => serde_json::to_value(crate::settings::Settings::load()).map_err(|e| e.to_string()),
            "settings_set" => {
                let s: crate::settings::Settings = arg(params)?;
                s.save().map_err(|e| format!("could not save the settings: {e}"))?;
                Ok(json!({ "ok": true }))
            }
            // Docker containers and their load (while watched — refreshed every 2 s)
            "docker" => Ok(serde_json::to_value(self.docker.get()).map_err(|e| e.to_string())?),
            // Windows services: details — also the start type and description (slower, but cached)
            "services" => {
                let details = params.get("details").and_then(Value::as_bool).unwrap_or(true);
                let list = crate::services::list(details).map_err(|e| e.to_string())?;
                Ok(json!({ "services": list, "elevated": crate::system::is_elevated() }))
            }
            "service_act" => {
                #[derive(Deserialize)]
                struct P {
                    name: String,
                    action: String,
                    #[serde(default)]
                    force: bool,
                }
                let p: P = arg(params)?;
                let what = match p.action.as_str() {
                    "start" => crate::services::Control::Start,
                    "stop" => crate::services::Control::Stop,
                    "restart" => crate::services::Control::Restart,
                    o => return Err(format!("unknown service action “{o}”")),
                };
                let state = crate::services::control(&p.name, what, p.force).map_err(|e| {
                    self.engine.log("warn", format!("Service {}: {} failed — {e}", p.name, p.action), None);
                    e.to_string()
                })?;
                self.engine.log("info", format!("Service {}: {} → {state}", p.name, p.action), None);
                Ok(json!({ "ok": true, "state": state }))
            }
            // network connections and open ports (pid — only this process)
            "connections" => {
                let pid = params.get("pid").and_then(Value::as_u64).map(|p| p as u32);
                let list: Vec<_> = crate::conns::list().into_iter().filter(|c| pid.is_none_or(|p| c.pid == p)).collect();
                Ok(json!({ "connections": list }))
            }
            // main window titles by PID: a browser tab, a file in an editor, a project in an IDE
            "windows" => Ok(json!(crate::labels::window_titles())),
            // which browser process serves which tab: read from its task manager (Shift+Esc) while it is
            // open; what was read is remembered while the process lives
            "browser_tasks" => {
                let mut g = self.btasks.lock().unwrap_or_else(|e| e.into_inner());
                if g.0.is_none_or(|t| t.elapsed() > Duration::from_secs(2)) {
                    g.0 = Some(std::time::Instant::now());
                    g.1 = false;
                    if let (Some(list), Some(s)) = (crate::labels::browser_tasks(), self.engine.snapshot()) {
                        g.1 = true;
                        let ct: std::collections::HashMap<u32, i64> = s.frame.procs.iter().map(|p| (p.pid, p.create_time)).collect();
                        let mut fresh: std::collections::HashMap<ProcKey, Vec<String>> = Default::default();
                        for (pid, t) in list {
                            if let Some(&c) = ct.get(&pid) {
                                let v = fresh.entry((pid, c)).or_default();
                                if !v.contains(&t) {
                                    v.push(t);
                                }
                            }
                        }
                        g.2.extend(fresh);
                    }
                    if let Some(s) = self.engine.snapshot() {
                        let alive: std::collections::HashSet<ProcKey> = s.frame.procs.iter().map(|p| p.key()).collect();
                        g.2.retain(|k, _| alive.contains(k));
                    }
                }
                let tasks: serde_json::Map<String, Value> = g.2.iter().map(|(k, v)| (crate::sampler::key_str(*k), json!(v))).collect();
                Ok(json!({ "open": g.1, "tasks": tasks }))
            }
            // open tabs of a Chromium browser (pid — its main process)
            "browser_tabs" => {
                let pid = params.get("pid").and_then(Value::as_u64).ok_or("pid required")? as u32;
                Ok(json!(crate::labels::browser_tabs(pid)?))
            }
            // which files processes read and write (pid — only this one); the first call starts the observation
            "disk_files" => {
                let pid = params.get("pid").and_then(Value::as_u64).map(|p| p as u32);
                let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(40).min(500) as usize;
                Ok(serde_json::to_value(crate::file_etw::report(pid, limit)?).map_err(|e| e.to_string())?)
            }
            // the process tab: modules, threads, handles, environment — on request
            "inspect" => {
                #[derive(Deserialize)]
                struct P {
                    pid: u32,
                    create_time: i64,
                    what: String,
                }
                let p: P = arg(params)?;
                let ct = crate::nt::js_safe(p.create_time);
                let e = |e: std::io::Error| match e.raw_os_error() {
                    Some(5) => "no access — administrator rights required".to_string(),
                    _ => e.to_string(),
                };
                use crate::inspect;
                match p.what.as_str() {
                    "modules" => Ok(json!({ "modules": inspect::modules(p.pid, ct).map_err(e)? })),
                    "threads" => Ok(json!({ "threads": inspect::threads(p.pid, ct).map_err(e)? })),
                    "handles" => Ok(json!(inspect::handles(p.pid, ct).map_err(e)?)),
                    "env" => Ok(json!(inspect::environment(p.pid, ct).map_err(e)?)),
                    w => Err(format!("inspect: unknown section “{w}” (modules, threads, handles, env)")),
                }
            }
            // window errors (window.onerror) — into the error log; length is limited
            "log" => {
                let msg: String = params.get("msg").and_then(Value::as_str).unwrap_or("").chars().take(2000).collect();
                crate::logs::write_ui(&msg);
                Ok(json!({ "ok": true }))
            }
            // file signature and SHA-256 (for the VirusTotal link)
            "signature" => {
                let path = params.get("path").and_then(Value::as_str).ok_or("path required")?;
                Ok(json!(crate::signature::check(path).map_err(|e| e.to_string())?))
            }
            // who holds the file or the files in a folder (Restart Manager)
            "file_holders" => {
                let path = params.get("path").and_then(Value::as_str).ok_or("path required")?;
                Ok(json!(crate::locks::holders(path).map_err(|e| e.to_string())?))
            }
            "docker_act" => {
                #[derive(Deserialize)]
                struct P {
                    id: String,
                    action: String,
                    #[serde(default)]
                    name: Option<String>,
                }
                let p: P = arg(params)?;
                crate::docker::act(&p.id, &p.action)?;
                self.docker.refresh();
                let who = p.name.unwrap_or(p.id);
                self.engine.log("info", format!("Docker: {who} — {}", crate::docker::action_title(&p.action)), None);
                Ok(json!({ "ok": true }))
            }
            "reveal" => {
                #[derive(Deserialize)]
                struct P {
                    path: String,
                }
                crate::system::reveal_in_explorer(&arg::<P>(params)?.path).map_err(|e| e.to_string())?;
                Ok(json!({ "ok": true }))
            }
            // the file’s VirusTotal page by SHA-256: only this address, no arbitrary links
            "web" if params.get("sha256").is_some() => {
                let h = params.get("sha256").and_then(Value::as_str).unwrap_or("");
                if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("sha256: 64 hexadecimal characters expected".into());
                }
                crate::system::shell_execute("open", &format!("https://www.virustotal.com/gui/file/{}", h.to_ascii_lowercase()), "").map_err(|e| e.to_string())?;
                Ok(json!({ "ok": true }))
            }
            "web" => {
                #[derive(Deserialize)]
                struct P {
                    q: String,
                }
                let q: String = arg::<P>(params)?
                    .q
                    .bytes()
                    .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
                    .collect();
                crate::system::shell_execute("open", &format!("https://www.bing.com/search?q={q}"), "").map_err(|e| e.to_string())?;
                Ok(json!({ "ok": true }))
            }
            _ => Err(format!("unknown method “{method}”")),
        }
    }

    /// An action on processes. Targets are matched against a fresh snapshot by (PID, creation time),
    /// “with children” is expanded from a fresh tree, the order is from the deepest descendants to the root.
    fn act(&self, params: &Value) -> Result<Value, String> {
        #[derive(Deserialize)]
        struct P {
            action: Action,
            targets: Vec<ProcKey>,
            #[serde(default)]
            tree: bool,
            #[serde(default)]
            app: bool,
            #[serde(default)]
            priority: Option<Priority>,
            #[serde(default)]
            dry_run: bool,
            /// without politely closing windows and with confirmed warnings
            #[serde(default)]
            force: bool,
            /// the warnings were shown to a human, and they agreed
            #[serde(default)]
            confirmed: bool,
        }
        let mut p: P = arg(params)?;
        p.targets = p.targets.into_iter().map(norm_key).collect();
        let frame = Sampler::new().sample().map_err(|e| e.to_string())?;
        let tree = Tree::build(&frame.procs);
        let mut roots = Vec::new();
        let mut missing = Vec::new();
        for key in &p.targets {
            match frame.procs.iter().position(|x| x.key() == *key) {
                Some(i) => roots.push(i),
                None => missing.push(key.0),
            }
        }
        let scope = if p.app { actions::Scope::App } else if p.tree { actions::Scope::Tree } else { actions::Scope::One };
        let guard = actions::Guard::new(&frame.procs, &tree);
        let plan = actions::plan(&frame.procs, &tree, &roots, scope, p.action, &guard);
        let mem_of = |pid: u32, ct: i64| frame.procs.iter().find(|x| x.pid == pid && x.create_time == ct).map_or(0, |x| x.mem);
        let mut results: Vec<Outcome> = if p.dry_run {
            plan.preview(&frame.procs, p.action)
        } else {
            let opts = actions::Opts { priority: p.priority, force: p.force, confirmed: p.confirmed, ..Default::default() };
            actions::execute(&frame.procs, &tree, &plan, p.action, opts)
        };
        for pid in missing {
            results.push(Outcome { pid, error: Some("the process has already exited".into()), ..Default::default() });
        }
        let done: Vec<&Outcome> = results.iter().filter(|r| r.ok).collect();
        let freed: u64 = if matches!(p.action, Action::Kill) { done.iter().map(|r| mem_of(r.pid, r.create_time)).sum() } else { 0 };

        if !p.dry_run && !done.is_empty() {
            let main = done.last().map(|r| r.name.clone()).unwrap_or_default();
            let more = if done.len() > 1 { format!(" and {} more", done.len() - 1) } else { String::new() };
            let text = match p.action {
                Action::Kill => format!("Ended: {main}{more} — freed {}", fmt_mem(freed)),
                Action::Suspend => format!("Suspended: {main}{more}"),
                Action::Resume => format!("Resumed: {main}{more}"),
                Action::Restart => format!("Restarted: {main}{more}"),
                Action::Priority => format!("Priority changed: {main}{more}"),
            };
            let who = done.last().map(|r| (r.pid, r.create_time));
            self.engine.log("info", text, who);
        }
        Ok(json!({
            "ok": results.iter().all(|r| r.ok),
            "dry_run": p.dry_run,
            "freed": freed,
            "results": results,
        }))
    }
}
