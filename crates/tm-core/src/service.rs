//! Единая точка входа ко всем возможностям: окно приложения, CLI (через канал),
//! MCP и режим разработки по HTTP вызывают одно и то же `Service::call(метод, параметры)`.
//!
//! Методы, которые что-то меняют в системе (`act`, `reveal`, `web`), помечены `is_mutating`:
//! канал их не пропускает — клиент выполняет действия сам, со своими правами.

use std::collections::HashSet;
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
    docker: crate::docker::DockerWatch,
}

pub fn is_mutating(method: &str) -> bool {
    matches!(method, "act" | "reveal" | "web" | "docker_act")
}

fn arg<T: for<'de> Deserialize<'de>>(params: &Value) -> Result<T, String> {
    serde_json::from_value(params.clone()).map_err(|e| format!("неверные параметры: {e}"))
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
        format!("{:.1} ГБ", b as f64 / (1u64 << 30) as f64).replace('.', ",")
    } else {
        format!("{} МБ", b >> 20)
    }
}

impl Service {
    pub fn new(engine: Engine) -> Self {
        Self { engine, icons: IconCache::default(), info: Default::default(), docker: crate::docker::DockerWatch::start() }
    }

    fn wait_first(&self) -> Result<Snapshot, String> {
        self.engine.wait_newer(0, self.engine.interval() * 3).ok_or_else(|| "данные ещё не собраны".to_string())
    }

    pub fn call(&self, method: &str, params: &Value) -> Result<Value, String> {
        match method {
            "ping" => Ok(json!("pong")),
            "status" => Ok(self.engine.status()),
            // совместимость с CLI: только кадр / кадр + приложения
            "frame" => Ok(serde_json::to_value(&*self.wait_first()?.frame).map_err(|e| e.to_string())?),
            "snapshot" => {
                let s = self.wait_first()?;
                Ok(json!({ "frame": &*s.frame, "apps": &*s.apps, "gpus": &*s.gpus, "nets": &*s.nets, "mem_detail": &s.mem_detail }))
            }
            // окно: ждём следующий замер (длинный опрос), вместе с новыми событиями журнала
            "tick" => {
                #[derive(Deserialize)]
                struct P {
                    #[serde(default)]
                    after: u64,
                    #[serde(default)]
                    after_event: u64,
                }
                let p: P = arg(params)?;
                let s = self.engine.wait_newer(p.after, Duration::from_secs(2)).ok_or("данные ещё не собраны")?;
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
            // несколько вызовов за один проход (окно запрашивает всё нужное раз в секунду)
            "batch" => {
                let calls = params.as_array().ok_or("batch: ожидается массив вызовов")?;
                Ok(Value::Array(
                    calls
                        .iter()
                        .map(|c| {
                            let m = c["method"].as_str().unwrap_or("");
                            let r = if is_mutating(m) || m == "batch" { Err("в batch можно только читать".to_string()) } else { self.call(m, &c["params"]) };
                            match r {
                                Ok(v) => json!({ "result": v }),
                                Err(e) => json!({ "error": e }),
                            }
                        })
                        .collect(),
                ))
            }
            // путь, описание, издатель и роль для многих процессов сразу (без командных строк)
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
                    "os": format!("{win} {ver} (сборка {build})"),
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
            // пул ядра по меткам: n крупнейших (by=size) или быстрее всех растущих (by=growth)
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
            // найти драйверы по меткам (в фоне, 10–30 с); результат придёт в следующих "pool"
            "pool_owners" => Ok(serde_json::to_value(crate::pool::start_owner_scan(self.engine.pool_tracked())).map_err(|e| e.to_string())?),
            "act" => self.act(params),
            // контейнеры Docker и их нагрузка (пока смотрят — обновляется раз в 2 с)
            "docker" => Ok(serde_json::to_value(self.docker.get()).map_err(|e| e.to_string())?),
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
            _ => Err(format!("неизвестный метод «{method}»")),
        }
    }

    /// Действие над процессами. Цели сверяются со свежим снимком по (PID, время создания),
    /// «с дочерними» раскрывается по свежему дереву, порядок — от самых глубоких потомков к корню.
    fn act(&self, params: &Value) -> Result<Value, String> {
        #[derive(Deserialize)]
        struct P {
            action: Action,
            targets: Vec<ProcKey>,
            #[serde(default)]
            tree: bool,
            #[serde(default)]
            priority: Option<Priority>,
            #[serde(default)]
            dry_run: bool,
        }
        let mut p: P = arg(params)?;
        p.targets = p.targets.into_iter().map(norm_key).collect();
        let frame = Sampler::new().sample().map_err(|e| e.to_string())?;
        let tree = Tree::build(&frame.procs);
        let mut set = Vec::new();
        let mut seen = HashSet::new();
        let mut missing = Vec::new();
        for key in &p.targets {
            let Some(i) = frame.procs.iter().position(|x| x.key() == *key) else {
                missing.push(key.0);
                continue;
            };
            let group: Vec<usize> = if p.tree { std::iter::once(i).chain(tree.descendants(i)).collect() } else { vec![i] };
            set.extend(group.into_iter().filter(|j| seen.insert(*j)));
        }
        let order = actions::deepest_first(&tree, &set);
        let mem_of = |pid: u32, ct: i64| frame.procs.iter().find(|x| x.pid == pid && x.create_time == ct).map_or(0, |x| x.mem);
        let mut results: Vec<Outcome> = if p.dry_run {
            order
                .iter()
                .map(|&i| {
                    let why = actions::protected_reason(&frame.procs[i]);
                    Outcome { pid: frame.procs[i].pid, create_time: frame.procs[i].create_time, name: frame.procs[i].name.clone(), ok: why.is_none(), error: why.map(str::to_string) }
                })
                .collect()
        } else {
            actions::apply(&frame.procs, &order, p.action, p.priority)
        };
        for pid in missing {
            results.push(Outcome { pid, create_time: 0, name: String::new(), ok: false, error: Some("процесс уже завершился".into()) });
        }
        let done: Vec<&Outcome> = results.iter().filter(|r| r.ok).collect();
        let freed: u64 = if matches!(p.action, Action::Kill) { done.iter().map(|r| mem_of(r.pid, r.create_time)).sum() } else { 0 };

        if !p.dry_run && !done.is_empty() {
            let main = done.last().map(|r| r.name.clone()).unwrap_or_default();
            let more = if done.len() > 1 { format!(" и ещё {}", done.len() - 1) } else { String::new() };
            let text = match p.action {
                Action::Kill => format!("Завершено: {main}{more} — освобождено {}", fmt_mem(freed)),
                Action::Suspend => format!("Приостановлено: {main}{more}"),
                Action::Resume => format!("Возобновлено: {main}{more}"),
                Action::Restart => format!("Перезапущено: {main}{more}"),
                Action::Priority => format!("Приоритет изменён: {main}{more}"),
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
