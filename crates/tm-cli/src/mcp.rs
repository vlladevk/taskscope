//! `tm mcp` — an MCP (Model Context Protocol) server over stdio for AI agents.
//!
//! Every tool is the same CLI command with `--json`: the agent gets exactly
//! what a human sees in the terminal, with the same checks (protected processes, `--all`,
//! `--dry-run`). If the engine is running, the answers are instant — through the pipe.
//!
//! Actions (end, suspend, Docker containers) are available only if the server
//! was started with `--allow-actions`: otherwise the act tool is not declared and calls are rejected.
//! One action affects no more than `MAX_TARGETS` processes.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const PROTOCOL: &str = "2025-06-18";
/// The process limit per agent action: `tm kill chrome --app` — yes, “half the system” — no.
const MAX_TARGETS: usize = 20;

fn tools(allow_actions: bool) -> Value {
    let target = json!({ "type": "string", "description": "PID, process name (chrome or chrome.exe) or PID:create_time from JSON answers — protects against PID reuse" });
    let mut all = json!([
        {
            "name": "sys",
            "description": "System summary: CPU load, memory (used/available/committed), GPUs (load, video memory), network adapters, process count, uptime.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "top",
            "description": "Who is loading the system right now: the heaviest apps and processes by CPU, memory or I/O. Start here when “everything is slow”.",
            "inputSchema": { "type": "object", "properties": {
                "by": { "type": "string", "enum": ["cpu", "mem", "io", "gpu", "net"], "default": "cpu", "description": "net — per-process network traffic (only available if the app runs as administrator)" },
                "n": { "type": "integer", "default": 10 }
            } }
        },
        {
            "name": "apps",
            "description": "Apps — processes grouped by application (all Chrome, IDEA, Docker processes and so on together) with their total load.",
            "inputSchema": { "type": "object", "properties": {
                "sort": { "type": "string", "enum": ["cpu", "mem", "io", "gpu", "count", "name"], "default": "cpu" },
                "n": { "type": "integer", "default": 20 }
            } }
        },
        {
            "name": "ps",
            "description": "Process list with CPU, memory, I/O, threads and handles. filter — part of the name.",
            "inputSchema": { "type": "object", "properties": {
                "filter": { "type": "string" },
                "sort": { "type": "string", "enum": ["cpu", "mem", "io", "gpu", "name", "pid", "threads", "handles"], "default": "cpu" },
                "n": { "type": "integer", "default": 30, "description": "0 — all" },
                "long": { "type": "boolean", "description": "add the description and file path" }
            } }
        },
        {
            "name": "tree",
            "description": "Process tree with subtree totals: who started whom and how much it all uses together.",
            "inputSchema": { "type": "object", "properties": {
                "target": target,
                "depth": { "type": "integer" }
            } }
        },
        {
            "name": "show",
            "description": "Everything about a process: path, command line, publisher, parents, child processes, priority, load.",
            "inputSchema": { "type": "object", "properties": { "target": target }, "required": ["target"] }
        },
        {
            "name": "history",
            "description": "Who was loading the system earlier (up to 24 h): series by app, process, system or network adapter. Needs a running engine (the tray app or tm daemon).",
            "inputSchema": { "type": "object", "properties": {
                "range": { "type": "string", "enum": ["2m", "15m", "1h", "3h", "12h", "24h"], "default": "15m" },
                "scope": { "type": "string", "enum": ["apps", "procs", "system", "net", "gpu"], "default": "apps" },
                "by": { "type": "string", "enum": ["cpu", "mem", "io", "read", "write", "gpu"], "default": "cpu" },
                "n": { "type": "integer", "default": 6 }
            } }
        },
        {
            "name": "events",
            "description": "Engine log: hung processes (≈1 core for a long time), memory leaks, system overloads with the culprit, performed actions.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "docker",
            "description": "Docker containers: state, CPU, memory, network, disk (container processes show up in Windows as a single vmmem). With action — an action on a container.",
            "inputSchema": { "type": "object", "properties": {
                "action": { "type": "string", "enum": ["ls", "start", "stop", "restart", "pause", "unpause", "kill"], "default": "ls" },
                "target": { "type": "string", "description": "container name or id prefix (for actions)" },
                "all": { "type": "boolean", "description": "allow several matches / the whole compose project" },
                "dry_run": { "type": "boolean" }
            } }
        },
        {
            "name": "pool",
            "description": "Kernel pool by tag — memory of drivers and kernel objects that is not visible in any process: size, object count, growth per hour (the engine samples once a minute), alarms (driver leak, token build-up, zombie processes and threads). owners=true finds the drivers of the tags by scanning files (10–30 s).",
            "inputSchema": { "type": "object", "properties": {
                "by": { "type": "string", "enum": ["size", "growth"], "default": "size" },
                "n": { "type": "integer", "default": 25 },
                "owners": { "type": "boolean", "description": "find which drivers contain the tags" }
            } }
        },
        {
            "name": "services",
            "description": "Windows services: state, start type, process PID (for svchost.exe — which services are inside), description. Without filter — running ones only; with filter — all matching.",
            "inputSchema": { "type": "object", "properties": {
                "filter": { "type": "string", "description": "part of the service name or display name" },
                "all": { "type": "boolean", "description": "include stopped ones" }
            } }
        },
        {
            "name": "connections",
            "description": "Network connections and open ports (TCP/UDP, IPv4/IPv6) with the owning process. target — only this process.",
            "inputSchema": { "type": "object", "properties": {
                "target": target,
                "listen": { "type": "boolean", "description": "only those waiting for connections (open ports)" }
            } }
        },
        {
            "name": "who",
            "description": "Who keeps a file or the files in a folder open (Restart Manager): why a file cannot be deleted or replaced.",
            "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] }
        },
        {
            "name": "inspect",
            "description": "A process from the inside: modules — loaded DLLs, threads — threads (CPU time, state, start address “module+offset”), handles — open handles (files, registry keys…). The target is a PID, or PID:create_time if the name is ambiguous. The process environment is not given to the agent: it may contain passwords and tokens.",
            "inputSchema": { "type": "object", "properties": {
                "target": { "type": "string" },
                "what": { "type": "string", "enum": ["modules", "threads", "handles"] }
            }, "required": ["target", "what"] }
        },
        {
            "name": "signature",
            "description": "The signature of a process executable or of a file by path (WinVerifyTrust, including Windows catalogs) and SHA-256 for a VirusTotal check.",
            "inputSchema": { "type": "object", "properties": { "target": { "type": "string", "description": "file path, PID or process name" } }, "required": ["target"] }
        },
        {
            "name": "service_act",
            "description": "Start, stop or restart a Windows service (usually needs administrator rights). System services (RPC, DCOM, power and so on) cannot be stopped by an agent.",
            "inputSchema": { "type": "object", "properties": {
                "action": { "type": "string", "enum": ["start", "stop", "restart"] },
                "name": { "type": "string", "description": "short service name (from services)" },
                "dry_run": { "type": "boolean" }
            }, "required": ["action", "name"] },
            "annotations": { "destructiveHint": true }
        },
        {
            "name": "act",
            "description": "An action on a process: kill (end; a program with a window is first asked to close it), suspend (freeze), resume, restart (start again with the same file, command line, folder and rights), prio (change priority). Protected: the kernel and critical Windows processes, tm itself, processes from the user’s protected list; the “Windows services” and “Windows” groups cannot be affected via app/all. No more than 20 processes at a time. The agent has no force mode: if a program did not close its window (for example, it asks about saving) or the action is risky (dwm, explorer), ask the human to do it in the app window or with a tm command with --force. If the name matches several processes, all=true is required. Check with dry_run=true first.",
            "inputSchema": { "type": "object", "properties": {
                "action": { "type": "string", "enum": ["kill", "suspend", "resume", "restart", "prio"] },
                "target": target,
                "level": { "type": "string", "enum": ["idle", "below", "normal", "above", "high"], "description": "for prio" },
                "tree": { "type": "boolean", "description": "together with all descendants" },
                "app": { "type": "boolean", "description": "the whole app the process belongs to" },
                "all": { "type": "boolean", "description": "allow it if the name matched several processes" },
                "dry_run": { "type": "boolean", "description": "show what would be done without changing anything" }
            }, "required": ["action", "target"] },
            "annotations": { "destructiveHint": true }
        }
    ]);
    if !allow_actions {
        // read-only: without act and without container actions
        if let Some(list) = all.as_array_mut() {
            list.retain(|t| t["name"] != "act" && t["name"] != "service_act");
            for t in list.iter_mut().filter(|t| t["name"] == "docker") {
                t["description"] = json!("Docker containers: state, CPU, memory, network, disk (container processes show up in Windows as a single vmmem).");
                t["inputSchema"] = json!({ "type": "object", "properties": {} });
            }
        }
    }
    all
}

/// Tool arguments → tm command-line arguments.
fn to_argv(name: &str, a: &Value, allow_actions: bool) -> Result<Vec<String>, String> {
    let s = |k: &str| a.get(k).and_then(|v| match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    });
    let b = |k: &str| a.get(k).and_then(Value::as_bool).unwrap_or(false);
    let mut v: Vec<String> = Vec::new();
    let opt = |v: &mut Vec<String>, flag: &str, key: &str| {
        if let Some(x) = s(key) {
            v.push(format!("--{flag}"));
            v.push(x);
        }
    };
    match name {
        "sys" | "events" => v.push(name.into()),
        "top" => {
            v.push("top".into());
            opt(&mut v, "by", "by");
            opt(&mut v, "n", "n");
        }
        "apps" => {
            v.push("apps".into());
            opt(&mut v, "sort", "sort");
            opt(&mut v, "n", "n");
        }
        "ps" => {
            v.push("ps".into());
            v.extend(s("filter"));
            opt(&mut v, "sort", "sort");
            opt(&mut v, "n", "n");
            if b("long") {
                v.push("--long".into());
            }
        }
        "tree" => {
            v.push("tree".into());
            v.extend(s("target"));
            opt(&mut v, "depth", "depth");
        }
        "show" => {
            v.push("show".into());
            v.push(s("target").ok_or("target required")?);
        }
        "history" => {
            v.push("history".into());
            opt(&mut v, "range", "range");
            opt(&mut v, "by", "by");
            opt(&mut v, "n", "n");
            match s("scope").as_deref() {
                None | Some("apps") => {}
                Some(sc @ ("procs" | "system" | "net" | "gpu")) => v.push(format!("--{sc}")),
                Some(o) => return Err(format!("unknown scope “{o}”")),
            }
        }
        "pool" => {
            v.push("pool".into());
            opt(&mut v, "by", "by");
            opt(&mut v, "n", "n");
            if b("owners") {
                v.push("--owners".into());
            }
        }
        "services" => {
            v.push("svc".into());
            v.extend(s("filter"));
            if b("all") {
                v.push("--all".into());
            }
        }
        "connections" => {
            v.push("conns".into());
            v.extend(s("target"));
            if b("listen") {
                v.push("--listen".into());
            }
        }
        "who" => {
            v.push("who".into());
            v.push(s("path").ok_or("path required")?);
        }
        "inspect" => {
            let what = s("what").ok_or("what required")?;
            // the environment is only for a human in the window and the CLI: it may contain secrets
            if !matches!(what.as_str(), "modules" | "threads" | "handles") {
                return Err(format!("section “{what}” is not available to the agent: modules, threads, handles"));
            }
            v.push("inspect".into());
            v.push(s("target").ok_or("target required")?);
            v.push(what);
        }
        "signature" => {
            v.push("sig".into());
            v.push(s("target").ok_or("target required")?);
        }
        "service_act" => {
            if !allow_actions {
                return Err(NO_ACTIONS.into());
            }
            let action = s("action").ok_or("action required")?;
            if !matches!(action.as_str(), "start" | "stop" | "restart") {
                return Err(format!("unknown action “{action}”"));
            }
            v.push("svc".into());
            v.push(action);
            v.push(s("name").ok_or("name required")?);
            if b("dry_run") {
                v.push("--dry-run".into());
            }
        }
        "docker" => {
            v.push("docker".into());
            let action = s("action").unwrap_or_else(|| "ls".into());
            if action != "ls" && !allow_actions {
                return Err(NO_ACTIONS.into());
            }
            if action != "ls" {
                v.push(action);
                v.push(s("target").ok_or("target required")?);
            }
            if b("all") {
                v.push("--all".into());
            }
            if b("dry_run") {
                v.push("--dry-run".into());
            }
        }
        "act" => {
            if !allow_actions {
                return Err(NO_ACTIONS.into());
            }
            let action = s("action").ok_or("action required")?;
            if !matches!(action.as_str(), "kill" | "suspend" | "resume" | "restart" | "prio") {
                return Err(format!("unknown action “{action}”"));
            }
            v.push(action.clone());
            v.push(s("target").ok_or("target required")?);
            if action == "prio" {
                v.push(s("level").ok_or("prio requires level")?);
            }
            for f in ["tree", "app", "all"] {
                if b(f) {
                    v.push(format!("--{f}"));
                }
            }
            if b("dry_run") {
                v.push("--dry-run".into());
            }
            v.push("--max-targets".into());
            v.push(MAX_TARGETS.to_string());
        }
        _ => return Err(format!("unknown tool “{name}”")),
    }
    v.push("--json".into());
    Ok(v)
}

const NO_ACTIONS: &str = "actions are off: the MCP server runs read-only (enable with: tm mcp --allow-actions)";

/// How long we wait for one command: the agent must not hang forever if a system query hangs.
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Like `Command::output()`, but no longer than TOOL_TIMEOUT: a hung command is ended.
fn run_limited(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    use std::io::Read;
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    // read both streams in the background, otherwise a full pipe buffer would stall the command
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let until = std::time::Instant::now() + TOOL_TIMEOUT;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if std::time::Instant::now() > until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the command did not answer within 60 s and was stopped"));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    Ok(std::process::Output { status, stdout: t_out.join().unwrap_or_default(), stderr: t_err.join().unwrap_or_default() })
}

fn call_tool(name: &str, args: &Value, allow_actions: bool) -> Value {
    let (text, is_error) = match to_argv(name, args, allow_actions) {
        Err(e) => (e, true),
        Ok(argv) => {
            let exe = std::env::current_exe().unwrap_or_else(|_| "tm.exe".into());
            match run_limited(Command::new(exe).args(&argv)) {
                Ok(o) => {
                    let mut t = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if t.is_empty() {
                        t = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    }
                    // compact JSON for the agent: half the tokens compared to indented output
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        t = v.to_string();
                    }
                    (t, !o.status.success())
                }
                Err(e) => (format!("could not start tm: {e}"), true),
            }
        }
    };
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

pub fn run(allow_actions: bool) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            writeln!(out, "{}", json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } }))?;
            out.flush()?;
            continue;
        };
        let Some(id) = req.get("id").cloned() else { continue }; // notifications get no answer
        let method = req["method"].as_str().unwrap_or("");
        let params = &req["params"];
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params["protocolVersion"].as_str().unwrap_or(PROTOCOL),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "tm", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Windows task manager. Start with top (what is loading the system now) or history (what was loading it earlier); \
                                 events — detected problems. Before kill/suspend confirm the target with show or tree; \
                                 for precision use PID:create_time from JSON."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools(allow_actions) })),
            "tools/call" => Ok(call_tool(params["name"].as_str().unwrap_or(""), &params["arguments"], allow_actions)),
            _ => Err(json!({ "code": -32601, "message": format!("method not supported: {method}") })),
        };
        let resp = match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
        };
        writeln!(out, "{resp}")?;
        out.flush()?;
    }
    Ok(())
}
