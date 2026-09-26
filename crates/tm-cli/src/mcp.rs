//! `tm mcp` — MCP-сервер (Model Context Protocol) поверх stdio для ИИ-агентов.
//!
//! Каждый инструмент — это та же команда CLI с `--json`: агент получает ровно то,
//! что видит человек в терминале, с теми же проверками (защищённые процессы, `--all`,
//! `--dry-run`). Если движок запущен, ответы мгновенные — через канал.
//!
//! Действия (завершить, приостановить, контейнеры Docker) доступны, только если сервер
//! запущен с `--allow-actions`: иначе инструмент act не объявляется и вызовы отклоняются.
//! Одно действие затрагивает не больше `MAX_TARGETS` процессов.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const PROTOCOL: &str = "2025-06-18";
/// Предел процессов на одно действие агента: `tm kill chrome --app` — да, «полсистемы» — нет.
const MAX_TARGETS: usize = 20;

fn tools(allow_actions: bool) -> Value {
    let target = json!({ "type": "string", "description": "PID, имя процесса (chrome или chrome.exe) или PID:create_time из JSON-ответов — защита от переиспользования PID" });
    let mut all = json!([
        {
            "name": "sys",
            "description": "Сводка системы: загрузка ЦП, память (занято/доступно/выделено), видеокарты (загрузка, видеопамять), сетевые адаптеры, число процессов, время работы.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "top",
            "description": "Кто нагружает систему прямо сейчас: самые тяжёлые приложения и процессы по ЦП, памяти или вводу-выводу. Начинайте с этого, когда «всё тормозит».",
            "inputSchema": { "type": "object", "properties": {
                "by": { "type": "string", "enum": ["cpu", "mem", "io", "gpu", "net"], "default": "cpu", "description": "net — сетевой трафик процессов (есть, только если приложение запущено от администратора)" },
                "n": { "type": "integer", "default": 10 }
            } }
        },
        {
            "name": "apps",
            "description": "Приложения — процессы, сгруппированные по приложению (все процессы Chrome, IDEA, Docker и т.п. вместе) с суммарной нагрузкой.",
            "inputSchema": { "type": "object", "properties": {
                "sort": { "type": "string", "enum": ["cpu", "mem", "io", "gpu", "count", "name"], "default": "cpu" },
                "n": { "type": "integer", "default": 20 }
            } }
        },
        {
            "name": "ps",
            "description": "Список процессов с ЦП, памятью, вводом-выводом, потоками и дескрипторами. filter — часть имени.",
            "inputSchema": { "type": "object", "properties": {
                "filter": { "type": "string" },
                "sort": { "type": "string", "enum": ["cpu", "mem", "io", "gpu", "name", "pid", "threads", "handles"], "default": "cpu" },
                "n": { "type": "integer", "default": 30, "description": "0 — все" },
                "long": { "type": "boolean", "description": "добавить описание и путь к файлу" }
            } }
        },
        {
            "name": "tree",
            "description": "Дерево процессов с суммами по поддереву: кто кого запустил и сколько всё это потребляет вместе.",
            "inputSchema": { "type": "object", "properties": {
                "target": target,
                "depth": { "type": "integer" }
            } }
        },
        {
            "name": "show",
            "description": "Всё о процессе: путь, командная строка, издатель, родители, дочерние процессы, приоритет, нагрузка.",
            "inputSchema": { "type": "object", "properties": { "target": target }, "required": ["target"] }
        },
        {
            "name": "history",
            "description": "Кто нагружал систему раньше (до 24 ч): ряды по приложениям, процессам, системе или сетевым адаптерам. Нужен работающий движок (приложение «Диспетчер» или tm daemon).",
            "inputSchema": { "type": "object", "properties": {
                "range": { "type": "string", "enum": ["2m", "15m", "1h", "3h", "12h", "24h"], "default": "15m" },
                "scope": { "type": "string", "enum": ["apps", "procs", "system", "net", "gpu"], "default": "apps" },
                "by": { "type": "string", "enum": ["cpu", "mem", "io", "read", "write", "gpu"], "default": "cpu" },
                "n": { "type": "integer", "default": 6 }
            } }
        },
        {
            "name": "events",
            "description": "Журнал движка: зависшие процессы (≈1 ядро долго), утечки памяти, перегрузки системы с виновником, выполненные действия.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "docker",
            "description": "Контейнеры Docker: состояние, ЦП, память, сеть, диск (процессы контейнеров в Windows видны одним vmmem). С action — действие над контейнером.",
            "inputSchema": { "type": "object", "properties": {
                "action": { "type": "string", "enum": ["ls", "start", "stop", "restart", "pause", "unpause", "kill"], "default": "ls" },
                "target": { "type": "string", "description": "имя или начало id контейнера (для действий)" },
                "all": { "type": "boolean", "description": "разрешить несколько совпадений / весь compose-проект" },
                "dry_run": { "type": "boolean" }
            } }
        },
        {
            "name": "pool",
            "description": "Пул ядра по меткам — память драйверов и объектов ядра, которая не видна ни у одного процесса: размер, число объектов, рост в час (движок снимает раз в минуту), тревоги (утечка в драйвере, накопление токенов, зомби-процессы и потоки). owners=true ищет драйверы меток по файлам (10–30 с).",
            "inputSchema": { "type": "object", "properties": {
                "by": { "type": "string", "enum": ["size", "growth"], "default": "size" },
                "n": { "type": "integer", "default": 25 },
                "owners": { "type": "boolean", "description": "найти, в каких драйверах встречаются метки" }
            } }
        },
        {
            "name": "services",
            "description": "Службы Windows: состояние, тип запуска, PID процесса (у svchost.exe — какие службы внутри), описание. Без filter — только работающие; с filter — все подходящие.",
            "inputSchema": { "type": "object", "properties": {
                "filter": { "type": "string", "description": "часть имени или названия службы" },
                "all": { "type": "boolean", "description": "и остановленные" }
            } }
        },
        {
            "name": "connections",
            "description": "Сетевые подключения и открытые порты (TCP/UDP, IPv4/IPv6) с процессом-владельцем. target — только этого процесса.",
            "inputSchema": { "type": "object", "properties": {
                "target": target,
                "listen": { "type": "boolean", "description": "только ожидающие подключений (открытые порты)" }
            } }
        },
        {
            "name": "who",
            "description": "Кто держит файл или файлы в папке открытыми (Restart Manager): почему файл не удаляется или не заменяется.",
            "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] }
        },
        {
            "name": "service_act",
            "description": "Запустить, остановить или перезапустить службу Windows (обычно нужны права администратора). Системные службы (RPC, DCOM, питание и т.п.) агенту не остановить.",
            "inputSchema": { "type": "object", "properties": {
                "action": { "type": "string", "enum": ["start", "stop", "restart"] },
                "name": { "type": "string", "description": "короткое имя службы (из services)" },
                "dry_run": { "type": "boolean" }
            }, "required": ["action", "name"] },
            "annotations": { "destructiveHint": true }
        },
        {
            "name": "act",
            "description": "Действие над процессом: kill (завершить; программе с окном сначала посылается «закрыть окно»), suspend (заморозить), resume, restart (перезапустить с тем же файлом, командной строкой, папкой и правами), prio (сменить приоритет). Защищены: ядро и критические процессы Windows, сам tm, процессы из списка защищённых пользователя; группы «Службы Windows» и «Windows» нельзя затронуть через app/all. Не больше 20 процессов за раз. Принудительного режима у агента нет: если программа не закрыла окно (например, спрашивает о сохранении) или действие рискованное (dwm, explorer), попросите человека сделать это в окне диспетчера или командой tm с --force. Если имя совпадает с несколькими процессами, нужен all=true. Сначала проверьте с dry_run=true.",
            "inputSchema": { "type": "object", "properties": {
                "action": { "type": "string", "enum": ["kill", "suspend", "resume", "restart", "prio"] },
                "target": target,
                "level": { "type": "string", "enum": ["idle", "below", "normal", "above", "high"], "description": "для prio" },
                "tree": { "type": "boolean", "description": "вместе со всеми потомками" },
                "app": { "type": "boolean", "description": "всё приложение, к которому относится процесс" },
                "all": { "type": "boolean", "description": "разрешить, если имя совпало с несколькими процессами" },
                "dry_run": { "type": "boolean", "description": "показать, что будет сделано, ничего не меняя" }
            }, "required": ["action", "target"] },
            "annotations": { "destructiveHint": true }
        }
    ]);
    if !allow_actions {
        // только чтение: без act и без действий над контейнерами
        if let Some(list) = all.as_array_mut() {
            list.retain(|t| t["name"] != "act" && t["name"] != "service_act");
            for t in list.iter_mut().filter(|t| t["name"] == "docker") {
                t["description"] = json!("Контейнеры Docker: состояние, ЦП, память, сеть, диск (процессы контейнеров в Windows видны одним vmmem).");
                t["inputSchema"] = json!({ "type": "object", "properties": {} });
            }
        }
    }
    all
}

/// Аргументы инструмента → аргументы командной строки tm.
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
            v.push(s("target").ok_or("нужен target")?);
        }
        "history" => {
            v.push("history".into());
            opt(&mut v, "range", "range");
            opt(&mut v, "by", "by");
            opt(&mut v, "n", "n");
            match s("scope").as_deref() {
                None | Some("apps") => {}
                Some(sc @ ("procs" | "system" | "net" | "gpu")) => v.push(format!("--{sc}")),
                Some(o) => return Err(format!("неизвестный scope «{o}»")),
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
            v.push(s("path").ok_or("нужен path")?);
        }
        "service_act" => {
            if !allow_actions {
                return Err(NO_ACTIONS.into());
            }
            let action = s("action").ok_or("нужен action")?;
            if !matches!(action.as_str(), "start" | "stop" | "restart") {
                return Err(format!("неизвестное действие «{action}»"));
            }
            v.push("svc".into());
            v.push(action);
            v.push(s("name").ok_or("нужен name")?);
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
                v.push(s("target").ok_or("нужен target")?);
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
            let action = s("action").ok_or("нужен action")?;
            if !matches!(action.as_str(), "kill" | "suspend" | "resume" | "restart" | "prio") {
                return Err(format!("неизвестное действие «{action}»"));
            }
            v.push(action.clone());
            v.push(s("target").ok_or("нужен target")?);
            if action == "prio" {
                v.push(s("level").ok_or("для prio нужен level")?);
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
        _ => return Err(format!("неизвестный инструмент «{name}»")),
    }
    v.push("--json".into());
    Ok(v)
}

const NO_ACTIONS: &str = "действия выключены: MCP-сервер запущен только для чтения (включается: tm mcp --allow-actions)";

fn call_tool(name: &str, args: &Value, allow_actions: bool) -> Value {
    let (text, is_error) = match to_argv(name, args, allow_actions) {
        Err(e) => (e, true),
        Ok(argv) => {
            let exe = std::env::current_exe().unwrap_or_else(|_| "tm.exe".into());
            match Command::new(exe).args(&argv).stdin(Stdio::null()).stderr(Stdio::piped()).output() {
                Ok(o) => {
                    let mut t = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if t.is_empty() {
                        t = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    }
                    // агенту — компактный JSON: вдвое меньше токенов, чем с отступами
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        t = v.to_string();
                    }
                    (t, !o.status.success())
                }
                Err(e) => (format!("не удалось запустить tm: {e}"), true),
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
        let Some(id) = req.get("id").cloned() else { continue }; // уведомления — без ответа
        let method = req["method"].as_str().unwrap_or("");
        let params = &req["params"];
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params["protocolVersion"].as_str().unwrap_or(PROTOCOL),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "tm", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Диспетчер задач Windows. Начинайте с top (что грузит сейчас) или history (что грузило раньше); \
                                 events — замеченные проблемы. Перед kill/suspend уточните цель через show или tree; \
                                 для точности используйте PID:create_time из JSON."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools(allow_actions) })),
            "tools/call" => Ok(call_tool(params["name"].as_str().unwrap_or(""), &params["arguments"], allow_actions)),
            _ => Err(json!({ "code": -32601, "message": format!("метод не поддерживается: {method}") })),
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
