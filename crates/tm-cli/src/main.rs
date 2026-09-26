//! tm — диспетчер задач для терминала и ИИ-агентов.
//! Любая команда поддерживает `--json`; человекочитаемый вывод и JSON строятся из одних данных.

mod mcp;
mod serve;

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use tm_core::actions::{self, Action, Priority};
use tm_core::history::{HistoryResult, Metric, Query, Scope};
use tm_core::{apps, pipe, Engine, Frame, InfoCache, ProcStat, Sampler, Tree};

const HELP: &str = "\
tm — диспетчер задач для терминала и ИИ-агентов

ИСПОЛЬЗОВАНИЕ: tm <команда> [параметры] [--json]

КОМАНДЫ
  sys                        Загрузка ЦП, память, число процессов
  top                        Кто нагружает прямо сейчас: приложения и процессы
                               --by cpu|mem|io|gpu|net   -n N (по умолчанию 10)
                               net — трафик процессов, только если движок запущен от администратора
  apps                       Приложения: процессы, сгруппированные по тому, кто их запустил
                               --sort cpu|mem|io|gpu|count|name   -n N
  ps [фильтр]                Процессы. Фильтр — часть имени
                               --sort cpu|mem|io|gpu|name|pid|threads|handles   -n N (0 — все)
                               --long — описание и путь к файлу
  tree [цель]                Дерево процессов с суммами по поддереву   --depth N
  show <цель>                Всё о процессе: путь, командная строка, родители, дети
  kill <цель>                Завершить процесс. Программе с окном сначала посылается «закрыть окно»
                               (как «Снять задачу»); не закрылась за --wait С (5) — повторите с --force
  suspend <цель>             Приостановить (заморозить) процесс
  resume <цель>              Возобновить процесс
  prio <цель> [уровень]      Показать или задать приоритет: idle|below|normal|above|high
  restart <цель>             Перезапустить как было: тот же файл, командная строка, папка, окружение
                               и права; новый процесс создаётся до завершения старого.
                               Не для служб, приложений из Store и процессов других пользователей
  events                     Журнал: проблемы и перегрузки, замеченные движком
  history                    Кто нагружал систему раньше (нужен движок: tm daemon start)
                               --range 2m|15m|1h|3h|24h (по умолчанию 15m)
                               --apps (по умолчанию) | --procs | --system | --net | --gpu
                               --by cpu|mem|io|read|write|gpu   -n N
  daemon start|stop|status   Фоновый движок: замер раз в секунду, история за 24 ч,
                               канал \\\\.\\pipe\\tm-<SID>-<сеанс>. `daemon run` — то же, но в этом окне
  docker [действие имя]      Контейнеры Docker: ЦП, память, сеть, диск.
                               Действия: start|stop|restart|pause|unpause|kill <имя|id>
  pool                       Пул ядра по меткам: память драйверов и объектов ядра, рост в час,
                               утечки в драйверах, накопление токенов, зомби-процессы
                               --by size|growth   -n N (0 — все)   --owners — найти драйверы меток
                               рост виден, когда запущен движок (снимок раз в минуту)
  mcp                        MCP-сервер (stdio) для ИИ-агентов: те же команды как инструменты.
                               По умолчанию только чтение; --allow-actions разрешает действия
                               (не больше 20 процессов за раз, защита та же, что у tm kill)

ЦЕЛЬ
  1234                       PID
  chrome | chrome.exe        имя процесса (без учёта регистра)
  1234:133721...             PID:create_time — защита от переиспользования PID (create_time из --json)

ПАРАМЕТРЫ ДЕЙСТВИЙ (kill, suspend, resume, prio)
  --tree                     вместе со всеми потомками (сначала потомки, потом родитель)
  --app                      всё приложение, к которому относится процесс
  --all                      разрешить действие, если имя совпало с несколькими процессами
  --dry-run                  показать, что будет сделано, ничего не меняя
  --force                    принудительно: не ждать закрытия окон и не спрашивать о рискованном
                               (приостановка dwm, explorer и т.п.)
  --wait С                   сколько секунд ждать, пока программа закроет окно (по умолчанию 5)

ОБЩИЕ ПАРАМЕТРЫ
  --json                     машиночитаемый вывод (для скриптов и ИИ-агентов)
  --local                    не обращаться к движку, замерить самостоятельно
  --interval MS              своё окно замера скоростей, мс (по умолчанию 500; включает --local)

Если движок запущен, команды отвечают мгновенно его свежими данными (скорости за 1 с).

Защищены от действий: ядро и критические процессы Windows (csrss, lsass, … из System32,
а также помеченные Windows как критические), сам tm и его окно, процессы из списка
«protected» в %LOCALAPPDATA%\\tm\\settings.json. Защищённый процесс закрывает всё своё дерево;
группы «Службы Windows» и «Windows» не затрагиваются через --app и --all.
Коды выхода: 0 — успех, 1 — ошибка или частичный сбой, 2 — неверные аргументы.
";

// ───────────────────────────── аргументы ─────────────────────────────

struct Args {
    pos: Vec<String>,
    flags: HashMap<String, String>,
}

const VALUED: &[&str] = &["sort", "by", "n", "depth", "interval", "range", "port", "root", "wait", "max-targets"];

impl Args {
    fn parse(raw: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut pos = Vec::new();
        let mut flags = HashMap::new();
        let mut it = raw.peekable();
        while let Some(a) = it.next() {
            let name = if let Some(n) = a.strip_prefix("--") {
                n.to_string()
            } else if a.len() > 1 && a.starts_with('-') && !a[1..].starts_with(|c: char| c.is_ascii_digit()) {
                a[1..].to_string()
            } else {
                pos.push(a);
                continue;
            };
            let (name, inline) = match name.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (name, None),
            };
            let name = match name.as_str() {
                "h" => "help".to_string(),
                "limit" => "n".to_string(),
                _ => name,
            };
            let val = if VALUED.contains(&name.as_str()) {
                inline.or_else(|| it.next()).ok_or_else(|| format!("параметру --{name} нужно значение"))?
            } else {
                String::new()
            };
            flags.insert(name, val);
        }
        Ok(Self { pos, flags })
    }
    fn has(&self, f: &str) -> bool {
        self.flags.contains_key(f)
    }
    fn get(&self, f: &str) -> Option<&str> {
        self.flags.get(f).map(String::as_str)
    }
    fn num(&self, f: &str, default: usize) -> Result<usize, String> {
        match self.get(f) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("--{f}: ожидается число, получено «{v}»")),
        }
    }
}

enum Fail {
    Usage(String),
    Error(String),
}

type Res<T> = Result<T, Fail>;

fn usage<T>(msg: impl Into<String>) -> Res<T> {
    Err(Fail::Usage(msg.into()))
}
fn io_err(e: std::io::Error) -> Fail {
    Fail::Error(e.to_string())
}
impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Usage(s)
    }
}

// ───────────────────────────── снимок ─────────────────────────────

struct Snap {
    frame: Frame,
    tree: Tree,
    info: InfoCache,
    /// Готовая группировка от движка (с названиями) — чтобы не искать описания заново.
    apps: Option<Vec<tm_core::AppStat>>,
    /// Видеокарты и сеть — только от движка (свой замер их не собирает).
    gpus: Vec<tm_core::gpu::GpuStat>,
    nets: Vec<tm_core::net::NetStat>,
    mem_detail: Option<tm_core::sysmem::MemDetail>,
}

#[derive(serde::Deserialize)]
struct EngineSnapshot {
    frame: Frame,
    apps: Vec<tm_core::AppStat>,
    #[serde(default)]
    gpus: Vec<tm_core::gpu::GpuStat>,
    #[serde(default)]
    nets: Vec<tm_core::net::NetStat>,
    #[serde(default)]
    mem_detail: Option<tm_core::sysmem::MemDetail>,
}

/// Готовый замер от работающего движка (приложения или `tm daemon`), если он есть.
fn snapshot_from_engine() -> Option<EngineSnapshot> {
    let v = pipe::call("snapshot", Value::Null, Duration::from_secs(3)).ok()?;
    serde_json::from_value(v).ok()
}

impl Snap {
    /// `rates` — нужны ли скорости (ЦП %, диск). Если движок запущен, берём его свежий замер
    /// (скорости за целую секунду, без ожидания); иначе — два своих замера с паузой.
    /// Для действий скорости не нужны, и берётся собственный мгновенный снимок:
    /// так виден даже процесс, появившийся долю секунды назад.
    fn take(args: &Args, rates: bool) -> Res<Self> {
        let engine = (rates && !args.has("local") && !args.has("interval")).then(snapshot_from_engine).flatten();
        let (frame, apps, gpus, nets, mem_detail) = match engine {
            Some(s) => (s.frame, Some(s.apps), s.gpus, s.nets, s.mem_detail),
            None => {
                let mut s = Sampler::new();
                let mut frame = s.sample().map_err(io_err)?;
                if rates {
                    let ms = args.num("interval", 500)?.clamp(50, 10_000);
                    std::thread::sleep(Duration::from_millis(ms as u64));
                    frame = s.sample().map_err(io_err)?;
                }
                (frame, None, Vec::new(), Vec::new(), None)
            }
        };
        let tree = Tree::build(&frame.procs);
        Ok(Self { frame, tree, info: InfoCache::default(), apps, gpus, nets, mem_detail })
    }

    fn groups(&mut self) -> Vec<tm_core::AppStat> {
        match &self.apps {
            Some(a) => a.clone(),
            None => apps::group(&self.frame.procs, &self.tree, &mut self.info),
        }
    }
    fn procs(&self) -> &[ProcStat] {
        &self.frame.procs
    }

    /// Находит процессы по цели: PID, PID:create_time или имени.
    fn resolve(&self, target: &str) -> Res<Vec<usize>> {
        let procs = self.procs();
        let found: Vec<usize> = if let Some((pid, ct)) = target.split_once(':') {
            let (Ok(pid), Ok(ct)) = (pid.parse::<u32>(), ct.parse::<i64>()) else {
                return usage(format!("не понимаю цель «{target}»: ожидается PID:create_time"));
            };
            let ct = tm_core::nt::js_safe(ct);
            let v: Vec<usize> = (0..procs.len()).filter(|&i| procs[i].pid == pid).collect();
            if !v.is_empty() && v.iter().all(|&i| procs[i].create_time != ct) {
                return Err(Fail::Error(format!("процесс {pid} уже завершился: PID занят другим процессом")));
            }
            v.into_iter().filter(|&i| procs[i].create_time == ct).collect()
        } else if let Ok(pid) = target.parse::<u32>() {
            (0..procs.len()).filter(|&i| procs[i].pid == pid).collect()
        } else {
            let t = target.to_ascii_lowercase();
            let t = t.strip_suffix(".exe").unwrap_or(&t);
            (0..procs.len())
                .filter(|&i| {
                    let n = procs[i].name.to_ascii_lowercase();
                    n.strip_suffix(".exe").unwrap_or(&n) == t
                })
                .collect()
        };
        if found.is_empty() {
            return Err(Fail::Error(format!("процесс «{target}» не найден")));
        }
        Ok(found)
    }
}

// ───────────────────────────── форматирование ─────────────────────────────

fn bytes(b: u64) -> String {
    let b = b as f64;
    const K: f64 = 1024.0;
    if b >= K * K * K {
        format!("{:.1} GB", b / (K * K * K))
    } else if b >= 100.0 * K * K {
        format!("{:.0} MB", b / (K * K))
    } else if b >= K * K {
        format!("{:.1} MB", b / (K * K))
    } else if b >= K {
        format!("{:.0} KB", b / K)
    } else {
        format!("{b:.0} B")
    }
}

fn rate(bps: f64) -> String {
    if bps < 1.0 {
        "0".into()
    } else {
        format!("{}/s", bytes(bps as u64))
    }
}

fn dur(ms: u64) -> String {
    let s = ms / 1000;
    let (d, h, m, s) = (s / 86400, s / 3600 % 24, s / 60 % 60, s % 60);
    if d > 0 {
        format!("{d} д {h} ч")
    } else if h > 0 {
        format!("{h} ч {m} мин")
    } else if m > 0 {
        format!("{m} мин {s} с")
    } else {
        format!("{s} с")
    }
}

/// FILETIME (100 нс с 1601 г.) → мс Unix.
fn unix_ms(ft: i64) -> u64 {
    ((ft - 116_444_736_000_000_000).max(0) / 10_000) as u64
}

fn print_json(v: &impl Serialize) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn sort_procs(procs: &[ProcStat], idx: &mut [usize], by: &str) -> Res<()> {
    let io = |p: &ProcStat| p.io_read_bps + p.io_write_bps;
    match by {
        "cpu" => idx.sort_by(|&a, &b| procs[b].cpu.total_cmp(&procs[a].cpu).then(procs[b].mem.cmp(&procs[a].mem))),
        "mem" => idx.sort_by(|&a, &b| procs[b].mem.cmp(&procs[a].mem)),
        "io" => idx.sort_by(|&a, &b| io(&procs[b]).total_cmp(&io(&procs[a]))),
        "net" => idx.sort_by(|&a, &b| (procs[b].net_rx_bps + procs[b].net_tx_bps).total_cmp(&(procs[a].net_rx_bps + procs[a].net_tx_bps))),
        "gpu" => idx.sort_by(|&a, &b| procs[b].gpu.total_cmp(&procs[a].gpu).then(procs[b].gpu_mem.cmp(&procs[a].gpu_mem))),
        "name" => idx.sort_by_cached_key(|&i| procs[i].name.to_lowercase()),
        "pid" => idx.sort_by_key(|&i| procs[i].pid),
        "threads" => idx.sort_by(|&a, &b| procs[b].threads.cmp(&procs[a].threads)),
        "handles" => idx.sort_by(|&a, &b| procs[b].handles.cmp(&procs[a].handles)),
        _ => return usage(format!("--sort: неизвестное поле «{by}»")),
    }
    Ok(())
}

fn sort_apps(list: &mut [tm_core::AppStat], by: &str) -> Res<()> {
    match by {
        "cpu" => list.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem.cmp(&a.mem))),
        "mem" => list.sort_by(|a, b| b.mem.cmp(&a.mem)),
        "io" => list.sort_by(|a, b| (b.io_read_bps + b.io_write_bps).total_cmp(&(a.io_read_bps + a.io_write_bps))),
        "net" => list.sort_by(|a, b| (b.net_rx_bps + b.net_tx_bps).total_cmp(&(a.net_rx_bps + a.net_tx_bps))),
        "gpu" => list.sort_by(|a, b| b.gpu.total_cmp(&a.gpu).then(b.gpu_mem.cmp(&a.gpu_mem))),
        "count" => list.sort_by(|a, b| b.count.cmp(&a.count)),
        "name" => list.sort_by_cached_key(|a| a.title.to_lowercase()),
        _ => return usage(format!("--sort: неизвестное поле «{by}»")),
    }
    Ok(())
}

// ───────────────────────────── команды ─────────────────────────────

fn cmd_sys(args: &Args) -> Res<()> {
    let snap = Snap::take(args, true)?;
    let s = &snap.frame.system;
    if args.has("json") {
        print_json(&json!({ "at_ms": snap.frame.at_ms, "interval_ms": snap.frame.interval_ms, "system": s, "gpus": snap.gpus, "nets": snap.nets, "mem_detail": snap.mem_detail }));
        return Ok(());
    }
    let m = &s.memory;
    println!("ЦП        {:.1} %  ({} логических процессоров)", s.cpu, s.logical_cpus);
    println!(
        "Память    {} из {} ({} %) · выделено {} из {}",
        bytes(m.used), bytes(m.total), m.load_pct, bytes(m.commit_used), bytes(m.commit_limit)
    );
    let private: u64 = snap.frame.procs.iter().map(|p| p.mem).sum();
    println!("          из них частная память процессов {} · остальное {}", bytes(private), bytes(m.used.saturating_sub(private)));
    if let Some(d) = &snap.mem_detail {
        let known = d.pool_nonpaged + d.pool_paged + d.cache + d.kernel_code + d.modified;
        let big = if d.pool_nonpaged > 1 << 30 { "  ← больше обычного (0,2–0,6 GB): возможна утечка в драйвере, подробности — tm pool" } else { "" };
        println!("          · невыгружаемый пул ядра (драйверы) {}{big}", bytes(d.pool_nonpaged));
        println!("          · выгружаемый пул ядра {}", bytes(d.pool_paged));
        println!("          · файловый кэш {} · код ядра и драйверов {} · ждёт записи на диск {}", bytes(d.cache), bytes(d.kernel_code), bytes(d.modified));
        println!(
            "          · общая память программ и прочее {} (DLL, общие буферы браузеров и Electron-приложений, таблицы страниц)",
            bytes(m.used.saturating_sub(private).saturating_sub(known))
        );
    }
    println!("Процессы  {} · потоков {} · дескрипторов {}", s.processes, s.threads, s.handles);
    for g in &snap.gpus {
        println!("Видео     {:.0} % ({}) · видеопамять {} из {} — {}", g.util, g.engine, bytes(g.mem_used), bytes(g.mem_total), g.name);
    }
    for n in &snap.nets {
        println!("Сеть      приём {} · отправка {} — {}", rate(n.rx_bps), rate(n.tx_bps), n.name);
    }
    if snap.gpus.is_empty() && snap.nets.is_empty() {
        println!("(видеокарта и сеть — когда запущен движок: приложение или tm daemon start)");
    }
    println!("Работает  {}", dur(s.uptime_ms));
    Ok(())
}

fn cmd_top(args: &Args) -> Res<()> {
    let mut snap = Snap::take(args, true)?;
    let by = args.get("by").unwrap_or("cpu");
    let n = args.num("n", 10)?;
    let mut list = snap.groups();
    sort_apps(&mut list, by)?;
    list.truncate(n);
    let procs = snap.procs();
    let mut idx: Vec<usize> = (0..procs.len()).filter(|&i| procs[i].pid != 0).collect();
    sort_procs(procs, &mut idx, by)?;
    idx.truncate(n);
    if args.has("json") {
        let top: Vec<&ProcStat> = idx.iter().map(|&i| &procs[i]).collect();
        print_json(&json!({ "at_ms": snap.frame.at_ms, "by": by, "system": snap.frame.system, "apps": list, "procs": top }));
        return Ok(());
    }
    let s = &snap.frame.system;
    println!(
        "ЦП {:.1} % · память {} из {} ({} %) · процессов {}\n",
        s.cpu, bytes(s.memory.used), bytes(s.memory.total), s.memory.load_pct, s.processes
    );
    // короткие процессы в список процессов не попадают — объясняем, куда делся процессор
    let short: f32 = list.iter().map(|a| a.short_cpu).sum();
    if short >= 5.0 {
        println!("Внимание: {short:.0} % ЦП — короткие процессы (живут меньше секунды, в списке ниже их нет); кто их запускает — «↳» у приложения.\n");
    }
    if s.unseen_cpu >= 5.0 {
        println!("{:.0} % ЦП не отнесено ни к одному процессу: прерывания, драйверы или процессы, завершившиеся до замера.\n", s.unseen_cpu);
    }
    println!("ПРИЛОЖЕНИЯ");
    print_apps(&list);
    println!("\nПРОЦЕССЫ");
    print_procs(procs, &idx, &snap.tree, None);
    Ok(())
}

fn print_apps(list: &[tm_core::AppStat]) {
    // сеть по процессам есть, только если движок работает от администратора
    let net = list.iter().any(|a| a.net_rx_bps + a.net_tx_bps > 0.0);
    let net_col = |rx: f64, tx: f64| if net { format!(" {:>21}", format!("{}/{}", rate(rx), rate(tx))) } else { String::new() };
    println!("{:>6} {:>9} {:>10} {:>5}{} {:>4}  {}", "CPU%", "MEM", "IO", "GPU%", if net { format!(" {:>21}", "NET ↓/↑") } else { String::new() }, "N", "APP");
    for a in list {
        println!(
            "{:>6.1} {:>9} {:>10} {:>5.0}{} {:>4}  {}  ({}, PID {})",
            a.cpu, bytes(a.mem), rate(a.io_read_bps + a.io_write_bps), a.gpu, net_col(a.net_rx_bps, a.net_tx_bps), a.count, a.title, a.key, a.root_pid
        );
        if a.short_cpu >= 1.0 {
            println!("{:>6}   ↳ из них {:.1} % — короткие процессы, которые оно запускает: {}", "", a.short_cpu, a.spawn_names.join(", "));
        }
    }
}

fn print_procs(procs: &[ProcStat], idx: &[usize], tree: &Tree, mut long: Option<&mut InfoCache>) {
    let net = idx.iter().any(|&i| procs[i].net_rx_bps + procs[i].net_tx_bps > 0.0);
    println!("{:>7} {:>7} {:>6} {:>9} {:>10} {:>5}{}  {}", "PID", "PPID", "CPU%", "MEM", "IO", "GPU%", if net { format!(" {:>21}", "NET ↓/↑") } else { String::new() }, "NAME");
    for &i in idx {
        let p = &procs[i];
        let ppid = tree.parent[i].map(|j| procs[j].pid.to_string()).unwrap_or_else(|| "-".into());
        let mut line = format!(
            "{:>7} {:>7} {:>6.1} {:>9} {:>10} {:>5.0}{}  {}",
            p.pid, ppid, p.cpu, bytes(p.mem), rate(p.io_read_bps + p.io_write_bps), p.gpu,
            if net { format!(" {:>21}", format!("{}/{}", rate(p.net_rx_bps), rate(p.net_tx_bps))) } else { String::new() },
            p.name
        );
        if let Some(info) = long.as_deref_mut() {
            let inf = info.get(p.key());
            if let Some(d) = &inf.description {
                line += &format!("  — {d}");
            }
            if let Some(path) = &inf.path {
                line += &format!("  [{path}]");
            }
        }
        println!("{line}");
    }
}

fn cmd_apps(args: &Args) -> Res<()> {
    let mut snap = Snap::take(args, true)?;
    let mut list = snap.groups();
    sort_apps(&mut list, args.get("sort").unwrap_or("cpu"))?;
    let n = args.num("n", 0)?;
    if n > 0 {
        list.truncate(n);
    }
    if args.has("json") {
        print_json(&json!({ "at_ms": snap.frame.at_ms, "apps": list }));
    } else {
        print_apps(&list);
    }
    Ok(())
}

#[derive(Serialize)]
struct PsRow<'a> {
    #[serde(flatten)]
    p: &'a ProcStat,
    app: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<tm_core::ProcInfo>,
}

fn cmd_ps(args: &Args) -> Res<()> {
    let mut snap = Snap::take(args, true)?;
    let json_out = args.has("json");
    let long = args.has("long") || args.has("l");
    let keys = apps::keys(snap.procs(), &snap.tree);
    let procs = &snap.frame.procs;
    let filter = args.pos.first().map(|s| s.to_lowercase());
    let mut idx: Vec<usize> = (0..procs.len())
        .filter(|&i| filter.as_ref().map_or(true, |f| procs[i].name.to_lowercase().contains(f.as_str())))
        .collect();
    sort_procs(procs, &mut idx, args.get("sort").unwrap_or("cpu"))?;
    let total = idx.len();
    let n = args.num("n", if json_out { 0 } else { 40 })?;
    if n > 0 {
        idx.truncate(n);
    }
    if json_out {
        let rows: Vec<PsRow> = idx
            .iter()
            .map(|&i| PsRow { p: &procs[i], app: &keys[i], info: long.then(|| snap.info.get(procs[i].key()).clone()) })
            .collect();
        print_json(&json!({ "at_ms": snap.frame.at_ms, "interval_ms": snap.frame.interval_ms, "total": total, "procs": rows }));
        return Ok(());
    }
    print_procs(procs, &idx, &snap.tree, long.then_some(&mut snap.info));
    if total > idx.len() {
        println!("… ещё {} (-n 0 — показать все)", total - idx.len());
    }
    Ok(())
}

fn cmd_tree(args: &Args) -> Res<()> {
    let snap = Snap::take(args, true)?;
    let procs = snap.procs();
    let tree = &snap.tree;
    // Σ — по приложению: программы, запущенные из процесса (из Проводника — почти всё),
    // считаются отдельно; полная сумма поддерева — в mem_subtree / «со всем запущенным»
    let keys = apps::keys(procs, tree);
    let same = |p: usize, c: usize| keys[p] == keys[c];
    let cpu_sum = tree.inclusive_if(procs.len(), |i| procs[i].cpu as f64, same);
    let mem_sum = tree.inclusive_if(procs.len(), |i| procs[i].mem as f64, same);
    let mem_all = tree.inclusive(procs.len(), |i| procs[i].mem as f64);
    let depth = args.num("depth", usize::MAX)?;
    let roots: Vec<usize> = match args.pos.first() {
        Some(t) => snap.resolve(t)?,
        None => {
            let mut r = tree.roots.clone();
            r.retain(|&i| procs[i].pid != 0);
            r
        }
    };
    let children = |i: usize| {
        let mut c = tree.children[i].clone();
        c.sort_by_key(|&j| procs[j].create_time);
        c
    };

    if args.has("json") {
        struct Sums<'a> {
            cs: &'a [f64],
            ms: &'a [f64],
            all: &'a [f64],
            keys: &'a [String],
        }
        fn node(i: usize, d: usize, max: usize, procs: &[ProcStat], s: &Sums, ch: &dyn Fn(usize) -> Vec<usize>) -> Value {
            let p = &procs[i];
            let kids: Vec<Value> = if d < max { ch(i).into_iter().map(|j| node(j, d + 1, max, procs, s, ch)).collect() } else { vec![] };
            json!({ "pid": p.pid, "create_time": p.create_time, "name": p.name, "app": s.keys[i], "cpu": p.cpu, "mem": p.mem,
                    "cpu_total": s.cs[i], "mem_total": s.ms[i] as u64, "mem_subtree": s.all[i] as u64, "children": kids })
        }
        let sums = Sums { cs: &cpu_sum, ms: &mem_sum, all: &mem_all, keys: &keys };
        let v: Vec<Value> = roots.iter().map(|&r| node(r, 0, depth, procs, &sums, &children)).collect();
        print_json(&json!({ "at_ms": snap.frame.at_ms, "note": "cpu_total/mem_total — сумма по своему приложению; mem_subtree — вместе со всем, что запущено из процесса", "tree": v }));
        return Ok(());
    }

    println!("{:>6} {:>9} {:>7} {:>9}  {}", "CPU%", "MEM", "ΣCPU%", "ΣMEM", "PROCESS   (Σ — вместе с дочерними процессами своего приложения)");
    // стек: (индекс, префикс для детей, «ветка» самого узла, глубина)
    let mut stack: Vec<(usize, String, String, usize)> =
        roots.iter().rev().map(|&r| (r, String::new(), String::new(), 0)).collect();
    while let Some((i, prefix, branch, d)) = stack.pop() {
        let p = &procs[i];
        let has_kids = !tree.children[i].is_empty();
        let (sc, sm) = if has_kids { (format!("{:.1}", cpu_sum[i]), bytes(mem_sum[i] as u64)) } else { (String::new(), String::new()) };
        // заметная разница — из процесса запущены другие программы (как из Проводника)
        let launched = if has_kids && mem_all[i] - mem_sum[i] > 50.0 * 1048576.0 { format!("  · со всем запущенным {}", bytes(mem_all[i] as u64)) } else { String::new() };
        println!("{:>6.1} {:>9} {:>7} {:>9}  {branch}{} {}{launched}", p.cpu, bytes(p.mem), sc, sm, p.name, p.pid);
        if d + 1 > depth {
            if has_kids {
                println!("{:>35}{prefix}└─ … ещё {} потомков", "", tree.descendants(i).len());
            }
            continue;
        }
        let kids = children(i);
        for (k, &j) in kids.iter().enumerate().rev() {
            let last = k == kids.len() - 1;
            let b = format!("{prefix}{}", if last { "└─ " } else { "├─ " });
            let pre = format!("{prefix}{}", if last { "   " } else { "│  " });
            stack.push((j, pre, b, d + 1));
        }
    }
    Ok(())
}

fn cmd_show(args: &Args) -> Res<()> {
    let Some(target) = args.pos.first() else { return usage("укажите цель: tm show <PID|имя>") };
    let mut snap = Snap::take(args, true)?;
    let found = snap.resolve(target)?;
    let keys = apps::keys(snap.procs(), &snap.tree);
    let groups = snap.groups();
    let now_ms = snap.frame.at_ms;
    let mut out = Vec::new();
    for &i in &found {
        let procs = &snap.frame.procs;
        let tree = &snap.tree;
        let p = &procs[i];
        let info = snap.info.get(p.key()).clone();
        let app = groups.iter().find(|g| g.key == keys[i]);
        let chain: Vec<Value> = tree.ancestors(i).iter().map(|&j| json!({ "pid": procs[j].pid, "name": procs[j].name })).collect();
        let desc = tree.descendants(i);
        let mut kids = tree.children[i].clone();
        kids.sort_by(|&a, &b| procs[b].cpu.total_cmp(&procs[a].cpu).then(procs[b].mem.cmp(&procs[a].mem)));
        let children: Vec<Value> = kids
            .iter()
            .map(|&j| json!({ "pid": procs[j].pid, "create_time": procs[j].create_time, "name": procs[j].name, "cpu": procs[j].cpu, "mem": procs[j].mem }))
            .collect();
        let sub_cpu: f32 = p.cpu + desc.iter().map(|&j| procs[j].cpu).sum::<f32>();
        let sub_mem: u64 = p.mem + desc.iter().map(|&j| procs[j].mem).sum::<u64>();
        out.push(json!({
            "process": p,
            "info": info,
            "priority": actions::get_priority(p),
            "started_unix_ms": unix_ms(p.create_time),
            "app": app.map(|a| json!({ "key": a.key, "title": a.title, "root_pid": a.root_pid, "count": a.count, "cpu": a.cpu, "mem": a.mem })),
            "ancestors": chain,
            "children": children,
            "subtree": { "count": desc.len() + 1, "cpu": sub_cpu, "mem": sub_mem },
        }));
    }
    if args.has("json") {
        print_json(&json!({ "at_ms": now_ms, "matches": out }));
        return Ok(());
    }
    for (n, v) in out.iter().enumerate() {
        if n > 0 {
            println!("\n────────────────────────────────────────");
        }
        let p = &snap.frame.procs[found[n]];
        let info = &v["info"];
        let s = |v: &Value| v.as_str().map(str::to_string);
        println!("{}  PID {}", p.name, p.pid);
        if let Some(d) = s(&info["description"]) {
            let c = s(&info["company"]).map(|c| format!(" — {c}")).unwrap_or_default();
            println!("Описание    {d}{c}");
        }
        match s(&info["path"]) {
            Some(path) => println!("Файл        {path}"),
            None => println!("Файл        нет доступа (нужны права администратора или это системный процесс)"),
        }
        if let Some(c) = s(&info["cmdline"]) {
            println!("Команда     {c}");
        }
        if let Some(a) = v["app"].as_object() {
            println!("Приложение  {} ({}), процессов: {}, ЦП {:.1} %, память {}",
                a["title"].as_str().unwrap_or(""), a["key"].as_str().unwrap_or(""), a["count"],
                a["cpu"].as_f64().unwrap_or(0.0), bytes(a["mem"].as_u64().unwrap_or(0)));
        }
        println!("Запущен     {} назад", dur(now_ms.saturating_sub(unix_ms(p.create_time))));
        println!("ЦП          {:.1} % · всего потрачено {}", p.cpu, dur(p.cpu_time_ms));
        println!("Память      {} частная · {} рабочий набор · {} выделено", bytes(p.mem), bytes(p.working_set), bytes(p.private_bytes));
        println!("Ввод-вывод  чтение {} · запись {}", rate(p.io_read_bps), rate(p.io_write_bps));
        let prio = v["priority"].as_str().unwrap_or("?");
        println!("Прочее      потоков {} · дескрипторов {} · сеанс {} · приоритет {prio}", p.threads, p.handles, p.session);
        let chain: Vec<String> = v["ancestors"].as_array().into_iter().flatten()
            .map(|a| format!("{} {}", a["name"].as_str().unwrap_or(""), a["pid"]))
            .chain(std::iter::once(format!("[{} {}]", p.name, p.pid)))
            .collect();
        println!("Цепочка     {}", chain.join(" → "));
        let sub = &v["subtree"];
        let kids = v["children"].as_array().cloned().unwrap_or_default();
        if !kids.is_empty() {
            println!("Потомки     процессов: {}, вместе с этим: ЦП {:.1} %, память {}",
                sub["count"].as_u64().unwrap_or(1) - 1, sub["cpu"].as_f64().unwrap_or(0.0), bytes(sub["mem"].as_u64().unwrap_or(0)));
            for k in kids.iter().take(15) {
                println!("  {:>7} {:>6.1} {:>9}  {}", k["pid"], k["cpu"].as_f64().unwrap_or(0.0), bytes(k["mem"].as_u64().unwrap_or(0)), k["name"].as_str().unwrap_or(""));
            }
            if kids.len() > 15 {
                println!("  … ещё {} (tm tree {})", kids.len() - 15, p.pid);
            }
        }
    }
    Ok(())
}

fn cmd_action(args: &Args, action: Action) -> Res<bool> {
    let verb = match action {
        Action::Kill => "kill",
        Action::Suspend => "suspend",
        Action::Resume => "resume",
        Action::Priority => "prio",
        Action::Restart => "restart",
    };
    let Some(target) = args.pos.first() else { return usage(format!("укажите цель: tm {verb} <PID|имя>")) };
    let prio = match (action, args.pos.get(1)) {
        (Action::Priority, Some(l)) => Some(Priority::parse(l).ok_or_else(|| format!("неизвестный приоритет «{l}»: idle|below|normal|above|high"))?),
        (Action::Priority, None) => return cmd_prio_show(args, target).map(|_| true),
        _ => None,
    };
    let snap = Snap::take(args, false)?;
    let procs = snap.procs();
    let found = snap.resolve(target)?;
    if found.len() > 1 && !args.has("all") {
        let list: Vec<String> = found.iter().map(|&i| procs[i].pid.to_string()).collect();
        return usage(format!(
            "«{target}» совпадает с {} процессами (PID {}). Укажите PID или добавьте --all",
            found.len(), list.join(", ")
        ));
    }
    let scope = if args.has("app") {
        actions::Scope::App
    } else if args.has("tree") {
        actions::Scope::Tree
    } else {
        actions::Scope::One
    };
    let guard = actions::Guard::new(procs, &snap.tree);
    let plan = actions::plan(procs, &snap.tree, &found, scope, action, &guard);
    // предел числа целей (его ставит MCP-сервер, чтобы агент не завершил полсистемы одной командой)
    let limit = args.num("max-targets", 0)?;
    if limit > 0 && plan.order.len() > limit as usize {
        return Err(Fail::Error(format!(
            "действие затронет {} процессов — больше предела {limit}; сузьте цель (PID вместо имени, без --app/--tree)",
            plan.order.len()
        )));
    }
    let dry = args.has("dry-run");
    let results = if dry {
        plan.preview(procs, action)
    } else {
        let wait = args.num("wait", 5)?.clamp(0, 120) as u64;
        let opts = actions::Opts { priority: prio, force: args.has("force"), confirmed: false, close_wait: Duration::from_secs(wait) };
        actions::execute(procs, &snap.tree, &plan, action, opts)
    };
    let ok = results.iter().all(|r| r.ok);
    if args.has("json") {
        print_json(&json!({ "action": action, "priority": prio, "dry_run": dry, "ok": ok, "results": results }));
    } else {
        let what = match action {
            Action::Kill => "завершить",
            Action::Suspend => "приостановить",
            Action::Resume => "возобновить",
            Action::Priority => "сменить приоритет",
            Action::Restart => "перезапустить",
        };
        if dry {
            println!("Будет {what} — процессов: {}, в этом порядке:", plan.order.len());
        }
        for r in &results {
            let note = r.note.as_deref().map(|n| format!(" — {n}")).unwrap_or_default();
            let new = r.new_pid.map(|p| format!(" → новый PID {p}")).unwrap_or_default();
            match &r.error {
                None => println!("{} {:>7}  {}{new}{note}", if dry { "·" } else { "✓" }, r.pid, r.name),
                Some(e) => println!("✗ {:>7}  {} — {e}", r.pid, r.name),
            }
        }
        if results.iter().any(|r| r.can_force) {
            println!("Повторите с --force, чтобы выполнить принудительно.");
        }
    }
    Ok(ok)
}

fn cmd_prio_show(args: &Args, target: &str) -> Res<()> {
    let snap = Snap::take(args, false)?;
    let procs = snap.procs();
    let rows: Vec<Value> = snap
        .resolve(target)?
        .iter()
        .map(|&i| json!({ "pid": procs[i].pid, "name": procs[i].name, "priority": actions::get_priority(&procs[i]) }))
        .collect();
    if args.has("json") {
        print_json(&json!({ "results": rows }));
    } else {
        for r in rows {
            println!("{:>7}  {}  {}", r["pid"], r["name"].as_str().unwrap_or(""), r["priority"].as_str().unwrap_or("нет доступа"));
        }
    }
    Ok(())
}

// ───────────────────────────── история и движок ─────────────────────────────

fn parse_range(s: &str) -> Res<u64> {
    let s = s.trim().to_lowercase();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let bad = || Fail::Usage(format!("--range: не понимаю «{s}» (примеры: 90s, 15m, 3h, 24h)"));
    let n: u64 = num.parse().map_err(|_| bad())?;
    let mult = match unit {
        "" | "s" | "с" => 1_000,
        "m" | "min" | "м" | "мин" => 60_000,
        "h" | "ч" => 3_600_000,
        "d" | "д" => 86_400_000,
        _ => return Err(bad()),
    };
    Ok(n * mult)
}

/// Мини-график из блоков: каждый столбец — максимум своей доли значений.
fn spark(values: &[f64], width: usize) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() {
        return String::new();
    }
    let cols = width.min(values.len()).max(1);
    let max = values.iter().copied().fold(0.0, f64::max);
    (0..cols)
        .map(|c| {
            let a = c * values.len() / cols;
            let b = ((c + 1) * values.len() / cols).max(a + 1);
            let v = values[a..b].iter().copied().fold(0.0, f64::max);
            if v <= 0.0 || max <= 0.0 {
                ' '
            } else {
                BARS[((v / max) * 7.0).round().clamp(0.0, 7.0) as usize]
            }
        })
        .collect()
}

fn engine_call(method: &str, params: Value, timeout: Duration) -> Res<Value> {
    pipe::call(method, params, timeout).map_err(|e| {
        if pipe::is_not_running(&e) {
            Fail::Error("движок tm не запущен. Запустите: tm daemon start".into())
        } else {
            io_err(e)
        }
    })
}

fn cmd_history(args: &Args) -> Res<()> {
    let scope = if args.has("procs") {
        Scope::Procs
    } else if args.has("system") {
        Scope::System
    } else if args.has("net") {
        Scope::Net
    } else if args.has("gpu") {
        Scope::Gpu
    } else {
        Scope::Apps
    };
    let by = match args.get("by").unwrap_or(if scope == Scope::Gpu { "gpu" } else { "cpu" }) {
        "cpu" => Metric::Cpu,
        "mem" => Metric::Mem,
        "io" => Metric::Io,
        "read" | "rx" => Metric::Read,
        "write" | "tx" => Metric::Write,
        "gpu" => Metric::Gpu,
        o => return usage(format!("--by: неизвестная метрика «{o}» (cpu|mem|io|read|write|gpu)")),
    };
    let q = Query { scope, range_ms: parse_range(args.get("range").unwrap_or("15m"))?, by, top: args.num("n", 6)?, keys: vec![] };
    let v = engine_call("history", serde_json::to_value(&q).unwrap_or_default(), Duration::from_secs(5))?;
    if args.has("json") {
        print_json(&v);
        return Ok(());
    }
    let r: HistoryResult = serde_json::from_value(v).map_err(|e| Fail::Error(e.to_string()))?;
    let fmt = |x: f64| match by {
        Metric::Cpu | Metric::Gpu => format!("{x:.1} %"),
        Metric::Mem => bytes(x as u64),
        Metric::Io | Metric::Read | Metric::Write => rate(x),
    };
    let span = r.points as u64 * r.step_ms;
    let what = match by {
        Metric::Cpu => "Загрузка ЦП",
        Metric::Gpu => "Загрузка видеокарты",
        Metric::Mem => "Память",
        Metric::Io if scope == Scope::Net => "Сеть (приём + отправка)",
        Metric::Read if scope == Scope::Net => "Сеть, приём",
        Metric::Write if scope == Scope::Net => "Сеть, отправка",
        Metric::Io => "Ввод-вывод",
        Metric::Read => "Чтение",
        Metric::Write => "Запись",
    };
    println!("{what} за {} (шаг {})", dur(span), dur(r.step_ms));
    if let Ok(st) = pipe::call("status", Value::Null, Duration::from_secs(2)) {
        let since = st["history_since_ms"].as_u64().unwrap_or(r.start_ms);
        let up = r.start_ms + span - since.min(r.start_ms + span);
        if up < span {
            println!("история собирается {} — более ранних данных нет", dur(up));
        }
    }
    const W: usize = 48;
    println!("\n{:>9} {:>9}  {:<W$}  {}", "СРЕДНЕЕ", "ПИК", "ГРАФИК", "ИСТОЧНИК");
    let row = |s: &tm_core::history::Series| {
        println!("{:>9} {:>9}  {:<W$}  {}", fmt(s.avg), fmt(s.peak), spark(&s.values, W), s.title);
    };
    let mut total = r.total.clone();
    total.title = "Всего".into();
    row(&total);
    r.series.iter().for_each(row);
    if let Some(o) = &r.other {
        row(o);
    }
    let left = format!("−{}", dur(span));
    println!("{:>19}  {left:<w$}сейчас", "", w = W - "сейчас".chars().count());
    Ok(())
}

fn cmd_events(args: &Args) -> Res<()> {
    let v = engine_call("events", json!({}), Duration::from_secs(3))?;
    if args.has("json") {
        print_json(&v);
        return Ok(());
    }
    let list = v.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("журнал пуст: движок пока ничего не заметил");
    }
    let now = tm_core::engine::wall_ms();
    let n = args.num("n", 30)?;
    for e in list.iter().rev().take(n).rev() {
        let at = e["at_ms"].as_u64().unwrap_or(now);
        let mark = match e["level"].as_str().unwrap_or("") {
            "red" => "✗",
            "yel" => "!",
            "ok" => "✓",
            _ => "·",
        };
        let pid = e["pid"].as_u64().map(|p| format!("  [PID {p}]")).unwrap_or_default();
        println!("{:>12} назад  {mark} {}{pid}", dur(now.saturating_sub(at)), e["text"].as_str().unwrap_or(""));
    }
    Ok(())
}

fn cmd_daemon(args: &Args) -> Res<bool> {
    match args.pos.first().map(String::as_str).unwrap_or("status") {
        "run" => daemon_run(args),
        "start" => daemon_start(args).map(|_| true),
        "stop" => daemon_stop(args).map(|_| true),
        "status" => daemon_status(args).map(|_| true),
        o => usage(format!("tm daemon: неизвестное действие «{o}» (start|stop|status|run)")),
    }
}

fn engine_running() -> bool {
    pipe::call("ping", Value::Null, Duration::from_secs(1)).is_ok()
}

fn daemon_run(args: &Args) -> Res<bool> {
    if engine_running() {
        return Err(Fail::Error("движок уже запущен (tm daemon status)".into()));
    }
    let service = tm_core::Service::new(Engine::start(Duration::from_secs(1), tm_core::engine::default_store()));
    let handler: pipe::Handler = Arc::new(move |m: &str, p: &Value| {
        if tm_core::service::is_mutating(m) {
            return Err("действия через канал не выполняются — tm делает их сам".into());
        }
        if m == "shutdown" {
            let _ = service.engine.save();
            tm_core::net_etw::shutdown();
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(150));
                std::process::exit(0)
            });
            return Ok(json!({ "ok": true }));
        }
        service.call(m, p)
    });
    if !args.has("quiet") {
        eprintln!("tm: движок работает (PID {}), канал {}. Ctrl+C — остановить.", std::process::id(), pipe::pipe_name());
    }
    pipe::serve(handler).map_err(io_err)?;
    Ok(true)
}

fn daemon_start(args: &Args) -> Res<()> {
    if !engine_running() {
        let exe = std::env::current_exe().map_err(io_err)?;
        tm_core::system::spawn_detached(&exe, &["daemon", "run", "--quiet"]).map_err(io_err)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !engine_running() {
            if std::time::Instant::now() > deadline {
                return Err(Fail::Error("движок не ответил после запуска".into()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    } else if !args.has("json") {
        println!("движок уже работал");
    }
    daemon_status(args)
}

fn daemon_stop(args: &Args) -> Res<()> {
    let was = engine_call("shutdown", Value::Null, Duration::from_secs(2)).is_ok();
    if was {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while engine_running() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if args.has("json") {
        print_json(&json!({ "stopped": was }));
    } else {
        println!("{}", if was { "движок остановлен" } else { "движок не был запущен" });
    }
    Ok(())
}

fn daemon_status(args: &Args) -> Res<()> {
    let st = match pipe::call("status", Value::Null, Duration::from_secs(2)) {
        Ok(v) => v,
        Err(e) if pipe::is_not_running(&e) => {
            if args.has("json") {
                print_json(&json!({ "running": false }));
            } else {
                println!("движок не запущен (tm daemon start)");
            }
            return Ok(());
        }
        Err(e) => return Err(io_err(e)),
    };
    if args.has("json") {
        let mut st = st;
        st["running"] = json!(true);
        print_json(&st);
        return Ok(());
    }
    let f = |k: &str| st[k].as_f64().unwrap_or(0.0);
    println!("Движок     работает {}, PID {}, замеров {}", dur(st["uptime_ms"].as_u64().unwrap_or(0)), st["pid"], st["samples"]);
    println!("Замер      в среднем {:.1} мс, худший {:.1} мс (интервал {} мс)", f("sample_cost_avg_ms"), f("sample_cost_max_ms"), st["interval_ms"]);
    println!("Сам        ЦП {:.2} % · память {}", f("own_cpu"), bytes(st["own_mem"].as_u64().unwrap_or(0)));
    let h = &st["history"];
    println!("История    приложений {} · процессов {} · точек {}", h["apps"], h["procs"], h["points"]);
    if let Some(e) = st["error"].as_str() {
        println!("Ошибка     {e}");
    }
    Ok(())
}

/// Скрытая команда: сколько стоит один замер и построение дерева (цель — единицы мс).
fn cmd_bench(args: &Args) -> Res<()> {
    let n = args.num("n", 200)?.max(1);
    let mut s = Sampler::new();
    s.sample().map_err(io_err)?;
    let (mut total, mut worst) = (0f64, 0f64);
    let mut parts = [0f64; 3];
    let mut procs = 0;
    for _ in 0..n {
        let t = std::time::Instant::now();
        let f = s.sample().map_err(io_err)?;
        let t1 = t.elapsed().as_secs_f64();
        let tree = Tree::build(&f.procs);
        let t2 = t.elapsed().as_secs_f64();
        let _ = apps::keys(&f.procs, &tree);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        parts[0] += t1 * 1000.0;
        parts[1] += (t2 - t1) * 1000.0;
        parts[2] += ms - t2 * 1000.0;
        total += ms;
        worst = worst.max(ms);
        procs = f.procs.len();
    }
    let avg = total / n as f64;
    if args.has("json") {
        print_json(&json!({ "samples": n, "procs": procs, "avg_ms": avg, "max_ms": worst,
            "sample_ms": parts[0] / n as f64, "tree_ms": parts[1] / n as f64, "apps_ms": parts[2] / n as f64 }));
    } else {
        let k = n as f64;
        println!("замеров {n}, процессов {procs}: в среднем {avg:.2} мс, худший {worst:.2} мс");
        println!("  снимок {:.2} мс · дерево {:.2} мс · приложения {:.2} мс", parts[0] / k, parts[1] / k, parts[2] / k);
        let time = |f: &mut dyn FnMut()| {
            let t = std::time::Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed().as_secs_f64() * 1000.0 / k
        };
        let mut q = tm_core::nt::ProcessQuery::default();
        let mut raw = Vec::new();
        println!("    NtQuerySystemInformation {:.2} мс", time(&mut || { let _ = q.snapshot(&mut raw); }));
        println!("    GlobalMemoryStatusEx     {:.2} мс", time(&mut || { let _ = tm_core::system::memory(); }));
        println!("    GetSystemTimes           {:.3} мс", time(&mut || { let _ = tm_core::system::cpu_times(); }));
    }
    Ok(())
}

fn run() -> Res<bool> {
    let mut raw = std::env::args().skip(1);
    let cmd = raw.next().unwrap_or_default();
    let args = Args::parse(raw)?;
    if args.has("help") || matches!(cmd.as_str(), "" | "help" | "-h" | "--help") {
        print!("{HELP}");
        return Ok(true);
    }
    match cmd.as_str() {
        "sys" => cmd_sys(&args).map(|_| true),
        "top" => cmd_top(&args).map(|_| true),
        "apps" => cmd_apps(&args).map(|_| true),
        "ps" => cmd_ps(&args).map(|_| true),
        "tree" => cmd_tree(&args).map(|_| true),
        "show" => cmd_show(&args).map(|_| true),
        "kill" => cmd_action(&args, Action::Kill),
        "suspend" => cmd_action(&args, Action::Suspend),
        "resume" => cmd_action(&args, Action::Resume),
        "prio" => cmd_action(&args, Action::Priority),
        "restart" => cmd_action(&args, Action::Restart),
        "bench" => cmd_bench(&args).map(|_| true),
        "history" => cmd_history(&args).map(|_| true),
        "events" => cmd_events(&args).map(|_| true),
        "serve" => {
            let root = args.get("root").map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from("ui"));
            let port = args.num("port", 5174)? as u16;
            let engine = Engine::start_readonly(Duration::from_secs(1), tm_core::engine::default_store());
            serve::run(Arc::new(tm_core::Service::new(engine)), root, port, args.has("allow-actions")).map_err(io_err)?;
            Ok(true)
        }
        "docker" => cmd_docker(&args),
        "pool" => cmd_pool(&args).map(|_| true),
        "mcp" => mcp::run(args.has("allow-actions")).map(|_| true).map_err(io_err),
        "daemon" => cmd_daemon(&args),
        "status" => daemon_status(&args).map(|_| true),
        "--version" | "version" => {
            println!("tm {}", env!("CARGO_PKG_VERSION"));
            Ok(true)
        }
        other => usage(format!("неизвестная команда «{other}». tm help — список команд")),
    }
}

fn main() -> ExitCode {
    let json_mode = std::env::args().any(|a| a == "--json");
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(f) => {
            let (msg, code) = match f {
                Fail::Usage(m) => (m, 2),
                Fail::Error(m) => (m, 1),
            };
            if json_mode {
                println!("{}", json!({ "error": msg }));
            } else {
                eprintln!("tm: {msg}");
            }
            ExitCode::from(code)
        }
    }
}

// ───────────────────────────── docker ─────────────────────────────

fn cmd_docker(args: &Args) -> Res<bool> {
    use tm_core::docker::{self, DockerState};
    let state: DockerState = match (args.has("local"), engine_call("docker", Value::Null, Duration::from_secs(6))) {
        (false, Ok(v)) => serde_json::from_value(v).map_err(|e| Fail::Error(e.to_string()))?,
        _ => docker::snapshot_now(),
    };
    let action = args.pos.first().map(String::as_str).unwrap_or("ls");
    if action != "ls" {
        let Some(target) = args.pos.get(1) else { return usage(format!("укажите контейнер: tm docker {action} <имя|id>")) };
        if !state.available {
            return Err(Fail::Error(state.error.unwrap_or_else(|| "Docker не запущен".into())));
        }
        let t = target.to_lowercase();
        let found: Vec<&docker::Container> = state
            .containers
            .iter()
            .filter(|c| c.name.to_lowercase() == t || c.id.starts_with(&t) || (args.has("all") && c.project.as_deref().is_some_and(|p| p.to_lowercase() == t)))
            .collect();
        if found.is_empty() {
            return usage(format!("контейнер «{target}» не найден (tm docker — список)"));
        }
        if found.len() > 1 && !args.has("all") {
            return usage(format!("«{target}» совпадает с несколькими контейнерами — добавьте --all"));
        }
        let mut ok = true;
        let mut results = Vec::new();
        for c in found {
            let r = if args.has("dry-run") { Ok(()) } else { docker::act(&c.id, action) };
            ok &= r.is_ok();
            if !args.has("json") {
                match &r {
                    Ok(()) => println!("{} {}  {}", if args.has("dry-run") { "·" } else { "✓" }, c.id, c.name),
                    Err(e) => println!("✗ {}  {} — {e}", c.id, c.name),
                }
            }
            results.push(json!({ "id": c.id, "name": c.name, "ok": r.is_ok(), "error": r.err() }));
        }
        if args.has("json") {
            print_json(&json!({ "action": action, "dry_run": args.has("dry-run"), "ok": ok, "results": results }));
        }
        return Ok(ok);
    }
    if args.has("json") {
        print_json(&state);
        return Ok(state.available);
    }
    if !state.available {
        println!("Docker: {}", state.error.as_deref().unwrap_or("не запущен"));
        return Ok(false);
    }
    println!("Docker {} · контейнеров {} (работает {})\n", state.version.as_deref().unwrap_or(""), state.containers.len(), state.containers.iter().filter(|c| c.state == "running").count());
    println!("{:>6} {:>9} {:>12} {:>12} {:>5}  {:<13} {}", "CPU%", "MEM", "NET ↓/↑", "DISK R/W", "PIDS", "ID", "NAME");
    for c in &state.containers {
        if c.state != "running" {
            println!("{:>6} {:>9} {:>12} {:>12} {:>5}  {:<13} {}  [{}]", "-", "-", "-", "-", "-", c.id, c.name, c.status);
            continue;
        }
        println!(
            "{:>6.1} {:>9} {:>12} {:>12} {:>5}  {:<13} {}{}",
            c.cpu,
            bytes(c.mem),
            format!("{}/{}", rate(c.net_rx_bps), rate(c.net_tx_bps)),
            format!("{}/{}", rate(c.blk_read_bps), rate(c.blk_write_bps)),
            c.pids,
            c.id,
            c.name,
            if c.state == "paused" { "  [приостановлен]" } else { "" }
        );
    }
    Ok(true)
}

// ───────────────────────────── пул ядра ─────────────────────────────

fn cmd_pool(args: &Args) -> Res<()> {
    use tm_core::pool::{self, PoolReport};
    let n = match args.num("n", 25)? {
        0 => 2000,
        n => n,
    };
    let by = args.get("by").unwrap_or("size");
    if !matches!(by, "size" | "growth") {
        return usage(format!("--by: неизвестный порядок «{by}» (size|growth)"));
    }
    let params = json!({ "n": n, "by": by });
    let fetch = || -> Option<PoolReport> {
        let v = pipe::call("pool", params.clone(), Duration::from_secs(5)).ok()?;
        serde_json::from_value(v).ok()
    };
    // движок следит за пулом раз в минуту и знает скорость роста; без него — один снимок
    let mut report = if args.has("local") { None } else { fetch() };
    let mut watch = pool::PoolWatch::default();
    if report.is_none() {
        let frame = Sampler::new().sample().map_err(io_err)?;
        let procs = frame.system.processes;
        watch.ingest(tm_core::engine::wall_ms(), pool::query(), procs, frame.system.threads);
    }
    if args.has("owners") {
        if report.is_some() {
            engine_call("pool_owners", Value::Null, Duration::from_secs(5))?;
            let t = std::time::Instant::now();
            while t.elapsed() < Duration::from_secs(180) {
                std::thread::sleep(Duration::from_millis(500));
                let st = engine_call("pool", json!({ "n": 1 }), Duration::from_secs(5))?;
                if st["owners"]["state"] != "running" {
                    break;
                }
            }
            report = fetch();
        } else {
            if !args.has("json") {
                eprintln!("ищу метки в файлах загруженных драйверов…");
            }
            pool::scan_owners(&watch.tracked(), |_, _| {});
        }
    }
    let r = report.unwrap_or_else(|| watch.report(n, by));
    if args.has("json") {
        print_json(&r);
        return Ok(());
    }
    if let Some(e) = &r.error {
        return Err(Fail::Error(format!("пул ядра недоступен: {e}")));
    }
    let watching = if r.watching_ms >= 10 * 60_000 {
        format!(" · наблюдение {}", dur(r.watching_ms))
    } else {
        String::new()
    };
    println!("Пул ядра: невыгружаемый {} · выгружаемый {}{watching}", bytes(r.nonpaged), bytes(r.paged));
    if r.watching_ms < 10 * 60_000 {
        println!("(рост в час появится после 10 минут наблюдения — движок снимает пул раз в минуту, пока запущено приложение или tm daemon)");
    }
    for a in &r.alerts {
        println!("{} {}", if a.level == "red" { "✗" } else { "!" }, a.text);
    }
    if r.zombie_procs > 0 || r.zombie_threads > 0 {
        println!("Завершённые, но не освобождённые: процессов {} · потоков {}", r.zombie_procs, r.zombie_threads);
    }
    println!("\n{:<5} {:>9} {:>9} {:>9} {:>10}  {:<16}  {}", "МЕТКА", "НЕВЫГР.", "ВЫГР.", "ОБЪЕКТОВ", "РОСТ/Ч", "ГРАФИК", "ЧТО ЭТО");
    for t in &r.tags {
        let growth = match t.rate {
            Some(v) if v.abs() >= 64.0 * 1024.0 => format!("{}{}", if v > 0.0 { "+" } else { "−" }, bytes(v.abs() as u64)),
            Some(_) => "0".into(),
            None => "—".into(),
        };
        // график формы: от минимума до максимума, иначе рост 190 → 192 МБ не виден
        let lo = t.spark.iter().copied().min().unwrap_or(0) as f64;
        let hi = t.spark.iter().copied().max().unwrap_or(0) as f64;
        let vals: Vec<f64> = t.spark.iter().map(|&v| v as f64 - lo + (hi - lo).max(1.0) * 0.08).collect();
        let owners = match t.owners.len() {
            0 => String::new(),
            1..=3 => format!(" [{}]", t.owners.join(", ")),
            k => format!(" [{}, … ещё {}]", t.owners[..2].join(", "), k - 2),
        };
        let mut what = format!("{}{owners}", t.about.as_deref().unwrap_or(""));
        if what.chars().count() > 90 {
            what = what.chars().take(89).collect::<String>() + "…";
        }
        println!(
            "{:<5} {:>9} {:>9} {:>9} {:>10}  {:<16}  {}{}",
            t.tag,
            bytes(t.nonpaged),
            bytes(t.paged),
            t.count,
            growth,
            spark(&vals, 16),
            if t.alert { "← " } else { "" },
            what.trim()
        );
    }
    if r.owners.state != "done" && !args.has("owners") {
        println!("\nЧей драйвер у метки — tm pool --owners (поиск по файлам загруженных драйверов, 10–30 с)");
    }
    Ok(())
}
