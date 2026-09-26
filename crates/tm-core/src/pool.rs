//! Пул ядра по меткам — память, которую ядро и драйверы берут под свои объекты.
//!
//! Каждое выделение в пуле помечено четырьмя буквами: `Toke` — токены безопасности,
//! `Thre` — потоки, `NVRM` — драйвер NVIDIA… Windows отдаёт размеры по меткам без прав
//! администратора (`NtQuerySystemInformation`, класс 22) — это один дешёвый вызов,
//! движок делает его раз в минуту.
//!
//! Утечка в ядре не видна ни у одного процесса — она видна только здесь, как метка,
//! которая растёт без остановки. Чья метка — ищем по файлам загруженных драйверов
//! (`start_owner_scan`): метка зашита в код драйвера теми же четырьмя байтами.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

const CLASS_POOLTAG: i32 = 22;
const CLASS_MODULES: i32 = 11;

/// Раз в минуту, час — для свежей скорости и графика.
const FINE_EVERY: u64 = 60_000;
const FINE_CAP: usize = 61;
/// Раз в 10 минут, сутки — для медленных утечек.
const COARSE_EVERY: u64 = 10 * 60_000;
const COARSE_CAP: usize = 145;
/// Следим за метками от 1 МБ: мелких тысячи, и утечкой они не станут незаметно.
const TRACK_MIN: u64 = 1 << 20;

/// Больше стольких токенов на домашнем компьютере не бывает без утечки ссылок.
const TOKENS_HIGH: u64 = 30_000;
const ZOMBIE_PROCS_HIGH: i64 = 300;
const ZOMBIE_THREADS_HIGH: i64 = 3_000;

#[derive(Clone, Copy, Debug, Default)]
pub struct Raw {
    pub paged: u64,
    pub nonpaged: u64,
    /// Живых выделений (выделено − освобождено).
    pub paged_live: u64,
    pub nonpaged_live: u64,
}

impl Raw {
    fn bytes(&self) -> u64 {
        self.paged + self.nonpaged
    }
    fn count(&self) -> u64 {
        self.paged_live + self.nonpaged_live
    }
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Метка как число — в том порядке байт, в каком она лежит в памяти и в коде драйвера.
pub fn tag_id(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

pub fn tag_str(t: u32) -> String {
    t.to_le_bytes().iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' }).collect::<String>().trim_end().to_string()
}

/// Все метки пула сейчас. Раскладка `SYSTEM_POOLTAG_INFORMATION` на x64: число меток,
/// затем с 8-го байта записи по 40 байт — метка, выделения/освобождения и байты
/// выгружаемого пула, затем то же для невыгружаемого.
pub fn query() -> std::io::Result<HashMap<u32, Raw>> {
    let b = crate::nt::query_system(CLASS_POOLTAG, 256 << 10)?;
    let n = rd32(&b, 0) as usize;
    let mut m = HashMap::with_capacity(n);
    for i in 0..n {
        let o = 8 + i * 40;
        if o + 40 > b.len() {
            break;
        }
        // счётчики 32-битные и переполняются, разность по модулю 2^32 остаётся верной
        let live = |a: u32, f: u32| a.wrapping_sub(f) as u64;
        m.insert(
            rd32(&b, o),
            Raw { paged: rd64(&b, o + 16), nonpaged: rd64(&b, o + 32), paged_live: live(rd32(&b, o + 4), rd32(&b, o + 8)), nonpaged_live: live(rd32(&b, o + 24), rd32(&b, o + 28)) },
        );
    }
    Ok(m)
}

/// Что за метка — для самых частых и важных. Остальное подскажет поиск по драйверам.
pub fn about(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "Toke" => "Токены безопасности — «пропуска» программ: от чьего имени работают и что им можно",
        "SeAt" => "Атрибуты токенов: группы и привилегии",
        "SeTl" => "Служебные записи токенов",
        "Proc" => "Объекты процессов, включая завершённые, на которые ещё держат дескрипторы",
        "Thre" => "Объекты потоков, включая завершённые, на которые ещё держат дескрипторы",
        "File" => "Открытые файлы",
        "Even" => "События — объекты синхронизации программ",
        "Sema" => "Семафоры — объекты синхронизации",
        "Muta" => "Мьютексы — объекты синхронизации",
        "Key" => "Открытые ключи реестра",
        "ObNm" => "Имена объектов ядра",
        "ObDi" => "Каталоги объектов ядра",
        "AlMs" => "Сообщения ALPC — обмен между программами и службами",
        "smNp" | "smCB" | "smBt" | "smCo" => "Сжатие памяти: хранилище сжатых страниц",
        "EtwB" => "Буферы трассировки событий (ETW) — журналы, которые пишут Windows и программы",
        "EtwR" => "Записи трассировки событий (ETW)",
        "MmSt" => "Таблицы отображения файлов в память",
        "MmCa" => "Области отображённых в память файлов",
        "MmRe" => "Управление памятью: ресурсы",
        "Vad" | "VadS" | "Vadl" => "Карта памяти процессов (VAD)",
        "FMfn" => "Кэш имён файлов фильтр-драйверов (антивирусы, облачные диски, резервное копирование)",
        "FMsl" => "Фильтр-драйверы: записи о файлах",
        "FMsc" => "Фильтр-драйверы: контексты открытых файлов",
        "FMic" => "Фильтр-драйверы: контексты экземпляров",
        "NtfF" => "NTFS: записи открытых файлов",
        "Ntff" => "NTFS: блоки управления файлами",
        "NtFs" => "NTFS: служебные данные",
        "CM31" | "CM25" | "CM16" | "CM29" | "CM32" => "Реестр Windows",
        "DxgK" => "DirectX: ядро графики",
        "NVRM" => "Драйвер видеокарты NVIDIA",
        "AfdB" | "AfdE" => "Сетевые сокеты (AFD)",
        "TcpE" | "TcpL" | "TcpR" => "TCP-соединения",
        "Irp" => "Запросы ввода-вывода к драйверам",
        "Pool" => "Служебные таблицы самого пула",
        "VdMm" => "Hyper-V: виртуальные машины (WSL, Docker, песочница)",
        "Wfp" | "WfpL" => "Брандмауэр Windows (WFP)",
        "Cont" => "Непрерывная физическая память для устройств",
        "HalD" => "HAL: память для устройств (DMA)",
        "MmCm" => "Непрерывная память для драйверов",
        "Gh05" | "Gla5" | "Gpbm" => "Графическая подсистема (win32k)",
        _ => return None,
    })
}

// ───────────────────────────── слежение ─────────────────────────────

#[derive(Clone, Copy)]
struct Pt {
    t: u64,
    bytes: u64,
    count: u64,
}

#[derive(Default)]
struct Series {
    fine: VecDeque<Pt>,
    coarse: VecDeque<Pt>,
}

/// Скорость роста за час по методу наименьших квадратов. `None`, пока данных меньше 10 минут.
fn slope(pts: &VecDeque<Pt>, f: fn(&Pt) -> u64) -> Option<(f64, u64)> {
    if pts.len() < 3 {
        return None;
    }
    let span = pts.back()?.t - pts.front()?.t;
    if span < 10 * 60_000 {
        return None;
    }
    let n = pts.len() as f64;
    let t0 = pts[0].t as f64;
    let mx = pts.iter().map(|p| (p.t as f64 - t0) / 3.6e6).sum::<f64>() / n;
    let my = pts.iter().map(|p| f(p) as f64).sum::<f64>() / n;
    let (mut sxy, mut sxx) = (0.0, 0.0);
    for p in pts {
        let x = (p.t as f64 - t0) / 3.6e6 - mx;
        sxy += x * (f(p) as f64 - my);
        sxx += x * x;
    }
    (sxx > 0.0).then(|| (sxy / sxx, span))
}

/// Доля шагов, на которых значение не уменьшилось.
fn ups(pts: &VecDeque<Pt>, f: fn(&Pt) -> u64) -> f64 {
    if pts.len() < 2 {
        return 0.0;
    }
    let up = pts.iter().zip(pts.iter().skip(1)).filter(|(a, b)| f(b) >= f(a)).count();
    up as f64 / (pts.len() - 1) as f64
}

impl Series {
    fn best(&self) -> &VecDeque<Pt> {
        let span = |v: &VecDeque<Pt>| v.back().map_or(0, |b| b.t - v[0].t);
        if span(&self.coarse) >= 60 * 60_000 {
            &self.coarse
        } else {
            &self.fine
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolAlert {
    pub tag: String,
    /// red | yel
    pub level: String,
    /// leak | tokens | zombie_procs | zombie_threads
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TagReport {
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    pub paged: u64,
    pub nonpaged: u64,
    /// Живых выделений (для объектов ядра — число объектов).
    pub count: u64,
    /// Рост, байт в час; `None` — наблюдаем меньше 10 минут.
    #[serde(default)]
    pub rate: Option<f64>,
    /// Рост числа выделений в час.
    #[serde(default)]
    pub count_rate: Option<f64>,
    /// За какой отрезок посчитан рост, мс.
    #[serde(default)]
    pub rate_window_ms: u64,
    /// Размер (байт) по времени — для графика; шаг `spark_step_ms`.
    #[serde(default)]
    pub spark: Vec<u64>,
    #[serde(default)]
    pub spark_step_ms: u64,
    /// Файлы драйверов, в коде которых встречается метка (после поиска).
    #[serde(default)]
    pub owners: Vec<String>,
    #[serde(default)]
    pub alert: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OwnersStatus {
    /// idle | running | done
    pub state: String,
    pub scanned: usize,
    pub total: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PoolReport {
    pub at_ms: u64,
    /// Сколько уже наблюдаем (скорость роста точнее с каждым часом).
    pub watching_ms: u64,
    pub paged: u64,
    pub nonpaged: u64,
    pub tags: Vec<TagReport>,
    pub alerts: Vec<PoolAlert>,
    /// Завершённые процессы и потоки, которые ещё держат в памяти (объектов больше, чем живых).
    pub zombie_procs: i64,
    pub zombie_threads: i64,
    pub owners: OwnersStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Default)]
pub struct PoolWatch {
    series: HashMap<u32, Series>,
    last: HashMap<u32, Raw>,
    at_ms: u64,
    started_ms: u64,
    coarse_at: u64,
    alerts: Vec<PoolAlert>,
    zombie_procs: i64,
    zombie_threads: i64,
    error: Option<String>,
}

fn mb(b: f64) -> String {
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} ГБ", b / (1u64 << 30) as f64).replace('.', ",")
    } else if b >= 10.0 * 1024.0 * 1024.0 {
        format!("{:.0} МБ", b / (1u64 << 20) as f64)
    } else {
        format!("{:.1} МБ", b / (1u64 << 20) as f64).replace('.', ",")
    }
}

fn span_text(ms: u64) -> String {
    let min = ms / 60_000;
    if min < 90 {
        format!("{min} мин")
    } else {
        format!("{} ч", (min + 30) / 60)
    }
}

/// Метаданные файлового кэша: растут от любого чтения файлов и возвращаются системе сами.
fn is_cache_tag(tag: &str) -> bool {
    matches!(tag, "MmSt" | "MmCa" | "File" | "NtfF" | "Ntff" | "NtFs" | "FMfn" | "FMsl" | "FMsc" | "CcSc" | "Vacb" | "FSfm" | "FSim")
}

fn thousands(n: f64) -> String {
    let n = n.round() as i64;
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('\u{a0}');
        }
        out.push(c);
    }
    if n < 0 {
        format!("−{out}")
    } else {
        out
    }
}

impl PoolWatch {
    /// Пора ли снова снимать пул (раз в минуту).
    pub fn due(&self, t: u64) -> bool {
        self.at_ms == 0 || t.saturating_sub(self.at_ms) >= FINE_EVERY
    }

    /// Принимает замер. Возвращает записи для журнала: появившиеся и прошедшие проблемы.
    pub fn ingest(&mut self, t: u64, raw: std::io::Result<HashMap<u32, Raw>>, procs: usize, threads: u64) -> Vec<(&'static str, String)> {
        let raw = match raw {
            Ok(r) => r,
            Err(e) => {
                self.error = Some(e.to_string());
                self.at_ms = t;
                return Vec::new();
            }
        };
        self.error = None;
        if self.started_ms == 0 {
            self.started_ms = t;
        }
        self.at_ms = t;
        let coarse = t.saturating_sub(self.coarse_at) >= COARSE_EVERY || self.coarse_at == 0;
        if coarse {
            self.coarse_at = t;
        }
        for (&tag, r) in &raw {
            if r.bytes() < TRACK_MIN && !self.series.contains_key(&tag) {
                continue;
            }
            let s = self.series.entry(tag).or_default();
            let p = Pt { t, bytes: r.bytes(), count: r.count() };
            s.fine.push_back(p);
            while s.fine.len() > FINE_CAP {
                s.fine.pop_front();
            }
            if coarse {
                s.coarse.push_back(p);
                while s.coarse.len() > COARSE_CAP {
                    s.coarse.pop_front();
                }
            }
        }
        // метка исчезла или давно мелкая — перестаём следить
        self.series.retain(|tag, s| raw.get(tag).is_some_and(|r| r.bytes() >= TRACK_MIN / 4) || s.fine.iter().any(|p| p.bytes >= TRACK_MIN));

        let obj = |name: &str| raw.get(&tag_id(name)).map_or(0, |r| r.count()) as i64;
        self.zombie_procs = (obj("Proc") - procs as i64).max(0);
        self.zombie_threads = (obj("Thre") - threads as i64).max(0);
        self.last = raw;

        let alerts = self.find_alerts();
        let mut out = Vec::new();
        for a in &alerts {
            if !self.alerts.iter().any(|o| o.tag == a.tag && o.kind == a.kind) {
                out.push((if a.level == "red" { "red" } else { "yel" }, format!("Ядро: {}", a.text)));
            }
        }
        for o in &self.alerts {
            if !alerts.iter().any(|a| a.tag == o.tag && a.kind == o.kind) {
                out.push(("ok", format!("Ядро: метка {} больше не растёт", o.tag)));
            }
        }
        self.alerts = alerts;
        out
    }

    fn find_alerts(&self) -> Vec<PoolAlert> {
        let mut out = Vec::new();
        let toke = self.last.get(&tag_id("Toke")).copied().unwrap_or_default();
        if toke.count() >= TOKENS_HIGH {
            let rate = self.series.get(&tag_id("Toke")).and_then(|s| slope(s.best(), |p| p.count)).map(|r| r.0);
            let growing = rate.filter(|&r| r >= 100.0).map(|r| format!(", прибавляется ~{} в час", thousands(r))).unwrap_or_default();
            out.push(PoolAlert {
                tag: "Toke".into(),
                level: "red".into(),
                kind: "tokens".into(),
                text: format!(
                    "накопилось {} токенов безопасности ({}){growing}. Обычно их несколько тысяч: какая-то программа или драйвер не освобождает ссылки. Чаще всего виновата программа, которая запускает процессы каждые несколько секунд. Освободит перезагрузка.",
                    thousands(toke.count() as f64),
                    mb(toke.bytes() as f64)
                ),
            });
        }
        if self.zombie_procs >= ZOMBIE_PROCS_HIGH {
            out.push(PoolAlert {
                tag: "Proc".into(),
                level: "yel".into(),
                kind: "zombie_procs".into(),
                text: format!("{} завершённых процессов всё ещё в памяти — какая-то программа держит на них дескрипторы", thousands(self.zombie_procs as f64)),
            });
        }
        if self.zombie_threads >= ZOMBIE_THREADS_HIGH {
            out.push(PoolAlert {
                tag: "Thre".into(),
                level: "yel".into(),
                kind: "zombie_threads".into(),
                text: format!("{} завершённых потоков всё ещё в памяти — какая-то программа держит на них дескрипторы", thousands(self.zombie_threads as f64)),
            });
        }
        for (&tag, s) in &self.series {
            let name = tag_str(tag);
            if name == "Toke" && out.iter().any(|a| a.kind == "tokens") {
                continue;
            }
            // метки файлового кэша растут вместе с чтением файлов (индексатор, сборка, антивирус)
            // и освобождаются сами — тревога только если рост идёт полсуток и набрал много
            let cache = is_cache_tag(&name);
            // медленная утечка: 3+ часа почти без спадов, +1 МБ/ч и больше
            let slow = s.coarse.len() >= if cache { 73 } else { 19 } && ups(&s.coarse, |p| p.bytes) >= 0.85;
            // быстрая: полчаса почти без спадов и уже +50 МБ
            let fast = !cache && s.fine.len() >= 31 && ups(&s.fine, |p| p.bytes) >= 0.9;
            let pts = if slow { &s.coarse } else { &s.fine };
            let grown = pts.back().map_or(0, |b| b.bytes.saturating_sub(pts[0].bytes));
            let Some((rate, span)) = slope(pts, |p| p.bytes) else { continue };
            let leak = (slow && rate >= (1 << 20) as f64 && grown >= if cache { 200 << 20 } else { 5 << 20 }) || (fast && grown >= 50 << 20);
            if !leak {
                continue;
            }
            let now = pts.back().map_or(0, |b| b.bytes) as f64;
            let what = about(&name).map(|a| format!(" ({})", a.split(" — ").next().unwrap_or(a).to_lowercase())).unwrap_or_default();
            out.push(PoolAlert {
                tag: name.clone(),
                level: if rate >= (20 << 20) as f64 || now >= (300 << 20) as f64 { "red" } else { "yel" }.into(),
                kind: "leak".into(),
                text: format!("метка {name}{what} растёт без остановки уже {}: +{}/ч, сейчас {} — похоже на утечку в драйвере", span_text(span), mb(rate), mb(now)),
            });
        }
        out.sort_by(|a, b| (a.level != "red").cmp(&(b.level != "red")).then(a.tag.cmp(&b.tag)));
        out
    }

    pub fn alerts(&self) -> &[PoolAlert] {
        &self.alerts
    }

    /// Отчёт: `n` меток по размеру (`by` = "size") или по росту ("growth"), плюс все с тревогой.
    pub fn report(&self, n: usize, by: &str) -> PoolReport {
        let owners = owners().lock().unwrap();
        let mut tags: Vec<TagReport> = self
            .last
            .iter()
            .map(|(&tag, r)| {
                let name = tag_str(tag);
                let s = self.series.get(&tag);
                let pts = s.map(Series::best);
                let rate = pts.and_then(|p| slope(p, |x| x.bytes));
                let count_rate = pts.and_then(|p| slope(p, |x| x.count)).map(|r| r.0);
                let (spark, step) = match pts {
                    Some(p) if p.len() >= 2 => (p.iter().map(|x| x.bytes).collect(), if std::ptr::eq(p, &s.unwrap().coarse) { COARSE_EVERY } else { FINE_EVERY }),
                    _ => (Vec::new(), 0),
                };
                TagReport {
                    alert: self.alerts.iter().any(|a| a.tag == name),
                    about: about(&name).map(str::to_string),
                    paged: r.paged,
                    nonpaged: r.nonpaged,
                    count: r.count(),
                    rate: rate.map(|r| r.0),
                    count_rate,
                    rate_window_ms: rate.map_or(0, |r| r.1),
                    spark,
                    spark_step_ms: step,
                    owners: owners.map.get(&tag).cloned().unwrap_or_default(),
                    tag: name,
                }
            })
            .collect();
        let size = |t: &TagReport| t.paged + t.nonpaged;
        if by == "growth" {
            tags.sort_by(|a, b| b.rate.unwrap_or(f64::MIN).total_cmp(&a.rate.unwrap_or(f64::MIN)).then(size(b).cmp(&size(a))));
        } else {
            tags.sort_by(|a, b| size(b).cmp(&size(a)));
        }
        let mut out: Vec<TagReport> = Vec::with_capacity(n + self.alerts.len());
        let mut rest = Vec::new();
        for (i, t) in tags.into_iter().enumerate() {
            if i < n || t.alert {
                out.push(t);
            } else {
                rest.push(t);
            }
        }
        PoolReport {
            at_ms: self.at_ms,
            watching_ms: self.at_ms.saturating_sub(self.started_ms),
            paged: self.last.values().map(|r| r.paged).sum(),
            nonpaged: self.last.values().map(|r| r.nonpaged).sum(),
            tags: out,
            alerts: self.alerts.clone(),
            zombie_procs: self.zombie_procs,
            zombie_threads: self.zombie_threads,
            owners: owners.status.clone(),
            error: self.error.clone(),
        }
    }

    /// Метки, за которыми следим (для поиска драйверов).
    pub fn tracked(&self) -> Vec<u32> {
        self.series.keys().copied().collect()
    }
}

// ───────────────────────────── чья метка ─────────────────────────────

#[derive(Default)]
struct Owners {
    status: OwnersStatus,
    map: HashMap<u32, Vec<String>>,
}

fn owners() -> &'static Mutex<Owners> {
    static O: OnceLock<Mutex<Owners>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(Owners { status: OwnersStatus { state: "idle".into(), ..Default::default() }, map: HashMap::new() }))
}

pub fn owners_status() -> OwnersStatus {
    owners().lock().unwrap().status.clone()
}

/// Загруженные драйверы: пути к файлам. Адреса без прав администратора скрыты, но имена видны.
pub fn loaded_drivers() -> Vec<std::path::PathBuf> {
    let Ok(b) = crate::nt::query_system(CLASS_MODULES, 128 << 10) else { return Vec::new() };
    let n = rd32(&b, 0) as usize;
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut out = Vec::new();
    for i in 0..n {
        let o = 8 + i * 296;
        if o + 296 > b.len() {
            break;
        }
        let raw = &b[o + 40..o + 296];
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        let p = String::from_utf8_lossy(&raw[..end]).to_string();
        let lower = p.to_ascii_lowercase();
        let path = if lower.starts_with(r"\systemroot\") {
            format!("{root}{}", &p[r"\SystemRoot".len()..])
        } else if let Some(rest) = p.strip_prefix(r"\??\") {
            rest.to_string()
        } else if lower.starts_with(r"\windows\") {
            format!("{}{}", &root[..2], p)
        } else if !p.contains(':') {
            format!(r"{root}\{}", p.trim_start_matches('\\'))
        } else {
            p
        };
        out.push(std::path::PathBuf::from(path));
    }
    out
}

/// Какие из меток встречаются в файле. В коде метка — непосредственный операнд команды
/// (`mov r8d, 'ekoT'`), вокруг неё байты команд; совпадение посреди текста («Token» в строке)
/// не считается — иначе метку `Toke` «выделял» бы любой драйвер со словом Token.
fn tags_in(data: &[u8], want: &HashSet<u32>, first: &[bool; 256]) -> HashSet<u32> {
    let text = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b' ';
    let mut hit = HashSet::new();
    for i in 0..data.len().saturating_sub(3) {
        if !first[data[i] as usize] {
            continue;
        }
        let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if !want.contains(&v) || hit.contains(&v) {
            continue;
        }
        let before = i.checked_sub(1).map(|j| data[j]);
        let after = data.get(i + 4).copied();
        if before.is_some_and(text) && after.is_some_and(text) {
            continue;
        }
        hit.insert(v);
    }
    hit
}

/// Ищет метки в файлах загруженных драйверов — в фоне, с низким приоритетом диска.
/// Совпадение значит, что драйвер (скорее всего) выделяет память с этой меткой.
pub fn start_owner_scan(tags: Vec<u32>) -> OwnersStatus {
    {
        let mut o = owners().lock().unwrap();
        if o.status.state == "running" {
            return o.status.clone();
        }
        o.status = OwnersStatus { state: "running".into(), ..Default::default() };
    }
    let spawned = std::thread::Builder::new().name("tm-pool-owners".into()).spawn(move || {
        use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN};
        unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) };
        scan_owners(&tags, |scanned, total| {
            let mut o = owners().lock().unwrap();
            o.status.scanned = scanned;
            o.status.total = total;
        });
    });
    if let Err(e) = spawned {
        let mut o = owners().lock().unwrap();
        o.status = OwnersStatus { state: "idle".into(), error: Some(e.to_string()), ..Default::default() };
    }
    owners_status()
}

/// То же синхронно (для CLI). Результат попадает в общий кэш и в отчёты.
pub fn scan_owners(tags: &[u32], progress: impl Fn(usize, usize)) {
    let files = loaded_drivers();
    let want: HashSet<u32> = tags.iter().copied().collect();
    let mut first = [false; 256];
    for t in &want {
        first[(t & 0xff) as usize] = true;
    }
    let mut found: HashMap<u32, Vec<String>> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        progress(i, files.len());
        let Ok(data) = std::fs::read(f) else { continue };
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for t in tags_in(&data, &want, &first) {
            found.entry(t).or_default().push(name.clone());
        }
    }
    // не нашли среди загруженных — ищем в остальных драйверах системы: выгруженный драйвер,
    // который не вернул память, оставляет свою метку в пуле до перезагрузки
    let missing: HashSet<u32> = want.iter().copied().filter(|t| !found.contains_key(t)).collect();
    if !missing.is_empty() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let loaded: HashSet<String> = files.iter().filter_map(|f| f.file_name()).map(|n| n.to_string_lossy().to_ascii_lowercase()).collect();
        let rest: Vec<std::path::PathBuf> = std::fs::read_dir(format!(r"{root}\System32\drivers"))
            .map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter(|p| {
                let n = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                n.ends_with(".sys") && !loaded.contains(&n)
            })
            .collect();
        let mut first = [false; 256];
        for t in &missing {
            first[(t & 0xff) as usize] = true;
        }
        for (i, f) in rest.iter().enumerate() {
            progress(files.len() + i, files.len() + rest.len());
            let Ok(data) = std::fs::read(f) else { continue };
            let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            for t in tags_in(&data, &missing, &first) {
                found.entry(t).or_default().push(format!("{name} (не загружен)"));
            }
        }
    }
    // ядро — первым: его метки встречаются и в драйверах, которые лишь вызывают его функции
    for v in found.values_mut() {
        v.sort_by_key(|n| (!n.eq_ignore_ascii_case("ntoskrnl.exe"), n.to_ascii_lowercase()));
    }
    let mut o = owners().lock().unwrap();
    for t in tags {
        o.map.insert(*t, found.remove(t).unwrap_or_default());
    }
    o.status = OwnersStatus { state: "done".into(), scanned: files.len(), total: files.len(), error: None };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip() {
        assert_eq!(tag_str(tag_id("Toke")), "Toke");
        assert_eq!(tag_str(tag_id("Key")), "Key");
        assert_eq!(tag_id("Toke"), 0x656B_6F54);
    }

    #[test]
    fn tag_in_code_not_in_text() {
        let want: HashSet<u32> = [tag_id("Toke")].into_iter().collect();
        let mut first = [false; 256];
        first[b'T' as usize] = true;
        // строка «Token» в данных — не метка
        assert!(tags_in(b"\x00GetTokenInformation\x00", &want, &first).is_empty());
        // mov r8d, 'ekoT' — метка
        assert_eq!(tags_in(b"\x41\xB8Toke\x48\x8B", &want, &first).len(), 1);
    }

    #[test]
    fn slope_per_hour() {
        let pts: VecDeque<Pt> = (0..31).map(|i| Pt { t: i * 60_000, bytes: 1000 + i * 100, count: i }).collect();
        let (r, span) = slope(&pts, |p| p.bytes).unwrap();
        assert!((r - 6000.0).abs() < 1e-6, "{r}");
        assert_eq!(span, 30 * 60_000);
    }

    #[test]
    fn detects_token_pileup() {
        let mut w = PoolWatch::default();
        let mut raw = HashMap::new();
        raw.insert(tag_id("Toke"), Raw { paged: 190 << 20, paged_live: 87_000, ..Default::default() });
        let ev = w.ingest(1_000, Ok(raw), 500, 9_000);
        assert_eq!(w.alerts().len(), 1);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].1.contains("87"));
    }

    #[test]
    fn file_cache_growth_is_not_a_leak() {
        let mut w = PoolWatch::default();
        for i in 0..=40u64 {
            let mut raw = HashMap::new();
            raw.insert(tag_id("MmSt"), Raw { paged: (20 << 20) + i * (3 << 20), ..Default::default() });
            raw.insert(tag_id("Xdrv"), Raw { nonpaged: (20 << 20) + i * (3 << 20), ..Default::default() });
            w.ingest(i * FINE_EVERY, Ok(raw), 300, 3_000);
        }
        let tags: Vec<_> = w.alerts().iter().map(|a| a.tag.as_str()).collect();
        assert_eq!(tags, ["Xdrv"]);
        assert!(w.alerts()[0].text.contains("40 мин"), "{}", w.alerts()[0].text);
    }
}
