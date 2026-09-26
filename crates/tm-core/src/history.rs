//! История нагрузки за 24 часа в кольцевых буферах фиксированной ёмкости.
//!
//! Три уровня детализации: 1 с за 15 мин, 10 с за 3 ч, 1 мин за 24 ч.
//! Память ограничена сверху: буферы не растут больше ёмкости, а следы исчезнувших
//! процессов и приложений удаляются, как только выходят за окно хранения.
//!
//! Процессов за сутки набегают тысячи, поэтому подробно (посекундно) храним только
//! последние 5 минут, а в крупных ячейках — лишь лидеров по ЦП, памяти и диску.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::sampler::ProcKey;

#[derive(Clone, Copy)]
pub struct Tier {
    pub step_ms: u64,
    pub cap: usize,
}

pub const TIERS: [Tier; 3] = [
    Tier { step_ms: 1_000, cap: 900 },
    Tier { step_ms: 10_000, cap: 1_080 },
    Tier { step_ms: 60_000, cap: 1_440 },
];
/// Ключи видеокарт в наборе устройств (там же, где сетевые адаптеры).
pub const GPU_PREFIX: &str = "gpu:";
/// Посекундная история процессов: 5 минут.
pub const PROC_T0_CAP: usize = 300;
/// Сколько лидеров по каждой метрике сохраняется в крупной ячейке.
pub const PROC_TOP_K: usize = 12;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Pt {
    pub cpu: f32,
    /// Пик ЦП внутри ячейки (в крупных ячейках среднее прячет всплески).
    pub cpu_max: f32,
    /// Загрузка видеокарты, % (самый занятый движок).
    pub gpu: f32,
    pub mem: u64,
    pub rd: f32,
    pub wr: f32,
}

impl Pt {
    fn metric(&self, m: Metric) -> f64 {
        match m {
            Metric::Cpu => self.cpu as f64,
            Metric::Gpu => self.gpu as f64,
            Metric::Mem => self.mem as f64,
            Metric::Io => (self.rd + self.wr) as f64,
            Metric::Read => self.rd as f64,
            Metric::Write => self.wr as f64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    System,
    Apps,
    Procs,
    /// Сетевые адаптеры: rd — приём, wr — отправка (байт/с).
    Net,
    /// Видеокарты: gpu — загрузка, mem — занятая видеопамять.
    Gpu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Metric {
    Cpu,
    Mem,
    /// Чтение + запись (для сети — приём + отправка).
    Io,
    /// Только чтение (для сети — приём).
    Read,
    /// Только запись (для сети — отправка).
    Write,
    /// Загрузка видеокарты, %.
    Gpu,
}

// ───────────────────────────── кирпичики ─────────────────────────────

/// Сумма замеров внутри крупной ячейки. Делится на число замеров ячейки в целом,
/// поэтому отсутствие приложения в части замеров честно считается нулём.
#[derive(Clone, Copy, Default)]
struct Acc {
    cpu: f64,
    cpu_max: f32,
    gpu: f64,
    mem: f64,
    rd: f64,
    wr: f64,
    touched: bool,
}

impl Acc {
    fn add(&mut self, p: Pt) {
        self.cpu += p.cpu as f64;
        self.cpu_max = self.cpu_max.max(p.cpu_max.max(p.cpu));
        self.gpu += p.gpu as f64;
        self.mem += p.mem as f64;
        self.rd += p.rd as f64;
        self.wr += p.wr as f64;
        self.touched = true;
    }
    fn avg(&self, n: u32) -> Pt {
        let n = n.max(1) as f64;
        Pt {
            cpu: (self.cpu / n) as f32,
            cpu_max: self.cpu_max,
            gpu: (self.gpu / n) as f32,
            mem: (self.mem / n) as u64,
            rd: (self.rd / n) as f32,
            wr: (self.wr / n) as f32,
        }
    }
}

/// Кольцо значений, привязанных к номерам ячеек (slot = время / шаг).
/// Пропущенные ячейки — нули; ёмкость не превышается никогда.
struct Ring {
    vals: VecDeque<Pt>,
    last: u64,
    cap: usize,
}

impl Ring {
    fn new(cap: usize) -> Self {
        Self { vals: VecDeque::new(), last: 0, cap }
    }
    fn put(&mut self, slot: u64, p: Pt) {
        if !self.vals.is_empty() {
            if slot <= self.last {
                if slot == self.last {
                    *self.vals.back_mut().unwrap() = p;
                }
                return;
            }
            let gap = slot - self.last - 1;
            if gap as usize >= self.cap {
                self.vals.clear();
            } else {
                self.vals.extend(std::iter::repeat(Pt::default()).take(gap as usize));
            }
        }
        self.vals.push_back(p);
        self.last = slot;
        while self.vals.len() > self.cap {
            self.vals.pop_front();
        }
    }
    fn get(&self, slot: u64) -> Pt {
        if self.vals.is_empty() || slot > self.last {
            return Pt::default();
        }
        let back = (self.last - slot) as usize;
        if back >= self.vals.len() {
            return Pt::default();
        }
        self.vals[self.vals.len() - 1 - back]
    }
}

struct Track {
    title: String,
    pid: Option<u32>,
    rings: [Ring; 3],
    accs: [Acc; 3], // [0] не используется: первый уровень пишется напрямую
    last_seen: u64,
}

impl Track {
    fn new(t0_cap: usize) -> Self {
        Self {
            title: String::new(),
            pid: None,
            rings: [Ring::new(t0_cap), Ring::new(TIERS[1].cap), Ring::new(TIERS[2].cap)],
            accs: [Acc::default(); 3],
            last_seen: 0,
        }
    }
}

#[derive(Clone)]
struct TopEntry {
    key: ProcKey,
    name: String,
    pt: Pt,
}

// ───────────────────────────── входные данные ─────────────────────────────

pub struct AppSample<'a> {
    pub key: &'a str,
    pub title: &'a str,
    pub pid: u32,
    pub pt: Pt,
}

pub struct ProcSample<'a> {
    pub key: ProcKey,
    pub name: &'a str,
    pub pt: Pt,
}

// ───────────────────────────── история ─────────────────────────────

pub struct History {
    sys: Track,
    apps: HashMap<String, Track>,
    nets: HashMap<String, Track>,
    /// У процессов используются только rings[0] и accs[1..]: крупные уровни — в `proc_top`.
    procs: HashMap<ProcKey, Track>,
    proc_top: [VecDeque<(u64, Vec<TopEntry>)>; 3],
    /// Номер текущей (ещё не закрытой) крупной ячейки и число замеров в ней.
    bucket: [Option<u64>; 3],
    n: [u32; 3],
    now: u64,
    /// Время первого замера: до него данных нет, и средние по диапазону считаются без этой части.
    first: Option<u64>,
}

impl Default for History {
    fn default() -> Self {
        Self {
            sys: Track::new(TIERS[0].cap),
            apps: HashMap::new(),
            nets: HashMap::new(),
            procs: HashMap::new(),
            proc_top: Default::default(),
            bucket: [None; 3],
            n: [0; 3],
            now: 0,
            first: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub apps: usize,
    pub procs: usize,
    pub points: usize,
}

impl History {
    /// Добавляет один замер. `t_ms` — монотонно растущее время (мс Unix).
    pub fn push(&mut self, t_ms: u64, sys: Pt, apps: &[AppSample], nets: &[AppSample], procs: &[ProcSample]) {
        for k in 1..3 {
            let slot = t_ms / TIERS[k].step_ms;
            if let Some(b) = self.bucket[k] {
                if b != slot {
                    self.flush(k, b);
                }
            }
            self.bucket[k] = Some(slot);
            self.n[k] += 1;
        }
        self.now = t_ms;
        self.first.get_or_insert(t_ms);
        let s0 = t_ms / TIERS[0].step_ms;

        let put = |tr: &mut Track, pt: Pt| {
            tr.rings[0].put(s0, pt);
            tr.accs[1].add(pt);
            tr.accs[2].add(pt);
            tr.last_seen = t_ms;
        };
        put(&mut self.sys, sys);
        for a in apps {
            let tr = self.apps.entry(a.key.to_string()).or_insert_with(|| Track::new(TIERS[0].cap));
            if tr.title != a.title {
                tr.title = a.title.to_string();
            }
            tr.pid = Some(a.pid);
            put(tr, a.pt);
        }
        for a in nets {
            let tr = self.nets.entry(a.key.to_string()).or_insert_with(|| Track::new(TIERS[0].cap));
            if tr.title != a.title {
                tr.title = a.title.to_string();
            }
            put(tr, a.pt);
        }
        for p in procs {
            let tr = self.procs.entry(p.key).or_insert_with(|| {
                let mut t = Track::new(PROC_T0_CAP);
                t.rings[1] = Ring::new(0);
                t.rings[2] = Ring::new(0);
                t.title = p.name.to_string();
                t.pid = Some(p.key.0);
                t
            });
            put(tr, p.pt);
        }

        // уборка: приложения живут в истории сутки, процессы — пока видны в посекундном окне
        let day = TIERS[2].step_ms * TIERS[2].cap as u64;
        self.apps.retain(|_, t| t_ms.saturating_sub(t.last_seen) <= day);
        self.nets.retain(|_, t| t_ms.saturating_sub(t.last_seen) <= day);
        let proc_keep = TIERS[0].step_ms * PROC_T0_CAP as u64;
        self.procs
            .retain(|_, t| t_ms.saturating_sub(t.last_seen) <= proc_keep || t.accs[1].touched || t.accs[2].touched);
    }

    fn flush(&mut self, k: usize, slot: u64) {
        let n = self.n[k];
        let mut close = |tr: &mut Track| {
            if tr.accs[k].touched {
                let pt = tr.accs[k].avg(n);
                tr.rings[k].put(slot, pt);
                tr.accs[k] = Acc::default();
            }
        };
        close(&mut self.sys);
        self.apps.values_mut().for_each(&mut close);
        self.nets.values_mut().for_each(&mut close);

        let mut all: Vec<TopEntry> = Vec::new();
        for (key, tr) in self.procs.iter_mut() {
            if tr.accs[k].touched {
                all.push(TopEntry { key: *key, name: tr.title.clone(), pt: tr.accs[k].avg(n) });
                tr.accs[k] = Acc::default();
            }
        }
        let mut keep: HashSet<ProcKey> = HashSet::new();
        for m in [Metric::Cpu, Metric::Mem, Metric::Io, Metric::Gpu] {
            all.sort_by(|a, b| b.pt.metric(m).total_cmp(&a.pt.metric(m)));
            keep.extend(all.iter().take(PROC_TOP_K).filter(|e| e.pt.metric(m) > 0.0).map(|e| e.key));
        }
        all.retain(|e| keep.contains(&e.key));
        let q = &mut self.proc_top[k];
        q.push_back((slot, all));
        while q.front().is_some_and(|(s, _)| s + (TIERS[k].cap as u64) <= slot) {
            q.pop_front();
        }
        self.n[k] = 0;
    }

    /// Время первого замера в истории (с учётом восстановленной с диска), мс Unix.
    pub fn first_ms(&self) -> Option<u64> {
        self.first
    }

    /// Посекундный ряд (до 5 мин) суммы нескольких процессов — процесс вместе с дочерними.
    /// Последний элемент — самый свежий замер.
    pub fn procs_t0(&self, keys: &[ProcKey], m: Metric, points: usize) -> Vec<f64> {
        let points = points.clamp(1, PROC_T0_CAP);
        let end = self.now / TIERS[0].step_ms;
        let start = (end + 1).saturating_sub(points as u64);
        let mut out = vec![0.0; (end + 1 - start) as usize];
        for k in keys {
            if let Some(tr) = self.procs.get(k) {
                for (i, s) in (start..=end).enumerate() {
                    out[i] += tr.rings[0].get(s).metric(m);
                }
            }
        }
        out
    }

    pub fn stats(&self) -> Stats {
        let rings = |t: &Track| t.rings.iter().map(|r| r.vals.len()).sum::<usize>();
        Stats {
            apps: self.apps.len(),
            procs: self.procs.len(),
            points: rings(&self.sys)
                + self.apps.values().map(rings).sum::<usize>()
                + self.procs.values().map(rings).sum::<usize>()
                + self.proc_top.iter().flat_map(|q| q.iter().map(|(_, v)| v.len())).sum::<usize>(),
        }
    }

    // ───────────────────────────── запросы ─────────────────────────────

    /// Значение трека в ячейке: закрытые ячейки из кольца, текущая — из накопителя.
    fn value(&self, tr: &Track, k: usize, slot: u64) -> Pt {
        if k > 0 && Some(slot) == self.bucket[k] {
            return if tr.accs[k].touched { tr.accs[k].avg(self.n[k]) } else { Pt::default() };
        }
        tr.rings[k].get(slot)
    }

    pub fn query(&self, q: &Query) -> HistoryResult {
        let t0_cap = if q.scope == Scope::Procs { PROC_T0_CAP } else { TIERS[0].cap };
        let k = if q.range_ms <= TIERS[0].step_ms * t0_cap as u64 {
            0
        } else if q.range_ms <= TIERS[1].step_ms * TIERS[1].cap as u64 {
            1
        } else {
            2
        };
        let tier = TIERS[k];
        let cap = if k == 0 { t0_cap } else { tier.cap };
        let end = if k == 0 { self.now / tier.step_ms } else { self.bucket[k].unwrap_or(self.now / tier.step_ms) };
        let points = ((q.range_ms / tier.step_ms).max(1) as usize).min(cap).min(end as usize + 1);
        let start = end + 1 - points as u64;
        let slots = start..=end;
        let m = q.by;
        // ячейки до первого замера — «нет данных», а не нули: в среднее не входят
        let skip = (self.first.unwrap_or(self.now) / tier.step_ms).saturating_sub(start).min(points as u64 - 1) as usize;

        let series_of = |key: String, title: String, pid: Option<u32>, vals: Vec<f64>, peaks: Option<Vec<f64>>| {
            let covered = &vals[skip.min(vals.len())..];
            let avg = covered.iter().sum::<f64>() / covered.len().max(1) as f64;
            let peak = peaks.unwrap_or_else(|| vals.clone()).into_iter().fold(0.0, f64::max);
            Series { key, title, pid, avg, peak, values: vals }
        };
        let track_series = |key: String, tr: &Track| {
            let pts: Vec<Pt> = slots.clone().map(|s| self.value(tr, k, s)).collect();
            let peaks = (m == Metric::Cpu).then(|| pts.iter().map(|p| p.cpu_max.max(p.cpu) as f64).collect());
            series_of(key, tr.title.clone(), tr.pid, pts.iter().map(|p| p.metric(m)).collect(), peaks)
        };

        let mut total = track_series("total".into(), &self.sys);
        let mut list: Vec<Series> = match q.scope {
            Scope::System => Vec::new(),
            // видеокарты хранятся в том же наборе устройств, что и сеть, с ключами «gpu:…»
            Scope::Net | Scope::Gpu => {
                let gpu = q.scope == Scope::Gpu;
                let list: Vec<Series> = self
                    .nets
                    .iter()
                    .filter(|(key, _)| key.starts_with(GPU_PREFIX) == gpu)
                    .map(|(key, tr)| track_series(key.clone(), tr))
                    .collect();
                let vals: Vec<f64> = (0..points)
                    .map(|i| if gpu { list.iter().map(|s| s.values[i]).fold(0.0, f64::max) } else { list.iter().map(|s| s.values[i]).sum() })
                    .collect();
                total = series_of("total".into(), if gpu { "Все видеокарты" } else { "Все адаптеры" }.into(), None, vals, None);
                list
            }
            Scope::Apps => self.apps.iter().map(|(key, tr)| track_series(key.clone(), tr)).collect(),
            Scope::Procs if k == 0 => self
                .procs
                .iter()
                .map(|(key, tr)| {
                    let mut s = track_series(crate::sampler::key_str(*key), tr);
                    s.title = format!("{} ({})", tr.title, key.0);
                    s
                })
                .collect(),
            Scope::Procs => {
                // крупные уровни: только лидеры каждой ячейки, остальное неизвестно (0)
                let mut by: HashMap<ProcKey, (String, Vec<f64>)> = HashMap::new();
                let n = points;
                for (slot, entries) in &self.proc_top[k] {
                    if *slot < start || *slot > end {
                        continue;
                    }
                    for e in entries {
                        let row = by.entry(e.key).or_insert_with(|| (e.name.clone(), vec![0.0; n]));
                        row.1[(slot - start) as usize] = e.pt.metric(m);
                    }
                }
                if let Some(cur) = self.bucket[k] {
                    for (key, tr) in &self.procs {
                        if cur >= start && tr.accs[k].touched {
                            let row = by.entry(*key).or_insert_with(|| (tr.title.clone(), vec![0.0; n]));
                            row.1[(cur - start) as usize] = tr.accs[k].avg(self.n[k]).metric(m);
                        }
                    }
                }
                by.into_iter()
                    .map(|(key, (name, vals))| series_of(crate::sampler::key_str(key), format!("{name} ({})", key.0), Some(key.0), vals, None))
                    .collect()
            }
        };
        if !q.keys.is_empty() {
            list.retain(|s| q.keys.contains(&s.key));
        }
        list.retain(|s| s.avg > 0.0 || s.peak > 0.0);
        list.sort_by(|a, b| b.avg.total_cmp(&a.avg));
        let rest = if list.len() > q.top { list.split_off(q.top) } else { Vec::new() };
        let other = (!rest.is_empty() && !(q.scope == Scope::Procs && k > 0)).then(|| {
            let vals: Vec<f64> = (0..points).map(|i| rest.iter().map(|s| s.values[i]).sum()).collect();
            series_of("other".into(), format!("Остальные ({})", rest.len()), None, vals, None)
        });

        HistoryResult {
            scope: q.scope,
            by: m,
            step_ms: tier.step_ms,
            start_ms: start * tier.step_ms,
            points,
            missing: skip,
            total,
            series: list,
            other,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    pub scope: Scope,
    pub range_ms: u64,
    pub by: Metric,
    pub top: usize,
    /// Если не пусто — только эти ключи (приложения, адаптеры или «pid:время» процессов).
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Series {
    pub key: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pid: Option<u32>,
    pub avg: f64,
    pub peak: f64,
    pub values: Vec<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryResult {
    pub scope: Scope,
    pub by: Metric,
    pub step_ms: u64,
    /// Время начала первой ячейки, мс Unix.
    pub start_ms: u64,
    pub points: usize,
    /// Сколько первых ячеек диапазона приходится на время до запуска движка (данных нет).
    #[serde(default)]
    pub missing: usize,
    pub total: Series,
    pub series: Vec<Series>,
    #[serde(default)]
    pub other: Option<Series>,
}

// ───────────────────────────── сохранение на диск ─────────────────────────────
//
// Сохраняются только крупные уровни (10 с и 1 мин): посекундные 15 минут не стоят записи на диск.
// Точка занимает 18 байт: ЦП, пик ЦП и видеокарта в сотых долях процента (u16), память в КБ (u32), диск f32.
// Формат версионирован; незнакомую или повреждённую версию просто пропускаем.

const MAGIC: &[u8; 4] = b"TMH3";
/// Предыдущая версия (без видеокарты) — читается, чтобы не потерять собранную историю.
const MAGIC_V2: &[u8; 4] = b"TMH2";

struct W<'a>(&'a mut Vec<u8>);
impl W<'_> {
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn f32(&mut self, v: f32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
    fn pt(&mut self, p: &Pt) {
        self.u16((p.cpu * 100.0).round().clamp(0.0, 65535.0) as u16);
        self.u16((p.cpu_max * 100.0).round().clamp(0.0, 65535.0) as u16);
        self.u16((p.gpu * 100.0).round().clamp(0.0, 65535.0) as u16);
        self.u32((p.mem / 1024).min(u32::MAX as u64) as u32);
        self.f32(p.rd);
        self.f32(p.wr);
    }
    fn ring(&mut self, r: &Ring) {
        self.u64(r.last);
        self.u32(r.vals.len() as u32);
        r.vals.iter().for_each(|p| self.pt(p));
    }
}

/// Второе поле — есть ли в точках видеокарта (формат TMH3).
struct R<'a>(&'a [u8], bool);
impl R<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn f32(&mut self) -> Option<f32> {
        Some(f32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn str(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    fn pt(&mut self) -> Option<Pt> {
        Some(Pt {
            cpu: self.u16()? as f32 / 100.0,
            cpu_max: self.u16()? as f32 / 100.0,
            gpu: if self.1 { self.u16()? as f32 / 100.0 } else { 0.0 },
            mem: self.u32()? as u64 * 1024,
            rd: self.f32()?,
            wr: self.f32()?,
        })
    }
    fn ring(&mut self, cap: usize) -> Option<Ring> {
        let last = self.u64()?;
        let n = self.u32()? as usize;
        if n > cap {
            return None;
        }
        let mut r = Ring::new(cap);
        r.last = last;
        for _ in 0..n {
            r.vals.push_back(self.pt()?);
        }
        Some(r)
    }
}

impl History {
    /// Двоичный снимок истории для записи на диск (несколько МБ максимум, обычно меньше).
    pub fn save(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 * 1024);
        let mut w = W(&mut buf);
        w.0.extend_from_slice(MAGIC);
        w.u64(self.now);
        w.u64(self.first.unwrap_or(0));
        let track = |w: &mut W, t: &Track| {
            w.str(&t.title);
            w.u32(t.pid.unwrap_or(0));
            w.u64(t.last_seen);
            w.ring(&t.rings[1]);
            w.ring(&t.rings[2]);
        };
        track(&mut w, &self.sys);
        for map in [&self.apps, &self.nets] {
            w.u32(map.len() as u32);
            for (key, t) in map {
                w.str(key);
                track(&mut w, t);
            }
        }
        for k in 1..3 {
            w.u32(self.proc_top[k].len() as u32);
            for (slot, entries) in &self.proc_top[k] {
                w.u64(*slot);
                w.u32(entries.len() as u32);
                for e in entries {
                    w.u32(e.key.0);
                    w.u64(e.key.1 as u64);
                    w.str(&e.name);
                    w.pt(&e.pt);
                }
            }
        }
        buf
    }

    /// Восстанавливает историю из снимка. `None` — файл чужой версии или повреждён.
    pub fn load(data: &[u8]) -> Option<Self> {
        let mut r = R(data, true);
        match r.take(4)? {
            m if m == MAGIC => {}
            m if m == MAGIC_V2 => r.1 = false,
            _ => return None,
        }
        let mut h = History { now: r.u64()?, ..Default::default() };
        let first = r.u64()?;
        h.first = (first > 0).then_some(first);
        let track = |r: &mut R, t0_cap: usize| -> Option<Track> {
            let mut t = Track::new(t0_cap);
            t.title = r.str()?;
            let pid = r.u32()?;
            t.pid = (pid > 0).then_some(pid);
            t.last_seen = r.u64()?;
            t.rings[1] = r.ring(TIERS[1].cap)?;
            t.rings[2] = r.ring(TIERS[2].cap)?;
            Some(t)
        };
        h.sys = track(&mut r, TIERS[0].cap)?;
        for _ in 0..r.u32()? {
            let key = r.str()?;
            let t = track(&mut r, TIERS[0].cap)?;
            h.apps.insert(key, t);
        }
        for _ in 0..r.u32()? {
            let key = r.str()?;
            let t = track(&mut r, TIERS[0].cap)?;
            h.nets.insert(key, t);
        }
        for k in 1..3 {
            for _ in 0..r.u32()? {
                let slot = r.u64()?;
                let n = r.u32()? as usize;
                let mut entries = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    let pid = r.u32()?;
                    let ct = r.u64()? as i64;
                    entries.push(TopEntry { key: (pid, ct), name: r.str()?, pt: r.pt()? });
                }
                h.proc_top[k].push_back((slot, entries));
            }
        }
        Some(h)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn pt(cpu: f32) -> Pt {
        Pt { cpu, cpu_max: cpu, gpu: 0.0, mem: 100, rd: 0.0, wr: 0.0 }
    }

    #[test]
    fn ring_caps_and_fills_gaps() {
        let mut r = Ring::new(3);
        r.put(10, pt(1.0));
        r.put(12, pt(3.0));
        assert_eq!(r.get(11).cpu, 0.0);
        assert_eq!(r.get(12).cpu, 3.0);
        r.put(14, pt(5.0));
        assert_eq!(r.vals.len(), 3);
        assert_eq!(r.get(10).cpu, 0.0); // вытеснено
        r.put(100, pt(9.0));
        assert_eq!(r.vals.len(), 1);
    }

    #[test]
    fn absent_samples_count_as_zero() {
        let mut h = History::default();
        let app = |c| [AppSample { key: "a", title: "A", pid: 1, pt: pt(c) }];
        // 10 замеров в одной 10-секундной ячейке, приложение есть только в одном
        for i in 0..10u64 {
            let apps: &[AppSample] = if i == 0 { &app(50.0) } else { &[] };
            h.push(1_000_000 + i * 1000, pt(10.0), apps, &[], &[]);
        }
        h.push(1_010_000, pt(10.0), &[], &[], &[]); // закрывает ячейку
        let tr = &h.apps["a"];
        assert!((tr.rings[1].get(100).cpu - 5.0).abs() < 1e-3);
        assert_eq!(tr.rings[1].get(100).cpu_max, 50.0);
    }

    #[test]
    fn save_load_roundtrip() {
        let mut h = History::default();
        for i in 0..200u64 {
            let procs = [ProcSample { key: (7, 42), name: "x.exe", pt: pt(12.5) }];
            h.push(1_700_000_000_000 + i * 1000, pt(30.0), &[AppSample { key: "a", title: "Приложение", pid: 5, pt: pt(20.0) }], &[AppSample { key: "eth", title: "Ethernet", pid: 0, pt: Pt { rd: 1000.0, ..pt(0.0) } }], &procs);
        }
        let bytes = h.save();
        let g = History::load(&bytes).expect("load");
        let q = Query { scope: Scope::Apps, range_ms: 3_600_000, by: Metric::Cpu, top: 5, keys: vec![] };
        let (a, b) = (h.query(&q), g.query(&q));
        assert_eq!(b.series[0].title, "Приложение");
        // закрытые 10-секундные ячейки совпадают (текущая, незакрытая, не сохраняется)
        let n = a.points - 2;
        assert!((a.series[0].values[n] - b.series[0].values[n]).abs() < 0.01);
        let qp = Query { scope: Scope::Procs, range_ms: 3_600_000, by: Metric::Cpu, top: 5, keys: vec![] };
        assert_eq!(g.query(&qp).series[0].title, "x.exe (7)");
        let qn = Query { scope: Scope::Net, range_ms: 3_600_000, by: Metric::Read, top: 5, keys: vec![] };
        assert_eq!(g.query(&qn).series[0].title, "Ethernet");
        assert_eq!(h.procs_t0(&[(7, 42)], Metric::Cpu, 10).len(), 10);
        assert!(History::load(&bytes[..bytes.len() / 2]).is_none());
        assert!(History::load(b"junk").is_none());
    }

    #[test]
    fn memory_is_bounded() {
        let mut h = History::default();
        // двое суток по секунде, каждый раз новый процесс — старые должны уходить
        for i in 0..(2 * 86_400u64) {
            let name = "p";
            let procs = [ProcSample { key: (i as u32, i as i64), name, pt: pt(1.0) }];
            h.push(i * 1000, pt(1.0), &[AppSample { key: "a", title: "A", pid: 1, pt: pt(1.0) }], &[], &procs);
        }
        let s = h.stats();
        assert!(s.procs <= PROC_T0_CAP + 61, "procs {}", s.procs);
        assert_eq!(s.apps, 1);
        assert!(s.points < 60_000, "points {}", s.points);
    }
}
