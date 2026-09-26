//! Из чего состоит память, которая занята, но не принадлежит ни одному процессу лично:
//! пулы ядра (память драйверов), файловый кэш, код ядра и драйверов, изменённые страницы.
//! Плюс списки страниц: резерв (standby), свободная, сжатая.
//! Остаток — общая память программ (DLL, общие буферы браузеров и Electron-приложений,
//! таблицы страниц): в «частную память» процессов она не входит.
//!
//! Источник — счётчики «Memory» (без прав администратора). Замер дешёвый: одно
//! обращение к PDH на все счётчики.

use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryW, PDH_FMT_COUNTERVALUE, PDH_FMT_LARGE,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemDetail {
    /// Невыгружаемый пул ядра — память драйверов, всегда в ОЗУ. Обычно 0,2–0,6 ГБ.
    pub pool_nonpaged: u64,
    /// Выгружаемый пул ядра, часть в ОЗУ.
    pub pool_paged: u64,
    /// Файловый кэш системы (его рабочий набор).
    pub cache: u64,
    /// Код ядра и драйверов в ОЗУ.
    pub kernel_code: u64,
    /// Изменённые страницы: ждут записи на диск, потом освободятся.
    pub modified: u64,
    /// Резерв (standby): кэш недавно использованных страниц. Занятой памятью не считается —
    /// Windows отдаёт его программам по первому требованию.
    #[serde(default)]
    pub standby: u64,
    /// Свободная и обнулённая память — совсем ничем не занята.
    #[serde(default)]
    pub free: u64,
    /// Сжатая память: рабочий набор процесса «Memory Compression» (заполняет движок).
    #[serde(default)]
    pub compressed: u64,
}

const COUNTERS: [&str; 10] = [
    r"\Memory\Pool Nonpaged Bytes",
    r"\Memory\Pool Paged Resident Bytes",
    r"\Memory\System Cache Resident Bytes",
    r"\Memory\System Driver Resident Bytes",
    r"\Memory\System Code Resident Bytes",
    r"\Memory\Modified Page List Bytes",
    r"\Memory\Standby Cache Core Bytes",
    r"\Memory\Standby Cache Normal Priority Bytes",
    r"\Memory\Standby Cache Reserve Bytes",
    r"\Memory\Free & Zero Page List Bytes",
];

pub struct MemSampler {
    query: isize,
    counters: Vec<isize>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl MemSampler {
    pub fn new() -> Option<Self> {
        let mut query = 0isize;
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let mut counters = Vec::new();
        for path in COUNTERS {
            let mut c = 0isize;
            // недоступный счётчик остаётся нулём, остальные работают
            let _ = unsafe { PdhAddEnglishCounterW(query, wide(path).as_ptr(), 0, &mut c) };
            counters.push(c);
        }
        Some(Self { query, counters })
    }

    pub fn sample(&mut self) -> MemDetail {
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return MemDetail::default();
        }
        let v: Vec<u64> = self
            .counters
            .iter()
            .map(|&c| {
                if c == 0 {
                    return 0;
                }
                let mut val: PDH_FMT_COUNTERVALUE = unsafe { std::mem::zeroed() };
                if unsafe { PdhGetFormattedCounterValue(c, PDH_FMT_LARGE, std::ptr::null_mut(), &mut val) } != 0 || val.CStatus > 1 {
                    return 0;
                }
                unsafe { val.Anonymous.largeValue }.max(0) as u64
            })
            .collect();
        MemDetail {
            pool_nonpaged: v[0],
            pool_paged: v[1],
            cache: v[2],
            kernel_code: v[3] + v[4],
            modified: v[5],
            standby: v[6] + v[7] + v[8],
            free: v[9],
            compressed: 0,
        }
    }
}

impl Drop for MemSampler {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.query) };
    }
}
