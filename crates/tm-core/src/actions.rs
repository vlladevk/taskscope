//! Действия над процессами. Каждое действие проверяет время создания процесса,
//! чтобы не ударить по чужому процессу, получившему тот же PID.

use std::io;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetPriorityClass, IsProcessCritical, SetPriorityClass, TerminateProcess,
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS,
    NORMAL_PRIORITY_CLASS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE, REALTIME_PRIORITY_CLASS,
};

use crate::handle::ProcHandle;
use crate::sampler::ProcStat;
use crate::tree::Tree;

/// Процессы, завершение которых роняет систему или сессию.
const CRITICAL: &[&str] = &[
    "system", "registry", "secure system", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "winlogon.exe",
];

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
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    pub pid: u32,
    pub create_time: i64,
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn protected_reason(p: &ProcStat) -> Option<&'static str> {
    if p.pid == 0 || p.pid == 4 || CRITICAL.contains(&p.name.to_ascii_lowercase().as_str()) {
        return Some("критический системный процесс — его завершение приведёт к сбою Windows");
    }
    if p.pid == unsafe { GetCurrentProcessId() } {
        return Some("это сам tm");
    }
    None
}

fn is_critical(h: &ProcHandle) -> bool {
    let mut crit: BOOL = 0;
    unsafe { IsProcessCritical(h.raw(), &mut crit) != 0 && crit != 0 }
}

fn denied(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.to_string())
}

fn open_for(p: &ProcStat, access: u32) -> io::Result<ProcHandle> {
    if let Some(why) = protected_reason(p) {
        return Err(denied(why));
    }
    let h = ProcHandle::open(p.pid, access | PROCESS_QUERY_LIMITED_INFORMATION, Some(p.create_time))
        .map_err(|e| match e.raw_os_error() {
            Some(5) => denied("нет доступа — нужен запуск от имени администратора"),
            Some(87) => io::Error::new(io::ErrorKind::NotFound, "процесс уже завершился"),
            _ => e,
        })?;
    if is_critical(&h) {
        return Err(denied("Windows помечает процесс как критический — его завершение приведёт к сбою"));
    }
    Ok(h)
}

pub fn kill(p: &ProcStat) -> io::Result<()> {
    let h = open_for(p, PROCESS_TERMINATE)?;
    if unsafe { TerminateProcess(h.raw(), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Перезапуск: запоминаем командную строку, завершаем процесс и запускаем заново из папки программы.
/// Возвращает PID нового процесса.
pub fn restart(p: &ProcStat) -> io::Result<u32> {
    let (cmdline, path) = {
        let h = open_for(p, PROCESS_TERMINATE)?;
        let cmd = crate::nt::command_line(h.raw()).filter(|c| !c.trim().is_empty());
        let path = crate::info::image_path(&h);
        (cmd, path)
    };
    let path = path.ok_or_else(|| denied("не удалось узнать путь к программе"))?;
    let cmdline = cmdline.unwrap_or_else(|| format!("\"{path}\""));
    kill(p)?;
    // даём процессу закрыться, чтобы новый экземпляр не упёрся в «уже запущено»
    std::thread::sleep(std::time::Duration::from_millis(300));
    const CREATE_NEW_CONSOLE: u32 = 0x10;
    let dir = std::path::Path::new(&path).parent();
    crate::system::spawn(&cmdline, dir, CREATE_NEW_CONSOLE)
}

pub fn suspend(p: &ProcStat) -> io::Result<()> {
    crate::nt::suspend(open_for(p, PROCESS_SUSPEND_RESUME)?.raw())
}

pub fn resume(p: &ProcStat) -> io::Result<()> {
    crate::nt::resume(open_for(p, PROCESS_SUSPEND_RESUME)?.raw())
}

pub fn set_priority(p: &ProcStat, prio: Priority) -> io::Result<()> {
    if prio == Priority::Realtime {
        return Err(denied("приоритет «реального времени» может подвесить систему — не поддерживается"));
    }
    let h = open_for(p, PROCESS_SET_INFORMATION)?;
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

/// Применяет действие к набору процессов и возвращает результат по каждому.
pub fn apply(procs: &[ProcStat], order: &[usize], action: Action, prio: Option<Priority>) -> Vec<Outcome> {
    order
        .iter()
        .map(|&i| {
            let p = &procs[i];
            let r = match action {
                Action::Kill => kill(p),
                Action::Suspend => suspend(p),
                Action::Resume => resume(p),
                Action::Priority => set_priority(p, prio.unwrap_or(Priority::Normal)),
                Action::Restart => restart(p).map(|_| ()),
            };
            Outcome {
                pid: p.pid,
                create_time: p.create_time,
                name: p.name.clone(),
                ok: r.is_ok(),
                error: r.err().map(|e| e.to_string()),
            }
        })
        .collect()
}
