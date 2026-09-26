//! Ядро tm: сбор данных о процессах и системе, дерево, группировка по приложениям, действия.
//! Используется и CLI (`tm`), и приложением с интерфейсом — логика одна.

pub mod actions;
pub mod apps;
pub mod conns;
pub mod engine;
pub mod docker;
pub mod gpu;
pub mod handle;
pub mod info;
pub mod inspect;
pub mod locks;
pub mod logs;
pub mod history;
pub mod icons;
pub mod net;
pub mod net_etw;
pub mod nt;
pub mod pipe;
pub mod pool;
pub mod sampler;
pub mod sysmem;
pub mod service;
pub mod services;
pub mod settings;
pub mod signature;
pub mod system;
pub mod tree;
pub mod watch;

pub use apps::AppStat;
pub use engine::Engine;
pub use service::Service;
pub use info::{InfoCache, ProcInfo};
pub use sampler::{Frame, ProcKey, ProcStat, Sampler, SystemStat};
pub use tree::Tree;