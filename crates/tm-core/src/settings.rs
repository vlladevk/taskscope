//! User settings: `%LOCALAPPDATA%\tm\settings.json`.
//!
//! The same for the app, the CLI and MCP — the list of protected processes
//! set in the window is respected by `tm kill` and by an AI agent alike.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Protected processes: an exe name (`chrome.exe`, case-insensitive) or a full path.
    pub protected: Vec<String>,
    /// Ask for confirmation before ending (“don’t ask again” turns it off).
    pub confirm_kill: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { protected: Vec::new(), confirm_kill: true }
    }
}

pub fn path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("tm").join("settings.json"))
}

impl Settings {
    /// Reads the settings; a missing or broken file gives the defaults.
    pub fn load() -> Self {
        path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Writes atomically: to a temporary file and then a rename, so half a file is never left behind.
    pub fn save(&self) -> std::io::Result<()> {
        let p = path().ok_or_else(|| std::io::Error::other("the LOCALAPPDATA variable is not set"))?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &p)
    }

    /// Whether the user protected the process: by name (with or without `.exe`) or by full path.
    pub fn is_protected(&self, name: &str, path: Option<&str>) -> bool {
        let n = name.to_ascii_lowercase();
        let stem = n.strip_suffix(".exe").unwrap_or(&n);
        self.protected.iter().any(|e| {
            let e = e.trim().to_ascii_lowercase();
            if e.contains('\\') || e.contains('/') {
                path.is_some_and(|p| p.to_ascii_lowercase().replace('/', "\\") == e.replace('/', "\\"))
            } else {
                e.strip_suffix(".exe").unwrap_or(&e) == stem
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_by_name_or_path() {
        let s = Settings { protected: vec!["Chrome".into(), r"C:\Tools\a.exe".into()], confirm_kill: true };
        assert!(s.is_protected("chrome.exe", None));
        assert!(s.is_protected("CHROME.EXE", Some(r"C:\x\chrome.exe")));
        assert!(!s.is_protected("chromium.exe", None));
        assert!(s.is_protected("a.exe", Some(r"c:\tools\A.exe")));
        assert!(!s.is_protected("a.exe", Some(r"c:\other\a.exe")));
        assert!(!s.is_protected("a.exe", None));
    }
}
