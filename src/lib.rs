//! VibeServe: TFTP, syslog and a folder over HTTP, off when you close it. A VibeWare app: Rust
//! and Slint on the software renderer, one small exe, no runtime beside it.
//!
//! The engine is plain Rust: `paths` (the one path validator, the root, uploads), `tftp`,
//! `syslog`, `http`, `listen` (sockets), `firewall` and `helper` (the elevated helper). The
//! `controller` ties it to the window, which only lays out and draws; `view` makes every word.

pub mod activity;
pub mod check;
pub mod controller;
pub mod dialogs;
pub mod export;
pub mod firewall;
pub mod gate;
pub mod helper;
pub mod host;
pub mod http;
pub mod launch;
pub mod listen;
pub mod logview;
pub mod paths;
pub mod prefs;
pub mod syslog;
pub mod text;
pub mod tftp;
pub mod trust;
pub mod view;

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One server's place: its port and where it listens ("all", "127.0.0.1", "fe80::1%12").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerPrefs {
    pub port: u16,
    pub bind: String,
}

impl Default for ServerPrefs {
    fn default() -> ServerPrefs {
        ServerPrefs { port: 0, bind: "all".into() }
    }
}

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibeserve).
/// The servers' switches and the write toggles are not among them: every start begins with
/// everything off (DECISIONS.md).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// The root folder the user picked (None: the default, %USERPROFILE%\VibeServe).
    pub root: Option<String>,
    pub tftp: ServerPrefs,
    pub syslog: ServerPrefs,
    pub http: ServerPrefs,
    pub syslog_udp: bool,
    pub syslog_tcp: bool,
    pub log_to_file: bool,
    /// The log folder the user picked (None: the app's own).
    pub log_folder: Option<String>,
    /// The tab on the right: 0 syslog, 1 TFTP log, 2 HTTP log.
    pub tab: u8,
}

impl Default for Prefs {
    fn default() -> Prefs {
        Prefs {
            theme: None,
            root: None,
            tftp: ServerPrefs { port: 69, bind: "all".into() },
            syslog: ServerPrefs { port: 514, bind: "all".into() },
            http: ServerPrefs { port: 80, bind: "all".into() },
            syslog_udp: true,
            syslog_tcp: true,
            log_to_file: false,
            log_folder: None,
            tab: 0,
        }
    }
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        let d = Prefs::default();
        if !matches!(self.theme.as_deref(), None | Some("dark") | Some("light")) {
            self.theme = None;
        }
        for (p, def) in [(&mut self.tftp, &d.tftp), (&mut self.syslog, &d.syslog), (&mut self.http, &d.http)] {
            if p.port == 0 {
                p.port = def.port;
            }
            if listen::Bind::from_key(&p.bind).is_none() {
                p.bind = "all".into();
            }
        }
        if !self.syslog_udp && !self.syslog_tcp {
            self.syslog_udp = true;
        }
        // A relative path (edited by hand) would depend on how the app was started: none.
        let blank = |s: &Option<String>| s.as_deref().is_none_or(|t| t.trim().is_empty() || t.chars().any(|c| c.is_control()) || !std::path::Path::new(t.trim()).is_absolute());
        if blank(&self.root) {
            self.root = None;
        }
        if blank(&self.log_folder) {
            self.log_folder = None;
        }
        if self.tab > 2 {
            self.tab = 0;
        }
        self
    }

    pub fn server(&self, k: activity::Kind) -> &ServerPrefs {
        match k {
            activity::Kind::Tftp => &self.tftp,
            activity::Kind::Syslog => &self.syslog,
            activity::Kind::Http => &self.http,
        }
    }

    pub fn server_mut(&mut self, k: activity::Kind) -> &mut ServerPrefs {
        match k {
            activity::Kind::Tftp => &mut self.tftp,
            activity::Kind::Syslog => &mut self.syslog,
            activity::Kind::Http => &mut self.http,
        }
    }
}

/// The window with its basics wired: theme, version, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load().sanitized();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}
