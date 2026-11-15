//! What the controller needs of Windows Firewall: reading it (no admin), and the elevated
//! helper's session (one UAC prompt). The tests hand the controller a fake.

use crate::firewall::{Rule, Status};
use crate::helper::{Launch, Reply, Request};
use std::path::PathBuf;

/// The helper at work (its rules exist while it lives).
pub trait GateSession: Send {
    fn send(&self, r: &Request) -> Result<Reply, String>;
    fn alive(&self) -> bool;
    fn close(self: Box<Self>) -> Result<Reply, String>;
}

pub trait Gate: Send + Sync {
    /// The firewall's state and every rule (no admin; it takes a moment: call it on a worker).
    fn read(&self) -> Result<(Status, Vec<Rule>), String>;
    /// Start the helper (the UAC prompt, owned by `hwnd`) with its first request. Blocks until
    /// the prompt is answered: call it on a worker.
    fn open(&self, hwnd: isize, first: &Request) -> Result<(Box<dyn GateSession>, Reply), Launch>;
    /// This exe's path, as the rules name it.
    fn exe(&self) -> PathBuf;
}

impl GateSession for crate::helper::Session {
    fn send(&self, r: &Request) -> Result<Reply, String> {
        crate::helper::Session::send(self, r)
    }
    fn alive(&self) -> bool {
        crate::helper::Session::alive(self)
    }
    fn close(self: Box<Self>) -> Result<Reply, String> {
        crate::helper::Session::close(*self)
    }
}

/// The real firewall and the real UAC prompt.
pub struct System;

impl Gate for System {
    fn read(&self) -> Result<(Status, Vec<Rule>), String> {
        Ok((crate::firewall::status()?, crate::firewall::rules()?))
    }

    fn open(&self, hwnd: isize, first: &Request) -> Result<(Box<dyn GateSession>, Reply), Launch> {
        let (s, r) = crate::helper::start(&crate::helper::Elevated, hwnd, first)?;
        Ok((Box::new(s), r))
    }

    fn exe(&self) -> PathBuf {
        crate::host::own_exe().unwrap_or_default()
    }
}
