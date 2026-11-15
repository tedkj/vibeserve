//! What each server tells the window: one entry per request (who fetched or sent what: time,
//! peer address and port, request, bytes, result, duration), and the per-server log the window
//! keeps (newest first, the last 5 000).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

/// Which server an entry belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Tftp,
    Syslog,
    Http,
}

/// How a request ended (the colour of its result: ink, warn, danger).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// Refused by a rule (a path, writes off, a cap): the server did what it should.
    Refused,
    /// Failed underway (a timeout, a peer's error, a disk error).
    Failed,
}

/// One request, as the activity log shows it. Text fields come from outside and are cleaned
/// when shown, not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// When it started (FILETIME, UTC).
    pub at: u64,
    pub peer: SocketAddr,
    /// "RRQ /c9300.bin octet blksize 1468", "GET /firmware/", "PUT /x.bin".
    pub request: String,
    pub bytes: u64,
    /// "ok", "206", "not found", "timed out after 5 retries".
    pub result: String,
    pub outcome: Outcome,
    pub duration: Duration,
}

/// Where servers send what happened (the controller's inbox; a list in tests).
pub trait Report: Send + Sync {
    fn entry(&self, kind: Kind, e: Entry);
}

/// The last `cap` entries, newest first.
pub struct Log {
    entries: VecDeque<Entry>,
    cap: usize,
    /// Entries ever added (a seq the window keys its refreshes on).
    pub added: u64,
}

pub const LOG_CAP: usize = 5_000;

impl Log {
    pub fn new(cap: usize) -> Log {
        Log { entries: VecDeque::new(), cap, added: 0 }
    }

    pub fn push(&mut self, e: Entry) {
        self.entries.push_front(e);
        self.entries.truncate(self.cap);
        self.added += 1;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entry `i`, newest first.
    pub fn get(&self, i: usize) -> Option<&Entry> {
        self.entries.get(i)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }
}

/// An address and port as the logs write them: 192.168.1.50:51234, [fe80::1%12]:51234.
pub fn peer_text(a: &SocketAddr) -> String {
    a.to_string()
}

/// The log as text for the clipboard: one tab-separated line per entry, newest first, with a
/// header line.
pub fn as_text(log: &Log) -> String {
    let mut s = String::from("time\tpeer\trequest\tbytes\tresult\tduration\n");
    for e in log.iter() {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            crate::host::local_clock(e.at).stamp_ms(),
            peer_text(&e.peer),
            crate::text::clean_max(&e.request, 1024),
            e.bytes,
            crate::text::clean_max(&e.result, 1024),
            crate::text::duration(e.duration)
        ));
    }
    s
}
