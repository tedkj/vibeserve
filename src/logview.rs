//! What the Syslog tab shows: the last 100 000 messages in memory (at most 64 MiB of their text), the view through the filter
//! (text in host, app and message; severity at or above; source), newest first, and Pause, which
//! freezes the view while reception goes on and counts what is new. Pure: the window's model
//! (`controller`) reads rows from here by index.

use crate::syslog::Message;
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

/// Messages kept in memory.
pub const KEEP: usize = 100_000;
/// Text kept in memory, all messages together: past it the oldest go (and are counted).
pub const KEEP_BYTES: usize = 64 * 1024 * 1024;

/// What the view shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// Lower-cased; empty: everything.
    pub text: String,
    /// Severity at or above (0 emerg .. 7 debug); 7 shows all.
    pub max_severity: u8,
    pub source: Option<IpAddr>,
}

impl Filter {
    pub fn all() -> Filter {
        Filter { text: String::new(), max_severity: 7, source: None }
    }

    pub fn is_all(&self) -> bool {
        self.text.is_empty() && self.max_severity >= 7 && self.source.is_none()
    }

    pub fn passes(&self, m: &Message) -> bool {
        if m.severity > self.max_severity {
            return false;
        }
        if self.source.is_some_and(|s| s != m.source.ip()) {
            return false;
        }
        if self.text.is_empty() {
            return true;
        }
        let has = |s: &str| s.to_lowercase().contains(&self.text);
        has(m.msg()) || has(m.host()) || has(m.app())
    }
}

/// How the view changed (for the window's model): rows added at the top, rows gone from the
/// bottom, or everything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Change {
    pub added_front: usize,
    pub removed_back: usize,
    pub reset: bool,
}

#[derive(Default)]
pub struct Store {
    msgs: VecDeque<Message>,
    /// The sequence number of `msgs[0]`.
    first: u64,
    /// Shown messages by sequence number, newest first.
    view: VecDeque<u64>,
    pub filter: Filter,
    paused: bool,
    /// Messages that arrived while paused.
    pub new_while_paused: u64,
    /// Messages per source address (in memory now).
    sources: BTreeMap<IpAddr, u64>,
    /// Messages received since start (or the last Clear).
    pub total: u64,
    keep: usize,
    keep_bytes: usize,
    /// Text bytes held now.
    bytes: usize,
    /// Messages that left memory early because of the byte cap (since start or the last Clear).
    pub over_memory: u64,
}

impl Store {
    pub fn new() -> Store {
        Store::with_caps(KEEP, KEEP_BYTES)
    }

    pub fn with_cap(keep: usize) -> Store {
        Store::with_caps(keep, KEEP_BYTES)
    }

    pub fn with_caps(keep: usize, keep_bytes: usize) -> Store {
        Store { filter: Filter::all(), keep, keep_bytes, ..Store::default() }
    }

    /// Text bytes in memory.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Shown rows.
    pub fn len(&self) -> usize {
        self.view.len()
    }

    pub fn is_empty(&self) -> bool {
        self.view.is_empty()
    }

    /// Messages in memory.
    pub fn held(&self) -> usize {
        self.msgs.len()
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    fn by_seq(&self, seq: u64) -> Option<&Message> {
        seq.checked_sub(self.first).and_then(|i| self.msgs.get(i as usize))
    }

    /// Row `i` of the view (0 is the newest) and its sequence number.
    pub fn row(&self, i: usize) -> Option<(u64, &Message)> {
        let seq = *self.view.get(i)?;
        Some((seq, self.by_seq(seq)?))
    }

    /// The message with this sequence number, if it is still in memory.
    pub fn get(&self, seq: u64) -> Option<&Message> {
        self.by_seq(seq)
    }

    /// The view's position of a sequence number.
    pub fn position(&self, seq: u64) -> Option<usize> {
        self.view.iter().position(|&s| s == seq)
    }

    pub fn sources(&self) -> impl Iterator<Item = (&IpAddr, &u64)> {
        self.sources.iter()
    }

    /// New messages (oldest first in the batch).
    pub fn push(&mut self, batch: Vec<Message>) -> Change {
        let mut c = Change::default();
        for m in batch {
            self.total += 1;
            *self.sources.entry(m.source.ip()).or_insert(0) += 1;
            let seq = self.first + self.msgs.len() as u64;
            if self.paused {
                self.new_while_paused += 1;
            } else if self.filter.passes(&m) {
                self.view.push_front(seq);
                c.added_front += 1;
            }
            self.bytes += m.size();
            self.msgs.push_back(m);
            while self.msgs.len() > self.keep || (self.bytes > self.keep_bytes && self.msgs.len() > 1) {
                if self.msgs.len() <= self.keep {
                    self.over_memory += 1;
                }
                if let Some(old) = self.msgs.pop_front() {
                    self.bytes -= old.size();
                    let ip = old.source.ip();
                    if let Some(n) = self.sources.get_mut(&ip) {
                        *n -= 1;
                        if *n == 0 {
                            self.sources.remove(&ip);
                        }
                    }
                }
                self.first += 1;
                while self.view.back().is_some_and(|&s| s < self.first) {
                    self.view.pop_back();
                    // A row added and gone in the same batch was never shown.
                    if c.added_front > 0 && self.view.len() < c.added_front {
                        c.added_front -= 1;
                    } else {
                        c.removed_back += 1;
                    }
                }
            }
        }
        c
    }

    fn rebuild(&mut self) -> Change {
        self.view.clear();
        for (i, m) in self.msgs.iter().enumerate().rev() {
            if self.filter.passes(m) {
                self.view.push_back(self.first + i as u64);
            }
        }
        Change { reset: true, ..Change::default() }
    }

    pub fn set_filter(&mut self, f: Filter) -> Change {
        self.filter = f;
        if self.paused {
            // The frozen view stays; the filter applies on resume.
            return Change::default();
        }
        self.rebuild()
    }

    pub fn set_paused(&mut self, on: bool) -> Change {
        if on == self.paused {
            return Change::default();
        }
        self.paused = on;
        if on {
            self.new_while_paused = 0;
            return Change::default();
        }
        self.new_while_paused = 0;
        self.rebuild()
    }

    pub fn clear(&mut self) -> Change {
        self.first += self.msgs.len() as u64;
        self.msgs.clear();
        self.bytes = 0;
        self.over_memory = 0;
        self.sources.clear();
        self.total = 0;
        self.new_while_paused = 0;
        self.view.clear();
        Change { reset: true, ..Change::default() }
    }

    /// The shown messages, newest first (Save view).
    pub fn shown(&self) -> Vec<&Message> {
        self.view.iter().filter_map(|&s| self.by_seq(s)).collect()
    }
}
