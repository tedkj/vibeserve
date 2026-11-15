//! The syslog receiver: UDP and TCP (RFC 6587: octet counting or LF-terminated, detected per
//! connection), the parsers for RFC 5424 and RFC 3164 with the variants real devices send, the
//! rate cap, and the daily log files.
//!
//! The parsers and the TCP framer are pure: bytes in, fields out, every length checked.
//! Anything that does not parse is kept whole as the message; nothing from the wire is trusted
//! (fields are cleaned when shown, the log file escapes control characters).

use crate::listen::{Bind, BindError, Ready, Stop, Woke};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One message on a TCP connection is cut here (and marked).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// The window keeps at most this much of one message (all its text fields together); the log
/// file keeps it whole, up to `MAX_MESSAGE`.
pub const WINDOW_MAX: usize = 8 * 1024;
/// More than this many messages in one second are dropped (and counted).
pub const MAX_RATE: u32 = 5_000;
pub const MAX_CONNECTIONS: usize = 64;
/// One address holds at most this many TCP connections (a device keeps one).
pub const PER_PEER: usize = 8;
pub const IDLE: Duration = Duration::from_secs(600);
/// A device writes a message in one go: one still unfinished after this is a slow drip.
pub const MESSAGE_WAIT: Duration = Duration::from_secs(60);

pub const FACILITIES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];
pub const SEVERITIES: [&str; 8] = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

/// A message as parsed. Text is as sent (lossy UTF-8), cleaned only when shown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub facility: u8,
    pub severity: u8,
    /// No valid PRI: 13 (user.notice) was taken, as RFC 3164 says.
    pub no_pri: bool,
    pub device_time: String,
    pub host: String,
    pub app: String,
    pub procid: String,
    pub msgid: String,
    pub sd: String,
    pub msg: String,
}

/// A received message as the window keeps it: every text field in one allocation (100 000 of
/// them are held; one string each instead of seven kept the working set under 50 MB).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// FILETIME, UTC.
    pub received: u64,
    pub source: SocketAddr,
    pub tcp: bool,
    pub facility: u8,
    pub severity: u8,
    /// Longer than 64 KiB on TCP: cut there.
    pub cut: bool,
    /// Longer than `WINDOW_MAX`: the window keeps the first 8 KiB (the log file has it whole).
    pub trimmed: bool,
    /// device time, host, app, procid, msgid, structured data, message, one after the other.
    text: Box<str>,
    /// Where each field but the message ends in `text` (offsets made from `text` itself).
    ends: [u32; 6],
}

impl Message {
    /// The fields share `WINDOW_MAX` bytes in order (header fields first, the message last);
    /// what does not fit is left out and the message is marked `trimmed`.
    pub fn new(p: Parsed, received: u64, source: SocketAddr, tcp: bool, cut: bool) -> Message {
        let fields = [&p.device_time, &p.host, &p.app, &p.procid, &p.msgid, &p.sd, &p.msg];
        let whole: usize = fields.iter().map(|f| f.len()).sum();
        let mut text = String::with_capacity(whole.min(WINDOW_MAX));
        let mut ends = [0u32; 6];
        for (i, f) in fields.iter().enumerate() {
            let room = WINDOW_MAX - text.len();
            text.push_str(&f[..f.floor_char_boundary(room.min(f.len()))]);
            if i < 6 {
                ends[i] = text.len() as u32;
            }
        }
        let trimmed = text.len() < whole;
        Message { received, source, tcp, facility: p.facility, severity: p.severity, cut, trimmed, text: text.into_boxed_str(), ends }
    }

    /// Bytes of text held (what the window's memory cap counts).
    pub fn size(&self) -> usize {
        self.text.len()
    }

    /// The window's note for a message it does not hold whole ("" for one it does).
    pub fn window_note(&self) -> &'static str {
        match (self.trimmed, self.cut) {
            (true, true) => " [cut at 8 KiB here; over 64 KiB as sent: Log to file keeps 64 KiB]",
            (true, false) => " [cut at 8 KiB here; Log to file keeps it whole]",
            (false, true) => " [cut at 64 KiB]",
            (false, false) => "",
        }
    }

    fn part(&self, i: usize) -> &str {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        let end = if i == 6 { self.text.len() } else { self.ends[i] as usize };
        &self.text[start..end]
    }

    pub fn device_time(&self) -> &str {
        self.part(0)
    }
    pub fn host(&self) -> &str {
        self.part(1)
    }
    pub fn app(&self) -> &str {
        self.part(2)
    }
    pub fn procid(&self) -> &str {
        self.part(3)
    }
    pub fn msgid(&self) -> &str {
        self.part(4)
    }
    pub fn sd(&self) -> &str {
        self.part(5)
    }
    pub fn msg(&self) -> &str {
        self.part(6)
    }
}

pub fn facility_name(f: u8) -> &'static str {
    FACILITIES.get(f as usize).copied().unwrap_or("?")
}

pub fn severity_name(s: u8) -> &'static str {
    SEVERITIES.get(s as usize).copied().unwrap_or("?")
}

// ---------- parsing ----------

/// `<PRI>` at the start: its value (0..=191) and the rest.
fn pri(s: &str) -> Option<(u8, &str)> {
    let rest = s.strip_prefix('<')?;
    let end = rest.find('>')?;
    let digits = &rest[..end];
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u16 = digits.parse().ok()?;
    (v <= 191).then_some((v as u8, &rest[end + 1..]))
}

/// The next space-separated token and what follows the single space after it.
fn token(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() || s.starts_with(' ') {
        return None;
    }
    Some(match s.find(' ') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    })
}

fn strip_bom(s: &str) -> &str {
    s.strip_prefix('\u{FEFF}').unwrap_or(s)
}

/// RFC 5424 structured data: "-" or one or more `[id k="v"...]` (escapes \" \\ \] inside
/// values). Its text and what follows.
fn structured(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('-') {
        return (rest.is_empty() || rest.starts_with(' ')).then(|| ("", rest.strip_prefix(' ').unwrap_or(rest)));
    }
    if !s.starts_with('[') {
        return None;
    }
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i] == b'[' {
        let mut quoted = false;
        i += 1;
        loop {
            let c = *b.get(i)?;
            match c {
                b'\\' if quoted => i += 2,
                b'"' => {
                    quoted = !quoted;
                    i += 1;
                }
                b']' if !quoted => {
                    i += 1;
                    break;
                }
                _ => i += 1,
            }
        }
    }
    let sd = &s[..i.min(s.len())];
    let rest = &s[i.min(s.len())..];
    if !rest.is_empty() && !rest.starts_with(' ') {
        return None;
    }
    Some((sd, rest.strip_prefix(' ').unwrap_or(rest)))
}

fn nil(s: &str) -> String {
    if s == "-" { String::new() } else { s.to_string() }
}

/// RFC 5424: `1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]`. None when it is not that.
fn rfc5424(s: &str) -> Option<Parsed> {
    let (ver, s) = token(s)?;
    if ver != "1" {
        return None;
    }
    let (ts, s) = token(s)?;
    if ts != "-" && !(ts.len() >= 19 && ts.as_bytes()[4] == b'-' && ts.as_bytes()[10] == b'T') {
        return None;
    }
    let (host, s) = token(s)?;
    let (app, s) = token(s)?;
    let (procid, s) = token(s)?;
    let (msgid, s) = token(s)?;
    let (sd, msg) = structured(s)?;
    Some(Parsed { device_time: nil(ts), host: nil(host), app: nil(app), procid: nil(procid), msgid: nil(msgid), sd: sd.to_string(), msg: strip_bom(msg).to_string(), ..Parsed::default() })
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const ZONES: [&str; 20] = ["UTC", "GMT", "Z", "CET", "CEST", "EET", "EEST", "WET", "WEST", "BST", "IST", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT", "JST"];

fn digits(s: &str, min: usize, max: usize) -> Option<(u32, &str)> {
    let n = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if n < min || n > max {
        return None;
    }
    Some((s[..n].parse().ok()?, &s[n..]))
}

/// `hh:mm:ss[.frac]`.
fn clock(s: &str) -> Option<&str> {
    let (h, s) = digits(s, 2, 2)?;
    let s = s.strip_prefix(':')?;
    let (m, s) = digits(s, 2, 2)?;
    let s = s.strip_prefix(':')?;
    let (sec, mut s) = digits(s, 2, 2)?;
    if h > 23 || m > 59 || sec > 60 {
        return None;
    }
    if let Some(f) = s.strip_prefix('.') {
        s = digits(f, 1, 9)?.1;
    }
    Some(s)
}

/// A time zone after a time: a known abbreviation, or any 2-5 capital letters when a colon
/// follows (Cisco: "... UTC: %SYS-..."). An offset like +01:00 too.
fn zone(s: &str) -> Option<&str> {
    let s1 = s.strip_prefix(' ')?;
    let n = s1.bytes().take_while(|b| b.is_ascii_uppercase()).count();
    if n > 0 {
        let z = &s1[..n];
        let after = &s1[n..];
        if (ZONES.contains(&z) && (after.is_empty() || after.starts_with([' ', ':']))) || ((2..=5).contains(&n) && after.starts_with(':')) {
            return Some(after);
        }
    }
    None
}

/// A device's timestamp at the start: BSD (`[*.]Mmm dd [yyyy] hh:mm:ss[.mmm] [TZ]`), NX-OS
/// (`yyyy Mmm dd hh:mm:ss[.mmm] [TZ]`) or ISO 8601. The text as sent and the rest.
pub fn timestamp(s: &str) -> Option<(&str, &str)> {
    let start = s;
    // ISO 8601
    if let Some((_, r)) = digits(s, 4, 4)
        && let Some(r) = r.strip_prefix('-')
        && let Some((mo, r)) = digits(r, 2, 2)
        && let Some(r) = r.strip_prefix('-')
        && let Some((d, r)) = digits(r, 2, 2)
        && let Some(r) = r.strip_prefix(['T', ' '])
        && (1..=12).contains(&mo)
        && (1..=31).contains(&d)
        && let Some(mut r) = clock(r)
    {
        if let Some(z) = r.strip_prefix('Z') {
            r = z;
        } else if let Some(z) = r.strip_prefix(['+', '-']) {
            let (_, z) = digits(z, 2, 2)?;
            let z = z.strip_prefix(':').unwrap_or(z);
            r = digits(z, 2, 2)?.1;
        }
        if !(r.is_empty() || r.starts_with([' ', ':'])) {
            return None;
        }
        let used = start.len() - r.len();
        return Some((&start[..used], r));
    }
    let mut s1 = s;
    // NX-OS: the year first.
    if let Some((y, r)) = digits(s1, 4, 4)
        && (1970..=2200).contains(&y)
        && let Some(r) = r.strip_prefix(' ')
    {
        s1 = r;
    } else if let Some(r) = s1.strip_prefix(['*', '.']) {
        s1 = r; // Cisco: * clock not synchronised, . synchronised but marked
    }
    let mon = s1.get(..3)?;
    if !MONTHS.contains(&mon) {
        return None;
    }
    let r = s1[3..].strip_prefix(' ')?;
    let r = r.strip_prefix(' ').unwrap_or(r); // "Mar  1": a space-padded day
    let (d, r) = digits(r, 1, 2)?;
    if !(1..=31).contains(&d) {
        return None;
    }
    let mut r = r.strip_prefix(' ')?;
    // Cisco's "show-timezone year": "Mar  1 2024 00:00:12".
    if let Some((_, after)) = digits(r, 4, 4)
        && let Some(after) = after.strip_prefix(' ')
    {
        r = after;
    }
    let mut r = clock(r)?;
    if let Some(after) = zone(r) {
        r = after;
    }
    if !(r.is_empty() || r.starts_with([' ', ':'])) {
        return None;
    }
    let used = start.len() - r.len();
    Some((&start[..used], r))
}

/// A tag: `app[pid]:`, `app:`, `%FAC-SEV-MNEMONIC:` (Cisco). Its app, pid and the message after.
fn tag(s: &str) -> Option<(String, String, &str)> {
    let (tok, rest) = match s.find(' ') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    if tok.is_empty() || tok.chars().count() > 64 {
        return None;
    }
    let body = tok.strip_suffix(':');
    let (name, pid) = match (body.unwrap_or(tok)).split_once('[') {
        Some((n, p)) => match p.strip_suffix(']') {
            Some(p) if !p.is_empty() && p.len() <= 128 => (n, p),
            _ => return None,
        },
        None if body.is_some() => (body.unwrap(), ""),
        None => return None, // no colon and no [pid]: not a tag
    };
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || "-_./%@,".contains(c)) {
        return None;
    }
    Some((name.to_string(), pid.to_string(), rest))
}

/// RFC 3164 and what devices really send.
fn rfc3164(s: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut s = s;
    // Cisco's sequence number "123: ", NX-OS's bare ": ".
    if let Some((n, r)) = digits(s, 1, 10)
        && let Some(r) = r.strip_prefix(": ")
    {
        p.msgid = n.to_string();
        s = r;
    } else if let Some(r) = s.strip_prefix(": ") {
        s = r;
    }
    let mut host_first = false;
    // Cisco "logging origin-id": "R1: *Mar  1 00:00:12: %SYS-...".
    if let Some((h, r)) = s.split_once(": ")
        && !h.is_empty()
        && !h.contains(' ')
        && h.len() <= 255
        && timestamp(r).is_some()
    {
        p.host = h.to_string();
        host_first = true;
        s = r;
    }
    let mut stamped = false;
    let mut cisco = false;
    if let Some((ts, r)) = timestamp(s) {
        p.device_time = ts.to_string();
        stamped = true;
        if let Some(r2) = r.strip_prefix(':') {
            cisco = true;
            s = r2.trim_start_matches(' ');
        } else {
            s = r.strip_prefix(' ').unwrap_or(r);
        }
    }
    if stamped && !cisco && !host_first {
        // RFC 3164: HOSTNAME after the timestamp, unless the next word is already the tag.
        if let Some((h, r)) = token(s)
            && tag(s).is_none()
        {
            p.host = h.to_string();
            s = r;
        }
    }
    if let Some((app, pid, r)) = tag(s) {
        p.app = app;
        p.procid = pid;
        s = r;
    }
    p.msg = strip_bom(s).to_string();
    // FortiOS key=value logs carry their name in devname="...".
    if p.host.is_empty()
        && let Some(i) = p.msg.find("devname=")
    {
        let v = &p.msg[i + 8..];
        let name = match v.strip_prefix('"') {
            Some(q) => q.split('"').next().unwrap_or(""),
            None => v.split(' ').next().unwrap_or(""),
        };
        if !name.is_empty() && name.len() <= 255 {
            p.host = name.to_string();
        }
    }
    p
}

/// Parse one message (one datagram, or one TCP frame).
pub fn parse(raw: &[u8]) -> Parsed {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim_end_matches(['\n', '\r', '\0']);
    let (value, rest, no_pri) = match pri(text) {
        Some((v, r)) => (v, r, false),
        None => (13, text, true),
    };
    let mut p = rfc5424(rest).unwrap_or_else(|| rfc3164(rest));
    p.facility = value >> 3;
    p.severity = value & 7;
    p.no_pri = no_pri;
    p
}

// ---------- TCP framing (RFC 6587) ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Octet,
    Lf,
}

/// One message from the stream (cut: longer than the cap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Msg(Vec<u8>, bool),
    /// The stream broke the framing it started with: the connection is closed.
    Broken(String),
}

/// Splits a TCP stream into messages: octet counting (`<len> <msg>`) when the first byte is a
/// digit, else LF-terminated (a NUL ends a message too). Memory stays under the cap.
pub struct Framer {
    mode: Option<Mode>,
    buf: Vec<u8>,
    /// Octet counting: bytes of the current message still to come.
    want: usize,
    /// Bytes still to throw away (the rest of a message past the cap).
    skip: usize,
    /// LF mode: throwing away until the next LF.
    skip_line: bool,
    max: usize,
    broken: bool,
}

impl Framer {
    pub fn new(max: usize) -> Framer {
        Framer { mode: None, buf: Vec::new(), want: 0, skip: 0, skip_line: false, max, broken: false }
    }

    pub fn push(&mut self, mut data: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        while !data.is_empty() && !self.broken {
            if self.skip > 0 {
                let n = self.skip.min(data.len());
                self.skip -= n;
                data = &data[n..];
                continue;
            }
            let mode = match self.mode {
                Some(m) => m,
                None => {
                    // Leading blank lines say nothing yet.
                    let n = data.iter().take_while(|b| matches!(b, b'\n' | b'\r' | b' ' | 0)).count();
                    data = &data[n..];
                    let Some(&first) = data.first() else { break };
                    let m = if first.is_ascii_digit() { Mode::Octet } else { Mode::Lf };
                    self.mode = Some(m);
                    m
                }
            };
            match mode {
                Mode::Lf => {
                    if self.skip_line {
                        match data.iter().position(|&b| b == b'\n' || b == 0) {
                            Some(i) => {
                                self.skip_line = false;
                                data = &data[i + 1..];
                            }
                            None => data = &[],
                        }
                        continue;
                    }
                    match data.iter().position(|&b| b == b'\n' || b == 0) {
                        Some(i) if self.buf.len() + i <= self.max => {
                            self.buf.extend_from_slice(&data[..i]);
                            data = &data[i + 1..];
                            let mut m = std::mem::take(&mut self.buf);
                            while m.last() == Some(&b'\r') {
                                m.pop();
                            }
                            if !m.is_empty() {
                                out.push(Frame::Msg(m, false));
                            }
                        }
                        _ => {
                            let room = self.max - self.buf.len();
                            let take = data.len().min(room);
                            let ends_here = data[..take].iter().any(|&b| b == b'\n' || b == 0);
                            debug_assert!(!ends_here);
                            self.buf.extend_from_slice(&data[..take]);
                            data = &data[take..];
                            if self.buf.len() >= self.max {
                                out.push(Frame::Msg(std::mem::take(&mut self.buf), true));
                                self.skip_line = true;
                            }
                        }
                    }
                }
                Mode::Octet => {
                    if self.want == 0 {
                        // The length: digits, then one space.
                        let digits_n = data.iter().take_while(|b| b.is_ascii_digit()).count();
                        if digits_n == data.len() {
                            // Header split across reads: keep it (at most 10 digits).
                            self.buf.extend_from_slice(data);
                            if self.buf.len() > 10 {
                                return self.fail(out, "a message length of more than 10 digits");
                            }
                            data = &[];
                            continue;
                        }
                        let mut head = std::mem::take(&mut self.buf);
                        head.extend_from_slice(&data[..digits_n]);
                        if head.is_empty() || head.len() > 10 || data[digits_n] != b' ' {
                            return self.fail(out, "octet counting without a length");
                        }
                        let len: usize = std::str::from_utf8(&head).ok().and_then(|t| t.parse().ok()).unwrap_or(usize::MAX);
                        if len == 0 || len == usize::MAX {
                            return self.fail(out, "a message length of 0");
                        }
                        data = &data[digits_n + 1..];
                        self.want = len;
                        continue;
                    }
                    let keep = self.want.min(self.max).saturating_sub(self.buf.len());
                    let n = data.len().min(keep);
                    self.buf.extend_from_slice(&data[..n]);
                    data = &data[n..];
                    if self.buf.len() >= self.want.min(self.max) {
                        let cut = self.want > self.max;
                        self.skip = self.want - self.buf.len();
                        self.want = 0;
                        out.push(Frame::Msg(std::mem::take(&mut self.buf), cut));
                    }
                }
            }
        }
        out
    }

    fn fail(&mut self, mut out: Vec<Frame>, why: &str) -> Vec<Frame> {
        self.broken = true;
        self.buf.clear();
        out.push(Frame::Broken(why.into()));
        out
    }

    /// A message has begun and not ended yet (its bytes, a length, or a rest still to come).
    pub fn mid(&self) -> bool {
        !self.broken && (!self.buf.is_empty() || self.want > 0 || self.skip > 0 || self.skip_line)
    }

    /// The connection ended: a last LF-mode message without its LF still counts.
    pub fn end(&mut self) -> Option<Frame> {
        if self.mode == Some(Mode::Lf) && !self.skip_line && !self.buf.is_empty() && !self.broken {
            let mut m = std::mem::take(&mut self.buf);
            while m.last() == Some(&b'\r') {
                m.pop();
            }
            return (!m.is_empty()).then_some(Frame::Msg(m, false));
        }
        None
    }
}

// ---------- the rate cap ----------

/// At most `MAX_RATE` messages in each second (UDP and TCP together); the rest are counted.
pub struct Rate {
    window: Mutex<(Instant, u32)>,
    pub dropped: AtomicU64,
    max: u32,
}

impl Rate {
    pub fn new(max: u32) -> Rate {
        Rate { window: Mutex::new((Instant::now(), 0)), dropped: AtomicU64::new(0), max }
    }

    /// Whether one more message may go in now.
    pub fn take(&self) -> bool {
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if now.duration_since(w.0) >= Duration::from_secs(1) {
            *w = (now, 0);
        }
        if w.1 >= self.max {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        w.1 += 1;
        true
    }
}

// ---------- the receivers ----------

/// Where messages go (the controller; a list in tests). Called in batches; `raw` holds each
/// message's bytes as received when `keep_raw` says so (the log file is on), else it is empty.
pub trait Sink: Send + Sync {
    fn messages(&self, batch: Vec<Message>, raw: Vec<Vec<u8>>);
    fn keep_raw(&self) -> bool {
        false
    }
}

/// Counters the window shows.
#[derive(Default)]
pub struct Stats {
    pub connections: AtomicUsize,
    /// Connections turned away at the cap.
    pub refused: AtomicU64,
    /// Connections closed for broken framing.
    pub broken: AtomicU64,
}

pub struct Server {
    stop: Arc<Stop>,
    threads: Vec<std::thread::JoinHandle<()>>,
    /// The TCP connections' threads, handed over when the accept loop ends.
    handed: crate::listen::Handed,
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub rate: Arc<Rate>,
    pub stats: Arc<Stats>,
}

impl Server {
    /// Stop, waiting at most `HALT_WAIT`: how many threads were left running.
    pub fn stop(self) -> usize {
        self.stop_left().count()
    }

    /// Stop as stop does: the threads it left, to see when they end (RL8-1).
    pub fn stop_left(mut self) -> crate::listen::Left {
        self.halt(crate::listen::HALT_WAIT)
    }

    pub fn stop_within(mut self, within: Duration) -> usize {
        self.halt(within).count()
    }

    fn halt(&mut self, within: Duration) -> crate::listen::Left {
        crate::listen::halt(&self.stop, std::mem::take(&mut self.threads), &self.handed, within)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Once only (`listen::halt`): after a stop this takes nothing.
        self.halt(crate::listen::HALT_WAIT);
    }
}

/// What the receivers run with (tests shorten the idle timeout and lower the rate).
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    pub idle: Duration,
    pub max_rate: u32,
    pub max_connections: usize,
    /// TCP connections one address may hold (IN-VibeServe-3).
    pub per_peer: usize,
    /// A message must arrive whole within this of its first byte (IN-VibeServe-3).
    pub message_wait: Duration,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning { idle: IDLE, max_rate: MAX_RATE, max_connections: MAX_CONNECTIONS, per_peer: PER_PEER, message_wait: MESSAGE_WAIT }
    }
}

/// Start the UDP and/or TCP receiver on `bind`:`port`. A failure names its protocol.
pub fn start(bind: &Bind, port: u16, udp: bool, tcp: bool, tuning: Tuning, sink: Arc<dyn Sink>) -> Result<Server, (bool, BindError)> {
    let stop = Stop::new();
    let rate = Arc::new(Rate::new(tuning.max_rate));
    let stats: Arc<Stats> = Default::default();
    let mut server = Server { stop: stop.clone(), threads: Vec::new(), handed: Default::default(), udp: None, tcp: None, rate: rate.clone(), stats: stats.clone() };
    if udp {
        let s = crate::listen::udp(bind, port, false).map_err(|e| (false, e))?;
        // Room for a burst (the default 64 KiB holds a few hundred messages): what the system
        // drops before we read it is never counted.
        crate::listen::set_recv_buffer(&s, 4 * 1024 * 1024);
        // Read from the socket: the controller's set of bound sockets keeps it (RL7-1).
        server.udp = Some(s.local_addr().map_err(|e| (false, BindError::Other(e.to_string())))?);
        let ready = Ready::new(&s, windows_sys::Win32::Networking::WinSock::FD_READ).map_err(|e| (false, BindError::Other(e.to_string())))?;
        let (st, sk, rt) = (stop.clone(), sink.clone(), rate.clone());
        let t = std::thread::Builder::new().name("syslog-udp".into()).stack_size(256 * 1024).spawn(move || udp_loop(s, ready, st, sk, rt)).map_err(|e| (false, BindError::Other(e.to_string())))?;
        server.threads.push(t);
    }
    if tcp {
        let l = crate::listen::tcp(bind, port).map_err(|e| (true, e))?;
        server.tcp = Some(l.local_addr().map_err(|e| (true, BindError::Other(e.to_string())))?);
        let ready = Ready::new(&l, windows_sys::Win32::Networking::WinSock::FD_ACCEPT).map_err(|e| (true, BindError::Other(e.to_string())))?;
        let (st, sk, rt, ss, hd) = (stop.clone(), sink.clone(), rate.clone(), stats.clone(), server.handed.clone());
        let t = std::thread::Builder::new().name("syslog-tcp".into()).stack_size(256 * 1024).spawn(move || tcp_loop(l, ready, st, sk, rt, ss, tuning, hd)).map_err(|e| (true, BindError::Other(e.to_string())))?;
        server.threads.push(t);
    }
    Ok(server)
}

/// Add a message (and its bytes, when the sink keeps them) to a batch. A batch's raw lines are
/// for all of its messages or for none (the sink pairs them by position): when `keep_raw`
/// changes, the batch so far goes first.
fn add(sink: &dyn Sink, batch: &mut Vec<Message>, raws: &mut Vec<Vec<u8>>, m: Message, raw: &[u8]) {
    let keep = sink.keep_raw();
    if !batch.is_empty() && keep == raws.is_empty() {
        sink.messages(std::mem::take(batch), std::mem::take(raws));
    }
    batch.push(m);
    if keep {
        raws.push(raw.to_vec());
    }
}

fn udp_loop(sock: UdpSocket, ready: Ready, stop: Arc<Stop>, sink: Arc<dyn Sink>, rate: Arc<Rate>) {
    let mut buf = vec![0u8; 65_536];
    let mut batch: Vec<Message> = Vec::new();
    let mut raws: Vec<Vec<u8>> = Vec::new();
    let mut after_stop = 0;
    loop {
        // RL8-1: looked at on every turn, not only when the socket is quiet: once stopped it
        // takes at most one batch more of what is queued (R-SERVE-1), so a steady stream of
        // messages never keeps it open past its stop.
        if stop.stopped() {
            after_stop += 1;
            if after_stop > 512 {
                break;
            }
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if rate.take() {
                    let m = Message::new(parse(&buf[..n]), crate::host::now_filetime(), crate::listen::unmap(from), false, false);
                    add(sink.as_ref(), &mut batch, &mut raws, m, &buf[..n]);
                }
                if batch.len() >= 512 {
                    sink.messages(std::mem::take(&mut batch), std::mem::take(&mut raws));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !batch.is_empty() {
                    sink.messages(std::mem::take(&mut batch), std::mem::take(&mut raws));
                }
                if ready.wait(&stop, None) == Woke::Stopped {
                    break;
                }
            }
            Err(_) => {
                if stop.stopped() {
                    break;
                }
                stop.sleep(Duration::from_millis(5));
            }
        }
    }
    if !batch.is_empty() {
        sink.messages(batch, raws);
    }
}

#[allow(clippy::too_many_arguments)]
fn tcp_loop(l: TcpListener, ready: Ready, stop: Arc<Stop>, sink: Arc<dyn Sink>, rate: Arc<Rate>, stats: Arc<Stats>, tuning: Tuning, handed: crate::listen::Handed) {
    let conns: Arc<Mutex<Vec<(u64, TcpStream)>>> = Default::default();
    let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut id: u64 = 0;
    let peers: Arc<crate::listen::Peers> = Default::default();
    loop {
        threads.retain(|t| !t.is_finished());
        // RL8-1: on every turn, not only when no connection waits (a steady stream of them
        // never keeps it open past its stop).
        if stop.stopped() {
            break;
        }
        match l.accept() {
            Ok((s, from)) => {
                if threads.len() >= tuning.max_connections {
                    stats.refused.fetch_add(1, Ordering::Relaxed);
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                // IN-VibeServe-3: one address never takes every slot.
                let Some(slot) = peers.take(crate::listen::unmap(from).ip(), tuning.per_peer) else {
                    stats.refused.fetch_add(1, Ordering::Relaxed);
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    continue;
                };
                if crate::listen::plain(&s).is_err() || s.set_read_timeout(Some(tuning.idle)).is_err() {
                    continue;
                }
                id += 1;
                let Ok(clone) = s.try_clone() else { continue };
                conns.lock().unwrap_or_else(|e| e.into_inner()).push((id, clone));
                let (sk, rt, ss, cs, me) = (sink.clone(), rate.clone(), stats.clone(), conns.clone(), id);
                stats.connections.fetch_add(1, Ordering::Relaxed);
                if let Ok(t) = std::thread::Builder::new().name("syslog-conn".into()).stack_size(256 * 1024).spawn(move || {
                    let _slot = slot;
                    connection(s, crate::listen::unmap(from), sk.as_ref(), &rt, &ss, tuning);
                    cs.lock().unwrap_or_else(|e| e.into_inner()).retain(|(i, _)| *i != me);
                    ss.connections.fetch_sub(1, Ordering::Relaxed);
                }) {
                    threads.push(t);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if ready.wait(&stop, None) == Woke::Stopped {
                    break;
                }
            }
            Err(_) => {
                if stop.stopped() {
                    break;
                }
                stop.sleep(Duration::from_millis(5));
            }
        }
    }
    // Stop: every connection's read ends now; `halt` waits for them (bounded).
    for (_, c) in conns.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        let _ = c.shutdown(std::net::Shutdown::Both);
    }
    handed.lock().unwrap_or_else(|e| e.into_inner()).extend(threads);
}

fn connection(mut s: TcpStream, from: SocketAddr, sink: &dyn Sink, rate: &Rate, stats: &Stats, tuning: Tuning) {
    use std::io::Read;
    let mut f = Framer::new(MAX_MESSAGE);
    let mut buf = vec![0u8; 16 * 1024];
    // IN-VibeServe-3: when the message under way began (its first byte); it must be whole
    // within `message_wait`. Between messages the idle time stands.
    let mut begun: Option<Instant> = None;
    loop {
        let wait = match begun {
            Some(t) => (t + tuning.message_wait).saturating_duration_since(Instant::now()).min(tuning.idle),
            None => tuning.idle,
        };
        let _ = s.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
        let n = match s.read(&mut buf) {
            Ok(0) => break,
            Err(_) if begun.is_some_and(|t| t.elapsed() >= tuning.message_wait) => {
                // A drip (or a device that ends its last message without an LF and keeps the
                // connection open): the connection goes, counted with the broken ones, and what
                // arrived of the message is still delivered, marked cut (RIN1-6).
                stats.broken.fetch_add(1, Ordering::Relaxed);
                let _ = s.shutdown(std::net::Shutdown::Both);
                if let Some(Frame::Msg(m, _)) = f.end()
                    && rate.take()
                {
                    let msg = Message::new(parse(&m), crate::host::now_filetime(), from, true, true);
                    let raws = if sink.keep_raw() { vec![m] } else { Vec::new() };
                    sink.messages(vec![msg], raws);
                }
                return;
            }
            // A socket timeout can fire a little before the time asked: a message's wait that
            // has not run out yet is waited out, never taken for the idle time.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) && begun.is_some() => continue,
            Err(_) => break, // closed, idle timeout, or stopped
            Ok(n) => n,
        };
        let mut batch = Vec::new();
        let mut raws = Vec::new();
        let frames = f.push(&buf[..n]);
        // A message still under way: begun now if this read finished another (or none was
        // under way), else as before.
        begun = match (f.mid(), begun) {
            (false, _) => None,
            (true, Some(t)) if frames.is_empty() => Some(t),
            (true, _) => Some(Instant::now()),
        };
        for fr in frames {
            match fr {
                Frame::Msg(m, cut) => {
                    if rate.take() {
                        let msg = Message::new(parse(&m), crate::host::now_filetime(), from, true, cut);
                        add(sink, &mut batch, &mut raws, msg, &m);
                    }
                }
                Frame::Broken(_) => {
                    stats.broken.fetch_add(1, Ordering::Relaxed);
                    if !batch.is_empty() {
                        sink.messages(batch, raws);
                    }
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    return;
                }
            }
        }
        if !batch.is_empty() {
            sink.messages(batch, raws);
        }
    }
    if let Some(Frame::Msg(m, cut)) = f.end()
        && rate.take()
    {
        let msg = Message::new(parse(&m), crate::host::now_filetime(), from, true, cut);
        let raws = if sink.keep_raw() { vec![m] } else { Vec::new() };
        sink.messages(vec![msg], raws);
    }
}

// ---------- the log file ----------

/// One day's file stops here.
pub const DAY_CAP: u64 = 1024 * 1024 * 1024;
/// Logging to file pauses below this much free space.
pub const MIN_FREE: u64 = 1024 * 1024 * 1024;
/// Files the app made in its own folder go after this many days.
pub const KEEP_DAYS: i64 = 30;

/// The daily file's name: `syslog-YYYY-MM-DD.log`.
pub fn day_file(c: &crate::host::Clock) -> String {
    format!("syslog-{}.log", c.date())
}

/// The date in a name the app makes (`syslog-YYYY-MM-DD.log`, nothing else), as days since 1970.
pub fn day_of_name(name: &str) -> Option<i64> {
    let d = name.strip_prefix("syslog-")?.strip_suffix(".log")?;
    let b = d.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || !d.bytes().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()) {
        return None;
    }
    let (y, m, day): (i64, u32, u32) = (d[..4].parse().ok()?, d[5..7].parse().ok()?, d[8..].parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(y, m, day))
}

/// Days since 1970-01-01 of a calendar date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// In the app's own syslog folder: remove its daily files older than `KEEP_DAYS` (by the date in
/// the name; only plain files with exactly that name form, never a folder or a link). Returns
/// how many went and how many could not be removed.
pub fn prune(folder: &Path, today: i64) -> (usize, usize) {
    let Ok(rd) = std::fs::read_dir(folder) else { return (0, 0) };
    let (mut gone, mut kept) = (0, 0);
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(String::from) else { continue };
        let Some(day) = day_of_name(&name) else { continue };
        if today - day <= KEEP_DAYS {
            continue;
        }
        // A plain file (not a folder, not a reparse point): symlink_metadata does not follow.
        let Ok(md) = std::fs::symlink_metadata(e.path()) else { continue };
        use std::os::windows::fs::MetadataExt;
        if !md.is_file() || md.file_attributes() & 0x400 != 0 {
            continue;
        }
        if std::fs::remove_file(e.path()).is_ok() { gone += 1 } else { kept += 1 }
    }
    (gone, kept)
}

/// A received message as one line of the log file: received time, source, protocol,
/// facility.severity, then the message as received with control characters escaped (\xNN), so
/// one message is always one line.
pub fn file_line(m: &Message, raw: &[u8]) -> String {
    let c = crate::host::local_clock(m.received);
    let mut s = format!("{}\t{}\t{}\t{}.{}\t", c.stamp_ms(), m.source.ip(), if m.tcp { "tcp" } else { "udp" }, facility_name(m.facility), severity_name(m.severity));
    for ch in String::from_utf8_lossy(raw).chars() {
        if ch.is_control() {
            s.push_str(&format!("\\x{:02x}", ch as u32 & 0xff));
        } else {
            s.push(ch);
        }
    }
    if m.cut {
        s.push_str(" [cut at 64 KiB]");
    }
    s.push_str("\r\n");
    s
}

/// What the file writer reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileState {
    Writing(PathBuf),
    /// Today's file reached the cap: nothing more today.
    DayFull(PathBuf),
    /// Less than 1 GiB free on the disk: paused until there is.
    DiskLow,
    /// The folder or file could not be written.
    Failed(String),
    Off,
}

/// The writer's limits (tests lower them).
#[derive(Clone, Copy, Debug)]
pub struct FileLimits {
    pub day_cap: u64,
    pub min_free: u64,
    /// Lines waiting for the writer, at most, by count and by bytes: past either, a line is not
    /// written, and counted.
    pub queue_lines: usize,
    pub queue_bytes: usize,
    /// A pause per line written (tests stand in for a slow disk with it); zero in the app.
    pub slow: Duration,
}

/// Lines waiting for the log file, at most.
pub const QUEUE_LINES: usize = 50_000;
/// Bytes waiting for the log file, at most.
pub const QUEUE_BYTES: usize = 8 * 1024 * 1024;

impl Default for FileLimits {
    fn default() -> FileLimits {
        FileLimits { day_cap: DAY_CAP, min_free: MIN_FREE, queue_lines: QUEUE_LINES, queue_bytes: QUEUE_BYTES, slow: Duration::ZERO }
    }
}

/// Appends lines to the daily file in `folder`, on its own thread; `told` hears each change of
/// state. The queue to the writer is bounded: a line that finds it full is not written and is
/// counted (`behind`), so a slow disk or share never grows memory. Letting go never waits: the
/// writer writes what is queued (at most `queue_bytes`) and ends on its own, telling nothing
/// more; `retire` hands over its thread for whoever wants to wait for it, with a bound.
pub struct FileLog {
    tx: Option<std::sync::mpsc::SyncSender<(u64, String)>>,
    thread: Option<std::thread::JoinHandle<()>>,
    queued: Arc<AtomicUsize>,
    behind: Arc<AtomicU64>,
    /// A line found the queue full.
    full: AtomicBool,
    /// Set once the owner let go: the writer's states are not told any more.
    quiet: Arc<AtomicBool>,
    max_bytes: usize,
}

impl FileLog {
    pub fn start(folder: PathBuf, limits: FileLimits, told: Box<dyn Fn(FileState) + Send>) -> FileLog {
        FileLog::start_after(folder, limits, told, None)
    }

    /// As `start`, but the writer first waits (at most 2 s) for an earlier writer to end, so two
    /// writers do not append to one file at once.
    pub fn start_after(folder: PathBuf, limits: FileLimits, told: Box<dyn Fn(FileState) + Send>, after: Option<std::thread::JoinHandle<()>>) -> FileLog {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(u64, String)>(limits.queue_lines.max(1));
        let queued: Arc<AtomicUsize> = Default::default();
        let quiet: Arc<AtomicBool> = Default::default();
        let behind: Arc<AtomicU64> = Default::default();
        let (q, qt, b) = (queued.clone(), quiet.clone(), behind.clone());
        let told: Box<dyn Fn(FileState) + Send> = Box::new(move |s| {
            if !qt.load(Ordering::SeqCst) {
                told(s)
            }
        });
        let thread = std::thread::Builder::new()
            .name("syslog-file".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                if let Some(t) = after {
                    wait_for(&t, Instant::now() + Duration::from_secs(2));
                }
                file_writer(folder, limits, rx, q, b, told)
            })
            .ok();
        FileLog { tx: Some(tx), thread, queued, behind, full: AtomicBool::new(false), quiet, max_bytes: limits.queue_bytes }
    }

    /// One line, received at `at` (FILETIME): its local date picks the file. Never waits: with
    /// the queue full the line is not written, and counted.
    pub fn line(&self, at: u64, line: String) {
        let Some(tx) = &self.tx else { return };
        let n = line.len();
        if self.queued.fetch_add(n, Ordering::SeqCst) + n > self.max_bytes || tx.try_send((at, line)).is_err() {
            self.queued.fetch_sub(n, Ordering::SeqCst);
            self.full.store(true, Ordering::Relaxed);
            self.behind.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whether lines went because the queue was full (the writer fell behind), not only with a
    /// failed write.
    pub fn fell_behind(&self) -> bool {
        self.full.load(Ordering::Relaxed)
    }

    /// Lines not written: the writer fell behind, or a write to the file failed with them still
    /// in its buffer.
    pub fn behind(&self) -> u64 {
        self.behind.load(Ordering::Relaxed)
    }

    /// Let go: the writer writes what is queued and ends, telling nothing more. Its thread, for
    /// a bounded wait (`wait_for`).
    pub fn retire(mut self) -> Option<std::thread::JoinHandle<()>> {
        self.thread.take()
    }
}

impl Drop for FileLog {
    fn drop(&mut self) {
        self.quiet.store(true, Ordering::SeqCst);
        self.tx = None;
    }
}

pub use crate::listen::wait_for;

/// The lines a file writer's buffer still holds (one message is one line, ending in a newline).
fn lines_held(w: &std::io::BufWriter<std::fs::File>) -> u64 {
    w.buffer().iter().filter(|b| **b == b'\n').count() as u64
}

fn file_writer(folder: PathBuf, limits: FileLimits, rx: std::sync::mpsc::Receiver<(u64, String)>, queued: Arc<AtomicUsize>, behind: Arc<AtomicU64>, told: Box<dyn Fn(FileState) + Send>) {
    use std::io::Write;
    let mut state = FileState::Off;
    let set = |s: FileState, state: &mut FileState| {
        if *state != s {
            *state = s.clone();
            told(s);
        }
    };
    // A failure is said once: the state stays "Failed" until a flush has worked (a line that
    // only entered the buffer is not written yet), so a file that opens but cannot be written
    // is not told again on every line (RVB6).
    let fail = |why: String, state: &mut FileState| {
        if !matches!(state, FileState::Failed(_)) {
            set(FileState::Failed(why), state);
        }
    };
    type Out = Option<(String, std::io::BufWriter<std::fs::File>, u64)>;
    // The buffer to the disk. On a failure the lines it held are counted as not written first
    // (so the state is never told without its count, RVB7), then dropped without another try (a
    // retry could land part of them after they were counted). A flush that works after a
    // failure says the file again.
    let flush = |out: &mut Out, state: &mut FileState| {
        let Some((name, w, _)) = out.as_mut() else { return };
        let path = folder.join(&*name);
        match w.flush() {
            Ok(()) if matches!(state, FileState::Failed(_)) => set(FileState::Writing(path), state),
            Ok(()) => {}
            Err(e) => {
                behind.fetch_add(lines_held(w), Ordering::Relaxed);
                fail(format!("{}: {e}", crate::text::clean_path(&path)), state);
                if let Some((_, w, _)) = out.take() {
                    let _ = w.into_parts();
                }
            }
        }
    };
    let mut out: Out = None;
    let mut free_checked: Option<Instant> = None;
    let mut low = false;
    let mut flushed = Instant::now();
    loop {
        let got = rx.recv_timeout(Duration::from_secs(1));
        // The buffer reaches the disk once a second: after a quiet second, and in a steady
        // stream once a second has passed since the last time (RVB4).
        if matches!(got, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) || flushed.elapsed() >= Duration::from_secs(1) {
            flushed = Instant::now();
            flush(&mut out, &mut state);
        }
        let (at, line) = match got {
            Ok(x) => x,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        queued.fetch_sub(line.len(), Ordering::SeqCst);
        if !limits.slow.is_zero() {
            std::thread::sleep(limits.slow);
        }
        // The free space, every 10 s (and at once after a pause).
        if free_checked.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
            free_checked = Some(Instant::now());
            let w: Vec<u16> = {
                use std::os::windows::ffi::OsStrExt;
                folder.as_os_str().encode_wide().collect()
            };
            let _ = std::fs::create_dir_all(&folder);
            low = matches!(crate::paths::free_space(&w), Some(f) if f < limits.min_free);
        }
        if low {
            if let Some((_, w, _)) = out.as_mut() {
                let _ = w.flush();
            }
            set(FileState::DiskLow, &mut state);
            continue;
        }
        let name = day_file(&crate::host::local_clock(at));
        if out.as_ref().is_none_or(|(n, _, _)| *n != name) {
            // The day's last lines: a failed flush is said and counted, as once a second (RVB5).
            flush(&mut out, &mut state);
            out = None;
            let path = folder.join(&name);
            let opened = std::fs::create_dir_all(&folder).and_then(|_| std::fs::OpenOptions::new().append(true).create(true).open(&path));
            match opened {
                Ok(f) => {
                    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
                    out = Some((name.clone(), std::io::BufWriter::with_capacity(64 * 1024, f), len));
                }
                Err(e) => {
                    fail(format!("{}: {e}", crate::text::clean_path(&path)), &mut state);
                    continue;
                }
            }
        }
        let Some((_, w, len)) = out.as_mut() else { continue };
        let path = folder.join(&name);
        if *len + line.len() as u64 > limits.day_cap {
            let _ = w.flush();
            set(FileState::DayFull(path), &mut state);
            continue;
        }
        match w.write_all(line.as_bytes()) {
            Ok(()) => {
                *len += line.len() as u64;
                // In the buffer, not on the disk: after a failure the next working flush says
                // the file again.
                if !matches!(state, FileState::Failed(_)) {
                    set(FileState::Writing(path), &mut state);
                }
            }
            Err(e) => {
                // This line and those the buffer still held are not written: counted, then said.
                behind.fetch_add(lines_held(w) + 1, Ordering::Relaxed);
                fail(format!("{}: {e}", crate::text::clean_path(&path)), &mut state);
                if let Some((_, w, _)) = out.take() {
                    let _ = w.into_parts();
                }
            }
        }
    }
    if let Some((_, mut w, _)) = out {
        let _ = w.flush();
    }
}
