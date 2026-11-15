//! TFTP (RFC 1350) with option negotiation (RFC 2347: blksize RFC 2348, tsize RFC 2349, timeout,
//! windowsize RFC 7440).
//!
//! The packet codec, the option negotiation, netascii both ways and the two transfer engines
//! (`send`, `receive`) are plain Rust over a `Link`: the tests drive them over a scripted lossy
//! channel. The server reads requests on its port, and gives each transfer a socket of its own
//! (its TID) bound to the address the request arrived at, on a thread of its own (at most 32).
//!
//! Retransmission happens on a timeout only, never on a duplicate ACK (the Sorcerer's
//! Apprentice, RFC 1123 4.2.3.1); a duplicate ACK neither resends nor moves the timeout. Packets
//! from a wrong TID get error 5 and leave the transfer alone. Block numbers roll over to 0
//! after 65535.

use crate::activity::{Entry, Kind, Outcome, Report};
use crate::listen::{Bind, BindError, Ready, Stop, Woke};
use crate::paths::{Found, Miss, Share, WriteError};
use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The log's words for a transfer whose file call returned after the server stopped.
const STOPPED: &str = "the server stopped while the file was opened";

pub const RRQ: u16 = 1;
pub const WRQ: u16 = 2;
pub const DATA: u16 = 3;
pub const ACK: u16 = 4;
pub const ERROR: u16 = 5;
pub const OACK: u16 = 6;

pub const E_UNDEFINED: u16 = 0;
pub const E_NOT_FOUND: u16 = 1;
pub const E_ACCESS: u16 = 2;
pub const E_DISK_FULL: u16 = 3;
pub const E_ILLEGAL: u16 = 4;
pub const E_UNKNOWN_TID: u16 = 5;
pub const E_EXISTS: u16 = 6;
pub const E_OPTIONS: u16 = 8;

/// A request longer than this is refused (RFC 2347 asks clients for 512; room to spare).
pub const MAX_REQUEST: usize = 2048;
/// The largest blksize answered over IPv4: a 1500-byte Ethernet frame minus IPv4 (20), UDP (8)
/// and TFTP (4) headers, so no block is fragmented.
pub const BLKSIZE_V4: usize = 1468;
/// The same over IPv6 (a 40-byte header).
pub const BLKSIZE_V6: usize = 1448;
pub const DEFAULT_BLKSIZE: usize = 512;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
pub const RETRIES: u32 = 5;
/// The longest timeout option taken: a larger one is left out of the OACK (RFC 2349 lets a
/// server decline it, not answer another value), so a silent client holds a transfer slot for
/// at most 6 x 30 s, not 6 x 255 s.
pub const MAX_TIMEOUT: u64 = 30;
pub const MAX_WINDOW: usize = 64;
pub const MAX_TRANSFERS: usize = 32;
/// One address runs at most this many of them at once (IN-VibeServe-3).
pub const PER_PEER: usize = 8;
/// The log's words for a request from outside the local network (SNA4).
pub const OUTSIDE: &str = "ignored: not on this PC's local network";

/// What the server runs with (tests lower the caps and the pace).
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    pub max_transfers: usize,
    pub per_peer: usize,
    /// The slowest a transfer may run (IN-VibeServe-3).
    pub pace: crate::listen::Pace,
    /// Whether a peer may make a request (SNA4): `listen::on_lan` in the app (tests: every peer
    /// is loopback, so they stand in another rule).
    pub lan: fn(IpAddr) -> bool,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning { max_transfers: MAX_TRANSFERS, per_peer: PER_PEER, pace: crate::listen::PACE, lan: crate::listen::on_lan }
    }
}

// ---------- packets ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Request { write: bool, file: &'a [u8], mode: &'a [u8], options: Vec<(&'a [u8], &'a [u8])> },
    Data { block: u16, data: &'a [u8] },
    Ack { block: u16 },
    Error { code: u16, msg: &'a [u8] },
    Oack { options: Vec<(&'a [u8], &'a [u8])> },
}

/// Why a datagram is not a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    Short,
    Opcode(u16),
    /// A string without its terminating NUL.
    Unterminated,
    /// An option name without a value.
    Options,
    TooLong,
}

/// NUL-terminated strings from `b`, every one terminated.
fn strings(b: &[u8]) -> Result<Vec<&[u8]>, Bad> {
    if b.is_empty() {
        return Ok(Vec::new());
    }
    if *b.last().unwrap() != 0 {
        return Err(Bad::Unterminated);
    }
    Ok(b[..b.len() - 1].split(|&c| c == 0).collect())
}

/// Option names and values, as they came.
type Options<'a> = Vec<(&'a [u8], &'a [u8])>;

fn pairs<'a>(v: &[&'a [u8]]) -> Result<Options<'a>, Bad> {
    if !v.len().is_multiple_of(2) {
        return Err(Bad::Options);
    }
    Ok(v.chunks(2).map(|c| (c[0], c[1])).collect())
}

pub fn parse(b: &[u8]) -> Result<Packet<'_>, Bad> {
    if b.len() < 4 {
        // An ACK, a DATA or an ERROR has at least opcode and block/code.
        return Err(Bad::Short);
    }
    let op = u16::from_be_bytes([b[0], b[1]]);
    let rest = &b[2..];
    match op {
        RRQ | WRQ => {
            if b.len() > MAX_REQUEST {
                return Err(Bad::TooLong);
            }
            let s = strings(rest)?;
            if s.len() < 2 || s[0].is_empty() || s[1].is_empty() {
                return Err(Bad::Unterminated);
            }
            Ok(Packet::Request { write: op == WRQ, file: s[0], mode: s[1], options: pairs(&s[2..])? })
        }
        DATA => Ok(Packet::Data { block: u16::from_be_bytes([rest[0], rest[1]]), data: &rest[2..] }),
        ACK => Ok(Packet::Ack { block: u16::from_be_bytes([rest[0], rest[1]]) }),
        ERROR => {
            let code = u16::from_be_bytes([rest[0], rest[1]]);
            let m = &rest[2..];
            // Lenient: a message without its NUL is still a message.
            let msg = match m.iter().position(|&c| c == 0) {
                Some(i) => &m[..i],
                None => m,
            };
            Ok(Packet::Error { code, msg })
        }
        OACK => {
            if b.len() > MAX_REQUEST {
                return Err(Bad::TooLong);
            }
            Ok(Packet::Oack { options: pairs(&strings(rest)?)? })
        }
        o => Err(Bad::Opcode(o)),
    }
}

pub fn data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&DATA.to_be_bytes());
    v.extend_from_slice(&block.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub fn ack(block: u16) -> Vec<u8> {
    let mut v = ACK.to_be_bytes().to_vec();
    v.extend_from_slice(&block.to_be_bytes());
    v
}

/// An error packet; the message in ASCII (anything else becomes '?').
pub fn error(code: u16, msg: &str) -> Vec<u8> {
    let mut v = ERROR.to_be_bytes().to_vec();
    v.extend_from_slice(&code.to_be_bytes());
    v.extend(msg.chars().take(200).map(|c| if c.is_ascii() && !c.is_ascii_control() { c as u8 } else { b'?' }));
    v.push(0);
    v
}

pub fn oack(options: &[(String, String)]) -> Vec<u8> {
    let mut v = OACK.to_be_bytes().to_vec();
    for (k, val) in options {
        v.extend_from_slice(k.as_bytes());
        v.push(0);
        v.extend_from_slice(val.as_bytes());
        v.push(0);
    }
    v
}

/// A request (for tests and the in-test client).
pub fn request(write: bool, file: &str, mode: &str, options: &[(&str, &str)]) -> Vec<u8> {
    let mut v = if write { WRQ } else { RRQ }.to_be_bytes().to_vec();
    for s in [file, mode].into_iter().chain(options.iter().flat_map(|(k, val)| [*k, *val])) {
        v.extend_from_slice(s.as_bytes());
        v.push(0);
    }
    v
}

// ---------- options ----------

/// What a transfer runs with, and the OACK that says so (empty: no OACK, RFC 1350 as is).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agreed {
    pub blksize: usize,
    pub timeout: Duration,
    pub windowsize: usize,
    /// WRQ: the size the client announced; RRQ: the size answered.
    pub tsize: Option<u64>,
    pub oack: Vec<(String, String)>,
}

impl Default for Agreed {
    fn default() -> Agreed {
        Agreed { blksize: DEFAULT_BLKSIZE, timeout: DEFAULT_TIMEOUT, windowsize: 1, tsize: None, oack: Vec::new() }
    }
}

fn number(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// Answer the options a request carried. Unknown options and invalid values are left out of the
/// OACK (the RFCs' way to refuse an option); only the first of a repeated option counts.
/// `file_size`: the file's size for an RRQ in octet mode (tsize is not answered for netascii).
pub fn negotiate(options: &[(&[u8], &[u8])], write: bool, netascii: bool, file_size: Option<u64>, v6: bool) -> Agreed {
    let mut a = Agreed::default();
    let mut seen: Vec<String> = Vec::new();
    for (k, v) in options {
        let name = String::from_utf8_lossy(k).to_ascii_lowercase();
        if seen.contains(&name) {
            continue;
        }
        seen.push(name.clone());
        let Some(n) = number(v) else { continue };
        match name.as_str() {
            "blksize" if n >= 8 => {
                let cap = if v6 { BLKSIZE_V6 } else { BLKSIZE_V4 };
                a.blksize = (n.min(65_464) as usize).min(cap);
                a.oack.push((name, a.blksize.to_string()));
            }
            "timeout" if (1..=MAX_TIMEOUT).contains(&n) => {
                a.timeout = Duration::from_secs(n);
                a.oack.push((name, n.to_string()));
            }
            "tsize" if write => {
                a.tsize = Some(n);
                a.oack.push((name, n.to_string()));
            }
            "tsize" if !netascii => {
                if let Some(size) = file_size {
                    a.tsize = Some(size);
                    a.oack.push((name, size.to_string()));
                }
            }
            "windowsize" if (1..=65_535).contains(&n) => {
                a.windowsize = (n as usize).min(MAX_WINDOW);
                a.oack.push((name, a.windowsize.to_string()));
            }
            _ => {}
        }
    }
    a
}

// ---------- netascii ----------

/// A file's bytes as netascii on the wire. Windows text already ends its lines with CR LF, which
/// passes as is; a lone LF becomes CR LF and a lone CR becomes CR NUL (DECISIONS.md).
pub struct ToNetascii<R: Read> {
    inner: R,
    out: VecDeque<u8>,
    cr: bool,
    eof: bool,
}

impl<R: Read> ToNetascii<R> {
    pub fn new(inner: R) -> ToNetascii<R> {
        ToNetascii { inner, out: VecDeque::new(), cr: false, eof: false }
    }
}

impl<R: Read> Read for ToNetascii<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.out.len() < buf.len() && !self.eof {
            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk)?;
            if n == 0 {
                self.eof = true;
                if self.cr {
                    self.out.push_back(0);
                    self.cr = false;
                }
                break;
            }
            for &b in &chunk[..n] {
                if self.cr {
                    self.cr = false;
                    if b == b'\n' {
                        self.out.push_back(b'\n');
                        continue;
                    }
                    self.out.push_back(0);
                }
                match b {
                    b'\r' => {
                        self.out.push_back(b'\r');
                        self.cr = true;
                    }
                    b'\n' => self.out.extend(*b"\r\n"),
                    _ => self.out.push_back(b),
                }
            }
        }
        let n = buf.len().min(self.out.len());
        for (i, b) in self.out.drain(..n).enumerate() {
            buf[i] = b;
        }
        Ok(n)
    }
}

/// Netascii from the wire as the file keeps it: CR NUL is a CR, CR LF stays (Windows text).
#[derive(Default)]
pub struct FromNetascii {
    cr: bool,
}

impl FromNetascii {
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &b in input {
            if self.cr {
                self.cr = false;
                match b {
                    0 => {
                        out.push(b'\r');
                        continue;
                    }
                    b'\n' => {
                        out.extend_from_slice(b"\r\n");
                        continue;
                    }
                    _ => out.push(b'\r'),
                }
            }
            if b == b'\r' {
                self.cr = true;
            } else {
                out.push(b);
            }
        }
    }

    pub fn end(&mut self, out: &mut Vec<u8>) {
        if self.cr {
            out.push(b'\r');
            self.cr = false;
        }
    }
}

// ---------- the transfer engines ----------

/// What a wait on the link brought.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Got {
    Packet(usize),
    Timeout,
    Stopped,
}

/// The transfer's socket, as the engines see it: packets from its peer only (the link answers
/// strangers with error 5 itself).
pub trait Link {
    fn send(&mut self, b: &[u8]) -> std::io::Result<()>;
    fn recv(&mut self, buf: &mut [u8], until: Instant) -> std::io::Result<Got>;
}

/// How a transfer failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The peer went quiet through every retry.
    Timeout,
    /// The peer sent an error.
    Peer(u16, String),
    /// The client declined the OACK (error 8): a clean end.
    Declined,
    /// The server stopped.
    Stopped,
    /// The client fell behind the pace (IN-VibeServe-3): ended with "too slow".
    Slow,
    /// We ended it with this error (sent to the peer).
    Local(u16, String),
    /// The socket failed.
    Io(String),
}

impl Fail {
    pub fn words(&self) -> String {
        match self {
            Fail::Timeout => format!("timed out after {RETRIES} retries"),
            Fail::Peer(c, m) => format!("the client sent error {c}: {}", crate::text::clean(m)),
            Fail::Declined => "the client declined the options".into(),
            Fail::Stopped => "stopped with the server".into(),
            Fail::Slow => "cut: the client was too slow".into(),
            Fail::Local(c, m) => format!("error {c}: {m}"),
            Fail::Io(e) => format!("socket error: {e}"),
        }
    }
}

fn io(e: std::io::Error) -> Fail {
    if e.get_ref().is_some_and(|x| x.is::<StoppedSend>()) {
        return Fail::Stopped;
    }
    Fail::Io(e.to_string())
}

/// A send refused because the server has stopped (`UdpLink::send`).
#[derive(Debug)]
struct StoppedSend;

impl std::fmt::Display for StoppedSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server stopped")
    }
}

impl std::error::Error for StoppedSend {}

/// A block number on the wire for the n-th block (rolls over to 0 after 65535).
pub fn wire(n: u64) -> u16 {
    (n % 65_536) as u16
}

/// Up to `len` bytes: fewer only at the end of the stream.
fn read_block(src: &mut dyn Read, len: usize) -> std::io::Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    let mut got = 0;
    while got < len {
        let n = src.read(&mut v[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    v.truncate(got);
    Ok(v)
}

/// Send a file (RRQ). With `send_oack`, the OACK goes first and must be acknowledged with ACK 0.
/// Returns the bytes the client acknowledged. `progress` hears the bytes so far and says whether
/// the transfer keeps its pace (false: it ends as too slow, IN-VibeServe-3).
pub fn send(link: &mut dyn Link, src: &mut dyn Read, a: &Agreed, send_oack: bool, retries: u32, progress: &dyn Fn(u64) -> bool) -> Result<u64, Fail> {
    let mut buf = vec![0u8; 65_536];
    if send_oack {
        let pkt = oack(&a.oack);
        link.send(&pkt).map_err(io)?;
        let mut tries = 0;
        let mut deadline = Instant::now() + a.timeout;
        loop {
            match link.recv(&mut buf, deadline).map_err(io)? {
                Got::Timeout => {
                    // RIN1-5: the pace holds on a quiet link too (a spoofed RRQ never ACKs).
                    if !progress(0) {
                        let _ = link.send(&error(E_UNDEFINED, "too slow"));
                        return Err(Fail::Slow);
                    }
                    tries += 1;
                    if tries > retries {
                        return Err(Fail::Timeout);
                    }
                    link.send(&pkt).map_err(io)?;
                    deadline = Instant::now() + a.timeout;
                }
                Got::Stopped => return Err(Fail::Stopped),
                Got::Packet(n) => match parse(&buf[..n]) {
                    Ok(Packet::Ack { block: 0 }) => break,
                    Ok(Packet::Error { code: E_OPTIONS, .. }) => return Err(Fail::Declined),
                    Ok(Packet::Error { code, msg }) => return Err(Fail::Peer(code, String::from_utf8_lossy(msg).into())),
                    _ => {}
                },
            }
        }
    }
    let (b, w) = (a.blksize, a.windowsize.max(1));
    let mut window: VecDeque<Vec<u8>> = VecDeque::new();
    let mut base: u64 = 1;
    let mut last_queued = false;
    let mut acked: u64 = 0;
    let mut tries = 0;
    loop {
        while window.len() < w && !last_queued {
            let blk = read_block(src, b).map_err(|e| {
                let _ = link.send(&error(E_UNDEFINED, "read error"));
                Fail::Local(E_UNDEFINED, format!("the file could not be read: {e}"))
            })?;
            last_queued = blk.len() < b;
            window.push_back(blk);
        }
        for (i, blk) in window.iter().enumerate() {
            link.send(&data(wire(base + i as u64), blk)).map_err(io)?;
        }
        // The timeout runs from the last send; nothing but progress resets it.
        let mut deadline = Instant::now() + a.timeout;
        'wait: loop {
            match link.recv(&mut buf, deadline).map_err(io)? {
                Got::Timeout => {
                    // RIN1-5: judged on every timeout, not only when an ACK moves it on.
                    if !progress(acked) {
                        let _ = link.send(&error(E_UNDEFINED, "too slow"));
                        return Err(Fail::Slow);
                    }
                    tries += 1;
                    if tries > retries {
                        let _ = link.send(&error(E_UNDEFINED, "timed out"));
                        return Err(Fail::Timeout);
                    }
                    for (i, blk) in window.iter().enumerate() {
                        link.send(&data(wire(base + i as u64), blk)).map_err(io)?;
                    }
                    deadline = Instant::now() + a.timeout;
                }
                Got::Stopped => {
                    let _ = link.send(&error(E_UNDEFINED, "server stopped"));
                    return Err(Fail::Stopped);
                }
                Got::Packet(n) => match parse(&buf[..n]) {
                    Ok(Packet::Ack { block }) => {
                        let diff = block.wrapping_sub(wire(base)) as usize;
                        if diff < window.len() {
                            for blk in window.drain(..=diff) {
                                acked += blk.len() as u64;
                            }
                            base += diff as u64 + 1;
                            tries = 0;
                            let on_pace = progress(acked);
                            if window.is_empty() && last_queued {
                                return Ok(acked);
                            }
                            if !on_pace {
                                let _ = link.send(&error(E_UNDEFINED, "too slow"));
                                return Err(Fail::Slow);
                            }
                            // A new window from the block after the one acknowledged.
                            break 'wait;
                        }
                        // A duplicate or stray ACK: nothing is resent, the timeout stands.
                    }
                    Ok(Packet::Error { code, msg }) => return Err(Fail::Peer(code, String::from_utf8_lossy(msg).into())),
                    _ => {}
                },
            }
        }
    }
}

/// Where received bytes go (the upload behind it). Errors carry the TFTP code to send.
pub trait Sink {
    fn write(&mut self, b: &[u8]) -> Result<(), (u16, String)>;
    fn finish(&mut self) -> Result<(), (u16, String)>;
}

/// Receive a file (WRQ). The OACK (with options) or ACK 0 goes first. Returns the bytes taken.
pub fn receive(link: &mut dyn Link, sink: &mut dyn Sink, a: &Agreed, send_oack: bool, retries: u32, progress: &dyn Fn(u64) -> bool) -> Result<u64, Fail> {
    let mut buf = vec![0u8; 65_536];
    let first = if send_oack { oack(&a.oack) } else { ack(0) };
    let mut last = first.clone();
    link.send(&last).map_err(io)?;
    let (b, w) = (a.blksize, a.windowsize.max(1));
    let mut expected: u64 = 1;
    let mut in_window = 0usize;
    let mut tries = 0;
    let mut total: u64 = 0;
    // A gap or a duplicate is answered once (the ACK of the last block in order), then quiet
    // until a block in order or a timeout: one window per ACK, never a storm of them.
    let mut gap_told = false;
    let mut deadline = Instant::now() + a.timeout;
    loop {
        match link.recv(&mut buf, deadline).map_err(io)? {
            Got::Timeout => {
                // RIN1-5: judged on every timeout, not only when a block moves it on.
                if !progress(total) {
                    let _ = link.send(&error(E_UNDEFINED, "too slow"));
                    return Err(Fail::Slow);
                }
                tries += 1;
                if tries > retries {
                    let _ = link.send(&error(E_UNDEFINED, "timed out"));
                    return Err(Fail::Timeout);
                }
                link.send(&last).map_err(io)?;
                gap_told = false;
                in_window = 0;
                deadline = Instant::now() + a.timeout;
            }
            Got::Stopped => {
                let _ = link.send(&error(E_UNDEFINED, "server stopped"));
                return Err(Fail::Stopped);
            }
            Got::Packet(n) => match parse(&buf[..n]) {
                Ok(Packet::Data { block, data: d }) if block == wire(expected) => {
                    if d.len() > b {
                        let msg = format!("a block of {} bytes is larger than the agreed blksize {b}", d.len());
                        let _ = link.send(&error(E_ILLEGAL, "block larger than blksize"));
                        return Err(Fail::Local(E_ILLEGAL, msg));
                    }
                    if let Err((code, msg)) = sink.write(d) {
                        let _ = link.send(&error(code, &msg));
                        return Err(Fail::Local(code, msg));
                    }
                    total += d.len() as u64;
                    expected += 1;
                    in_window += 1;
                    tries = 0;
                    gap_told = false;
                    let on_pace = progress(total);
                    if d.len() >= b && !on_pace {
                        let _ = link.send(&error(E_UNDEFINED, "too slow"));
                        return Err(Fail::Slow);
                    }
                    if d.len() < b {
                        if let Err((code, msg)) = sink.finish() {
                            let _ = link.send(&error(code, &msg));
                            return Err(Fail::Local(code, msg));
                        }
                        last = ack(block);
                        link.send(&last).map_err(io)?;
                        dally(link, &mut buf, &last, block, a.timeout);
                        return Ok(total);
                    }
                    if in_window >= w {
                        last = ack(block);
                        link.send(&last).map_err(io)?;
                        in_window = 0;
                    }
                    deadline = Instant::now() + a.timeout;
                }
                Ok(Packet::Data { .. }) => {
                    // Out of order or a duplicate: acknowledge the last block in order (our ACK
                    // or one of its blocks was lost); before any data, the first answer again.
                    if !gap_told {
                        last = if expected == 1 { first.clone() } else { ack(wire(expected - 1)) };
                        link.send(&last).map_err(io)?;
                        gap_told = true;
                    }
                    in_window = 0;
                }
                // The client declined our OACK (RFC 2347): a clean end, as on a read.
                Ok(Packet::Error { code: E_OPTIONS, .. }) if send_oack && expected == 1 => return Err(Fail::Declined),
                Ok(Packet::Error { code, msg }) => return Err(Fail::Peer(code, String::from_utf8_lossy(msg).into())),
                _ => {}
            },
        }
    }
}

/// After the final ACK: answer a repeated final block (our ACK was lost) until the peer is quiet.
fn dally(link: &mut dyn Link, buf: &mut [u8], last: &[u8], block: u16, timeout: Duration) {
    let mut deadline = Instant::now() + timeout;
    for _ in 0..3 {
        match link.recv(buf, deadline) {
            Ok(Got::Packet(n)) => {
                if let Ok(Packet::Data { block: k, .. }) = parse(&buf[..n])
                    && k == block
                {
                    let _ = link.send(last);
                    deadline = Instant::now() + timeout;
                }
            }
            _ => return,
        }
    }
}

// ---------- the server ----------

/// A transfer underway, for the card.
pub struct Live {
    pub id: u64,
    pub peer: SocketAddr,
    /// "/c9300.bin" (as asked; cleaned when shown).
    pub file: String,
    pub write: bool,
    pub bytes: AtomicU64,
    /// The size when known (tsize, or the file's size).
    pub total: AtomicU64,
    pub started: Instant,
}

/// A running TFTP server. Dropping it stops it (and every transfer, their temp files removed).
pub struct Server {
    stop: Arc<Stop>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The transfers' threads, handed over when the listener ends.
    handed: crate::listen::Handed,
    pub local: SocketAddr,
    pub live: Arc<Mutex<Vec<Arc<Live>>>>,
}

impl Server {
    /// Stop, waiting at most `HALT_WAIT`: how many threads were left running (a transfer in a
    /// file open that ignores the stop; it ends when that open lets go, which may be never: see
    /// DECISIONS).
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
        crate::listen::halt(&self.stop, self.thread.take().into_iter().collect(), &self.handed, within)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Once only (`listen::halt`): after a stop this takes nothing.
        self.halt(crate::listen::HALT_WAIT);
    }
}

pub fn start(bind: &Bind, port: u16, shared: Arc<Share>, tuning: Tuning, report: Arc<dyn Report>) -> Result<Server, BindError> {
    let sock = crate::listen::udp(bind, port, true)?;
    crate::listen::set_recv_buffer(&sock, 1024 * 1024);
    let local = sock.local_addr().map_err(|e| BindError::Other(e.to_string()))?;
    let ready = Ready::new(&sock, windows_sys::Win32::Networking::WinSock::FD_READ).map_err(|e| BindError::Other(e.to_string()))?;
    let stop = Stop::new();
    let live: Arc<Mutex<Vec<Arc<Live>>>> = Default::default();
    let handed: crate::listen::Handed = Default::default();
    let (st, lv, b, hd) = (stop.clone(), live.clone(), bind.clone(), handed.clone());
    let thread = std::thread::Builder::new()
        .name("tftp".into())
        .stack_size(256 * 1024)
        .spawn(move || listener(sock, ready, b, st, shared, tuning, report, lv, hd))
        .map_err(|e| BindError::Other(e.to_string()))?;
    Ok(Server { stop, thread: Some(thread), handed, local, live })
}

type Key = (SocketAddr, bool, Vec<u8>);

#[allow(clippy::too_many_arguments)]
fn listener(sock: UdpSocket, ready: Ready, bind: Bind, stop: Arc<Stop>, shared: Arc<Share>, tuning: Tuning, report: Arc<dyn Report>, live: Arc<Mutex<Vec<Arc<Live>>>>, handed: crate::listen::Handed) {
    let mut buf = vec![0u8; 65_536];
    let peers: Arc<crate::listen::Peers> = Default::default();
    let active: Arc<Mutex<HashSet<Key>>> = Default::default();
    let mut sessions: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut next_id: u64 = 1;
    loop {
        sessions.retain(|h| !h.is_finished());
        // RL8-1: on every turn, not only when the socket is quiet (a steady stream of requests
        // never keeps it open past its stop).
        if stop.stopped() {
            break;
        }
        let (n, peer, dst) = match crate::listen::recv_msg(&sock, &mut buf) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if ready.wait(&stop, None) == Woke::Stopped {
                    break;
                }
                continue;
            }
            Err(_) => {
                // A socket error (an ICMP echo of an earlier packet): never spin on it.
                if stop.stopped() {
                    break;
                }
                stop.sleep(Duration::from_millis(5));
                continue;
            }
        };
        let local_ip = match (dst, &bind) {
            (Some((ip, ifx)), _) => (ip, if matches!(ip, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80) { ifx } else { 0 }),
            (None, Bind::One(ip, s)) => (*ip, *s),
            (None, Bind::All) => (if peer.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) }, 0),
        };
        let pkt = &buf[..n];
        let started = crate::host::now_filetime();
        // SNA4: a peer outside the local network gets no answer at all (no error either: a
        // spoofed source must not make this server send anything); its requests are logged.
        if !(tuning.lan)(peer.ip()) {
            if let Ok(Packet::Request { write, file, mode, options }) = parse(pkt) {
                report.entry(Kind::Tftp, Entry { at: started, peer, request: describe(write, file, mode, &options), bytes: 0, result: OUTSIDE.into(), outcome: Outcome::Refused, duration: Duration::ZERO });
            }
            continue;
        }
        let refuse = |code: u16, msg: &str, request: String, result: String| {
            if let Ok(s) = crate::listen::udp_from(local_ip.0, local_ip.1) {
                let _ = s.send_to(&error(code, msg), peer);
            }
            report.entry(Kind::Tftp, Entry { at: started, peer, request, bytes: 0, result, outcome: Outcome::Refused, duration: Duration::ZERO });
        };
        match parse(pkt) {
            Ok(Packet::Request { write, file, mode, options }) => {
                let key: Key = (peer, write, file.to_vec());
                if active.lock().unwrap_or_else(|e| e.into_inner()).contains(&key) {
                    continue; // a repeated request for a transfer that runs: ignored
                }
                let req_text = describe(write, file, mode, &options);
                if sessions.len() >= tuning.max_transfers {
                    refuse(E_UNDEFINED, &format!("server busy: {} transfers running", tuning.max_transfers), req_text, format!("refused: {} transfers already running", tuning.max_transfers));
                    continue;
                }
                // IN-VibeServe-3: one address never takes every slot.
                let Some(slot) = peers.take(peer.ip(), tuning.per_peer) else {
                    refuse(E_UNDEFINED, &format!("server busy: {} transfers from your address", tuning.per_peer), req_text, format!("refused: {} transfers already running from this address", tuning.per_peer));
                    continue;
                };
                active.lock().unwrap_or_else(|e| e.into_inner()).insert(key.clone());
                let opts: Vec<(Vec<u8>, Vec<u8>)> = options.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
                let job = Job { id: next_id, peer, local: local_ip, write, file: file.to_vec(), mode: mode.to_vec(), options: opts, started, request: req_text };
                next_id += 1;
                let (st, sh, rp, lv, ac, pace) = (stop.clone(), shared.clone(), report.clone(), live.clone(), active.clone(), tuning.pace);
                let spawned = std::thread::Builder::new().name("tftp-transfer".into()).stack_size(256 * 1024).spawn(move || {
                    let _slot = slot;
                    session(&job, &st, &sh, rp.as_ref(), &lv, pace);
                    ac.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                });
                match spawned {
                    Ok(h) => sessions.push(h),
                    Err(_) => {
                        active.lock().unwrap_or_else(|e| e.into_inner()).remove(&(peer, write, file.to_vec()));
                    }
                }
            }
            Ok(Packet::Error { .. }) => {} // never answer an error with an error
            Ok(Packet::Data { .. } | Packet::Ack { .. } | Packet::Oack { .. }) => {
                refuse(E_UNKNOWN_TID, "unknown transfer ID", format!("opcode {} to the server port", u16::from_be_bytes([pkt[0], pkt[1]])), "refused: not a request".into());
            }
            Err(Bad::Short) => {} // too short to be anything: no answer
            Err(why) => {
                refuse(E_ILLEGAL, "illegal TFTP operation", format!("{n} bytes"), format!("refused: malformed ({why:?})"));
            }
        }
    }
    // `halt` waits for them (bounded).
    handed.lock().unwrap_or_else(|e| e.into_inner()).extend(sessions);
}

/// "RRQ /c9300.bin octet blksize 1468 tsize 0" (raw: cleaned when shown).
fn describe(write: bool, file: &[u8], mode: &[u8], options: &[(&[u8], &[u8])]) -> String {
    let mut s = format!("{} {} {}", if write { "WRQ" } else { "RRQ" }, String::from_utf8_lossy(file), String::from_utf8_lossy(mode).to_ascii_lowercase());
    for (k, v) in options.iter().take(8) {
        s.push_str(&format!(" {} {}", String::from_utf8_lossy(k), String::from_utf8_lossy(v)));
    }
    s
}

struct Job {
    id: u64,
    peer: SocketAddr,
    local: (IpAddr, u32),
    write: bool,
    file: Vec<u8>,
    mode: Vec<u8>,
    options: Vec<(Vec<u8>, Vec<u8>)>,
    started: u64,
    request: String,
}

/// The transfer's socket: packets from the peer's address and port only; anyone else gets
/// error 5 and the transfer goes on.
struct UdpLink<'a> {
    // `ready` before `sock`: fields drop in this order, and `Ready`'s drop deselects the socket
    // by its handle. Closed first, the handle can already be another socket's (Windows hands
    // a freed handle out again at once, and any thread may take it): the deselect would make
    // that socket non-blocking and cut its own `Ready` off (a deaf server, a blocking client
    // that says "would block").
    ready: Ready,
    sock: UdpSocket,
    peer: SocketAddr,
    stop: &'a Stop,
}

impl Link for UdpLink<'_> {
    fn send(&mut self, b: &[u8]) -> std::io::Result<()> {
        // RL8-1: once the server has stopped, a transfer sends no more data, ACKs or OACKs (one
        // a stop left in a file call sends nothing when that call returns); an error that ends
        // it may still go.
        if self.stop.stopped() && (b.len() < 2 || u16::from_be_bytes([b[0], b[1]]) != ERROR) {
            return Err(std::io::Error::other(StoppedSend));
        }
        self.sock.send_to(b, self.peer).map(|_| ())
    }

    fn recv(&mut self, buf: &mut [u8], until: Instant) -> std::io::Result<Got> {
        loop {
            match self.sock.recv_from(buf) {
                Ok((n, from)) => {
                    if crate::listen::unmap(from) == self.peer {
                        return Ok(Got::Packet(n));
                    }
                    if n >= 4 && u16::from_be_bytes([buf[0], buf[1]]) != ERROR {
                        let _ = self.sock.send_to(&error(E_UNKNOWN_TID, "unknown transfer ID"), from);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(Got::Timeout);
                    }
                    match self.ready.wait(self.stop, Some(left)) {
                        Woke::Stopped => return Ok(Got::Stopped),
                        Woke::Timeout => return Ok(Got::Timeout),
                        Woke::Ready => {}
                    }
                }
                // A datagram larger than the buffer, or an ICMP echo: not the peer's packet.
                Err(e) if matches!(e.raw_os_error(), Some(10040 | 10054)) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

struct UploadSink {
    upload: Option<crate::paths::Upload>,
    ascii: Option<FromNetascii>,
    scratch: Vec<u8>,
}

fn write_code(e: &WriteError) -> u16 {
    match e {
        WriteError::Exists => E_EXISTS,
        WriteError::TooBig | WriteError::DiskFull => E_DISK_FULL,
        WriteError::NotAFile | WriteError::Invisible | WriteError::ExplorerActs => E_ACCESS,
        WriteError::Miss(Miss::NotFound | Miss::Outside | Miss::Denied | Miss::Busy) => E_ACCESS,
        WriteError::Miss(Miss::Io(_)) => E_UNDEFINED,
    }
}

fn write_msg(e: &WriteError) -> String {
    match e {
        WriteError::Exists => "file already exists".into(),
        WriteError::TooBig => "file too large (over 4 GiB)".into(),
        WriteError::DiskFull => "disk full".into(),
        // SNA3: the uploader is told why.
        WriteError::ExplorerActs => "VibeServe doesn't take shortcut-type files: Windows acts on them just by showing their folder".into(),
        _ => "access violation".into(),
    }
}

impl Sink for UploadSink {
    fn write(&mut self, b: &[u8]) -> Result<(), (u16, String)> {
        let up = self.upload.as_mut().ok_or((E_UNDEFINED, "closed".to_string()))?;
        let r = match self.ascii.as_mut() {
            Some(a) => {
                self.scratch.clear();
                a.feed(b, &mut self.scratch);
                up.write(&self.scratch)
            }
            None => up.write(b),
        };
        r.map_err(|e| (write_code(&e), write_msg(&e)))
    }

    fn finish(&mut self) -> Result<(), (u16, String)> {
        let mut up = self.upload.take().ok_or((E_UNDEFINED, "closed".to_string()))?;
        if let Some(a) = self.ascii.as_mut() {
            self.scratch.clear();
            a.end(&mut self.scratch);
            if !self.scratch.is_empty() {
                up.write(&self.scratch).map_err(|e| (write_code(&e), write_msg(&e)))?;
            }
        }
        up.finish().map(|_| ()).map_err(|e| (write_code(&e), write_msg(&e)))
    }
}

fn session(job: &Job, stop: &Stop, shared: &Share, report: &dyn Report, live: &Mutex<Vec<Arc<Live>>>, pace: crate::listen::Pace) {
    let t0 = Instant::now();
    let done = |bytes: u64, result: String, outcome: Outcome| {
        report.entry(Kind::Tftp, Entry { at: job.started, peer: job.peer, request: job.request.clone(), bytes, result, outcome, duration: t0.elapsed() });
    };
    let sock = match crate::listen::udp_from(job.local.0, job.local.1) {
        Ok(s) => s,
        Err(e) => return done(0, format!("no transfer socket: {e}"), Outcome::Failed),
    };
    let ready = match Ready::new(&sock, windows_sys::Win32::Networking::WinSock::FD_READ) {
        Ok(r) => r,
        Err(e) => return done(0, format!("no transfer socket: {e}"), Outcome::Failed),
    };
    let mut link = UdpLink { sock, ready, peer: job.peer, stop };
    let refuse = |link: &mut UdpLink, code: u16, msg: &str, result: String| {
        let _ = link.send(&error(code, msg));
        done(0, result, Outcome::Refused);
    };
    let mode = String::from_utf8_lossy(&job.mode).to_ascii_lowercase();
    let netascii = match mode.as_str() {
        "octet" => false,
        "netascii" => true,
        "mail" => return refuse(&mut link, E_ILLEGAL, "mail mode is not supported", "refused: mail mode".into()),
        _ => return refuse(&mut link, E_ILLEGAL, "unknown transfer mode", "refused: unknown mode".into()),
    };
    if job.write && !shared.writes.load(Ordering::SeqCst) {
        return refuse(&mut link, E_ACCESS, "writes are off", "refused: writes are off".into());
    }
    let Ok(name) = std::str::from_utf8(&job.file) else {
        return refuse(&mut link, E_ACCESS, "file name is not UTF-8", "refused: the name is not UTF-8".into());
    };
    let req = match crate::paths::validate(name) {
        Ok(r) if !r.parts.is_empty() && !r.dir => r,
        Ok(_) => return refuse(&mut link, E_ACCESS, "access violation", "refused: not a file name".into()),
        Err(why) => return refuse(&mut link, E_ACCESS, "access violation", format!("refused: {}", why.words())),
    };
    let Some(root) = shared.root() else {
        return refuse(&mut link, E_ACCESS, "access violation", "refused: no root folder".into());
    };
    let options: Vec<(&[u8], &[u8])> = job.options.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
    let v6 = job.peer.is_ipv6();
    let retries = RETRIES;
    let entry = Arc::new(Live { id: job.id, peer: job.peer, file: req.shown(), write: job.write, bytes: AtomicU64::new(0), total: AtomicU64::new(0), started: t0 });
    let track = |e: &Arc<Live>| live.lock().unwrap_or_else(|p| p.into_inner()).push(e.clone());
    let untrack = |id: u64| live.lock().unwrap_or_else(|p| p.into_inner()).retain(|l| l.id != id);
    let progress = |n: u64| {
        entry.bytes.store(n, Ordering::Relaxed);
        !pace.behind(t0, n)
    };
    let ended = |r: Result<u64, Fail>| match r {
        Ok(n) => done(n, "ok".into(), Outcome::Ok),
        Err(Fail::Declined) => done(0, Fail::Declined.words(), Outcome::Refused),
        Err(Fail::Slow) => done(entry.bytes.load(Ordering::Relaxed), format!("{} ({})", Fail::Slow.words(), pace.words()), Outcome::Failed),
        Err(f) => done(entry.bytes.load(Ordering::Relaxed), f.words(), if matches!(f, Fail::Local(E_EXISTS | E_DISK_FULL, _)) { Outcome::Refused } else { Outcome::Failed }),
    };
    if job.write {
        let a = negotiate(&options, true, netascii, None, v6);
        let limits = shared.limits();
        let made = root.create_upload(&req, a.tsize, limits);
        if stop.stopped() {
            // The server stopped while the create waited (a filter driver held it): an upload
            // made goes again (its Drop), and nothing is sent.
            return done(0, STOPPED.into(), Outcome::Failed);
        }
        let upload = match made {
            Ok(u) => u,
            Err(e) => return refuse(&mut link, write_code(&e), &write_msg(&e), format!("refused: {}", e.words())),
        };
        entry.total.store(a.tsize.unwrap_or(0), Ordering::Relaxed);
        track(&entry);
        let mut sink = UploadSink { upload: Some(upload), ascii: netascii.then(FromNetascii::default), scratch: Vec::new() };
        let r = receive(&mut link, &mut sink, &a, !a.oack.is_empty(), retries, &progress);
        drop(sink); // an unfinished upload deletes its temp file here
        untrack(job.id);
        ended(r);
    } else {
        let opened = root.open_read(&req);
        if stop.stopped() {
            return done(0, STOPPED.into(), Outcome::Failed);
        }
        let opened = match opened {
            Ok(Found::File(f)) => f,
            Ok(Found::Dir(_)) => return refuse(&mut link, E_NOT_FOUND, "file not found", "refused: a folder".into()),
            Err(Miss::NotFound) => return refuse(&mut link, E_NOT_FOUND, "file not found", "not found".into()),
            Err(m) => return refuse(&mut link, E_ACCESS, "access violation", format!("refused: {}", m.words())),
        };
        let a = negotiate(&options, false, netascii, Some(opened.size), v6);
        entry.total.store(if netascii { 0 } else { opened.size }, Ordering::Relaxed);
        track(&entry);
        let file = std::io::BufReader::with_capacity(64 * 1024, opened.file);
        let r = if netascii {
            send(&mut link, &mut ToNetascii::new(file), &a, !a.oack.is_empty(), retries, &progress)
        } else {
            let mut f = file;
            send(&mut link, &mut f, &a, !a.oack.is_empty(), retries, &progress)
        };
        untrack(job.id);
        ended(r);
    }
}
