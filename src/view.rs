//! Every word the window shows, made from the controller's state. Pure: the tests read these
//! without a window.

use crate::activity::{Entry, Kind, Outcome};
use crate::listen::{Bind, LocalAddr};
use crate::syslog::{Message, facility_name, severity_name};
use crate::text::{clean, clean_max, thousands};
use crate::{AddrLine, LogRow, SyslogDetail, SyslogRow, TransferRow};
use std::net::IpAddr;

pub fn title(k: Kind) -> &'static str {
    match k {
        Kind::Tftp => "TFTP",
        Kind::Syslog => "Syslog",
        Kind::Http => "HTTP",
    }
}

pub fn default_port(k: Kind) -> u16 {
    match k {
        Kind::Tftp => 69,
        Kind::Syslog => 514,
        Kind::Http => 80,
    }
}

/// "UDP", "UDP · TCP", "TCP" (the protocols a card's server takes; its port is in the field).
pub fn proto(k: Kind, udp: bool, tcp: bool) -> String {
    match k {
        Kind::Tftp => "UDP".into(),
        Kind::Http => "TCP".into(),
        Kind::Syslog => match (udp, tcp) {
            (true, true) => "UDP · TCP".into(),
            (true, false) => "UDP".into(),
            (false, true) => "TCP".into(),
            (false, false) => "no protocol".into(),
        },
    }
}

/// A port as typed: 1-65535, digits only (spaces around it allowed).
pub fn parse_port(s: &str) -> Option<u16> {
    let t = s.trim();
    if t.is_empty() || t.len() > 5 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse::<u16>().ok().filter(|p| *p != 0)
}

/// The loopback choice of the bind pickers.
pub const LOOPBACK: &str = "127.0.0.1";

/// The bind picker's lines and their keys: All addresses, this PC only, then every adapter
/// address; a remembered address that is not on this PC now is kept, marked, so it is never
/// silently swapped for another. The index of `current`.
pub fn bind_options(adapters: &[LocalAddr], current: &str) -> (Vec<String>, Vec<String>, usize) {
    let mut lines = vec!["All addresses".to_string(), format!("{LOOPBACK} · this PC only")];
    let mut keys = vec!["all".to_string(), LOOPBACK.to_string()];
    for a in adapters {
        let key = a.bind().key();
        if keys.contains(&key) {
            continue;
        }
        lines.push(format!("{} · {}", a.text(), a.adapter));
        keys.push(key);
    }
    let i = match keys.iter().position(|k| k == current) {
        Some(i) => i,
        None => {
            lines.push(format!("{} · not on this PC now", clean(current)));
            keys.push(current.to_string());
            keys.len() - 1
        }
    };
    (lines, keys, i)
}

/// An HTTP URL for an address (None for an IPv6 link-local one: browsers take no zone).
pub fn url(addr: &IpAddr, port: u16) -> Option<String> {
    let host = match addr {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80 => return None,
        IpAddr::V6(a) => format!("[{a}]"),
    };
    Some(if port == 80 { format!("http://{host}/") } else { format!("http://{host}:{port}/") })
}

/// Where a running server listens, one line per address: for All, every adapter address; for
/// one address, that one (with its adapter when it has one).
pub fn listen_lines(k: Kind, bind: &Bind, port: u16, adapters: &[LocalAddr]) -> Vec<AddrLine> {
    let line = |addr: IpAddr, text: String, adapter: String| AddrLine {
        addr: text.into(),
        adapter: adapter.into(),
        url: if k == Kind::Http { url(&addr, port).unwrap_or_default().into() } else { "".into() },
        toggle: "".into(),
    };
    match bind {
        Bind::All => adapters.iter().map(|a| line(a.addr, a.text(), a.adapter.clone())).collect(),
        Bind::One(ip, scope) => {
            let a = adapters.iter().find(|a| a.addr == *ip && (a.scope == *scope || *scope == 0));
            let text = Bind::One(*ip, *scope).key();
            let adapter = if ip.is_loopback() { "this PC only".to_string() } else { a.map(|a| a.adapter.clone()).unwrap_or_default() };
            vec![line(*ip, text, adapter)]
        }
    }
}

/// A card's address list: more than `FOLD_OVER` lines fold to the first two and "+N more"
/// (the column stays short enough to see all three cards); open, all of them and "Show fewer".
pub const FOLD_OVER: usize = 3;

pub fn fold_lines(mut lines: Vec<AddrLine>, open: bool) -> Vec<AddrLine> {
    if lines.len() <= FOLD_OVER {
        return lines;
    }
    let toggle = |t: String| AddrLine { addr: "".into(), adapter: "".into(), url: "".into(), toggle: t.into() };
    if open {
        lines.push(toggle("Show fewer".into()));
    } else {
        let more = lines.len() - 2;
        lines.truncate(2);
        lines.push(toggle(format!("+{more} more")));
    }
    lines
}

/// "Listening on 3 addresses", "Listening on 192.168.1.20".
pub fn listening(bind: &Bind, count: usize) -> String {
    match bind {
        Bind::All if count == 1 => "Listening on 1 address".into(),
        Bind::All => format!("Listening on {} addresses", thousands(count as u64)),
        Bind::One(ip, _) if ip.is_loopback() => "Listening on this PC only".into(),
        Bind::One(..) => format!("Listening on {}", bind.key()),
    }
}

pub fn severities() -> Vec<String> {
    vec![
        "Any severity".into(),
        "info and worse".into(),
        "notice and worse".into(),
        "warning and worse".into(),
        "err and worse".into(),
        "crit and worse".into(),
        "alert and worse".into(),
        "emerg only".into(),
    ]
}

/// The severity picker's index for a maximum severity (7 any .. 0 emerg) and back.
pub fn severity_index(max: u8) -> usize {
    7 - max.min(7) as usize
}

pub fn severity_of_index(i: usize) -> u8 {
    7 - i.min(7) as u8
}

pub fn syslog_row(m: &Message, selected: bool) -> SyslogRow {
    SyslogRow {
        time: crate::host::local_clock(m.received).time_ms().into(),
        source: m.source.ip().to_string().into(),
        facility: facility_name(m.facility).into(),
        severity: severity_name(m.severity).into(),
        sev: m.severity as i32,
        device_time: clean_max(m.device_time(), 64).into(),
        host: clean_max(m.host(), 255).into(),
        app: clean_max(m.app(), 128).into(),
        msg: {
            let mut s = clean_max(m.msg(), 2_000);
            s.push_str(m.window_note());
            s.into()
        },
        selected,
    }
}

pub fn syslog_detail(m: &Message) -> SyslogDetail {
    let c = crate::host::local_clock(m.received);
    let mut head = vec![c.stamp_ms(), m.source.to_string(), if m.tcp { "tcp".into() } else { "udp".into() }, format!("{}.{}", facility_name(m.facility), severity_name(m.severity))];
    for f in [&m.device_time(), &m.host(), &m.app()] {
        if !f.is_empty() {
            head.push(clean_max(f, 255));
        }
    }
    if !m.procid().is_empty() {
        head.push(format!("pid {}", clean_max(m.procid(), 128)));
    }
    if !m.msgid().is_empty() {
        head.push(format!("msgid {}", clean_max(m.msgid(), 64)));
    }
    let mut body = String::new();
    if !m.sd().is_empty() {
        body.push_str(&clean_max(m.sd(), 8_000));
        body.push(' ');
    }
    body.push_str(&clean_max(m.msg(), 66_000));
    body.push_str(m.window_note());
    SyslogDetail { shown: true, head: head.join(" · ").into(), body: body.into() }
}

/// The sources picker shows at most this many addresses (UDP sources can be spoofed by the
/// thousand); the filter keeps working for any of them.
pub const MAX_SOURCES: usize = 500;

/// The sources picker: "All sources", then the addresses with the most messages (at most `cap`,
/// sorted by address) with their counts, then "… N more" when some were left out. The chosen
/// address is always listed. The keys say what each line picks; the "more" line picks the
/// current choice (no change).
pub fn source_lines<'a>(sources: impl Iterator<Item = (&'a std::net::IpAddr, &'a u64)>, chosen: Option<std::net::IpAddr>, cap: usize) -> (Vec<String>, Vec<Option<std::net::IpAddr>>) {
    let mut all: Vec<(std::net::IpAddr, u64)> = sources.map(|(ip, n)| (*ip, *n)).collect();
    let more = all.len().saturating_sub(cap);
    if more > 0 {
        // The busiest `cap`, ties by address (a total order: the same list every time).
        all.select_nth_unstable_by(cap - 1, |a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        all.truncate(cap);
        all.sort_unstable_by_key(|x| x.0);
    }
    let mut lines = vec!["All sources".to_string()];
    let mut keys: Vec<Option<std::net::IpAddr>> = vec![None];
    for (ip, n) in &all {
        lines.push(format!("{ip} · {}", thousands(*n)));
        keys.push(Some(*ip));
    }
    if let Some(c) = chosen
        && !keys.contains(&Some(c))
    {
        lines.push(format!("{c} · {}", if more > 0 { "chosen" } else { "0" }));
        keys.push(Some(c));
    }
    if more > 0 {
        lines.push(format!("… {} more with fewer messages", thousands(more as u64)));
        keys.push(chosen);
    }
    (lines, keys)
}

/// The selected message for the clipboard: the head line, then the message whole.
pub fn detail_text(m: &Message) -> String {
    let d = syslog_detail(m);
    format!("{}\n{}", d.head, d.body)
}

pub fn log_row(e: &Entry) -> LogRow {
    LogRow {
        time: {
            let c = crate::host::local_clock(e.at);
            format!("{:02}:{:02}:{:02}", c.hour, c.minute, c.second).into()
        },
        peer: e.peer.to_string().into(),
        request: clean_max(&e.request, 512).into(),
        bytes: if e.bytes == 0 { "-".into() } else { thousands(e.bytes).into() },
        result: clean_max(&e.result, 512).into(),
        kind: match e.outcome {
            Outcome::Ok => 0,
            Outcome::Refused => 2,
            Outcome::Failed => 3,
        },
        duration: crate::text::duration(e.duration).into(),
    }
}

/// A TFTP transfer underway: its line on the card.
pub fn transfer_row(file: &str, peer: &str, write: bool, bytes: u64, total: u64, secs: f64) -> TransferRow {
    let speed = if secs > 0.2 { crate::text::rate(bytes as f64 / secs) } else { "-".into() };
    let (progress, detail) = if total > 0 {
        let pct = (bytes.min(total) as f64 / total as f64 * 100.0).floor();
        ((bytes.min(total) as f64 / total as f64) as f32, format!("{pct:.0} % · {speed}"))
    } else {
        (-1.0, format!("{} · {speed}", crate::text::bytes(bytes)))
    };
    TransferRow { file: clean_max(file, 512).into(), peer: format!("{} {peer}", if write { "from" } else { "to" }).into(), detail: detail.into(), progress, write }
}
