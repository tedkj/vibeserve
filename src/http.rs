//! The one-folder HTTP/1.1 server, hand-written on a TcpListener: GET and HEAD, single byte
//! ranges (206, 416), keep-alive, a folder listing, and PUT uploads when they are on.
//!
//! Request parsing, ranges, the listing and the MIME table are pure. Everything from the client
//! is hostile: the request line is capped at 8 KiB and the headers at 16 KiB, the whole head must
//! arrive within 30 s (slowloris), the target is percent-decoded once (`%00` and invalid UTF-8
//! refused) and then goes through the same path validator as TFTP. Request smuggling has no
//! foothold: a body is only ever read for a PUT with one Content-Length; Transfer-Encoding is
//! refused.

use crate::activity::{Entry, Kind, Outcome, Report};
use crate::listen::{Bind, BindError, Ready, Stop, Woke};
use crate::paths::{Found, Miss, Share, WriteError};
use std::io::{Read, Seek, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_LINE: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 16 * 1024;
pub const MAX_CONNECTIONS: usize = 32;
/// One address holds at most this many of them (a browser opens 6).
pub const PER_PEER: usize = 8;
pub const IDLE: Duration = Duration::from_secs(30);
/// The log's words for a request whose file call returned after the server stopped.
const STOPPED: &str = "the server stopped while the file was opened";
/// A soft close reads and drops what the client still sends for at most this long and this
/// much (`close_softly`, and the 503s the accept loop closes).
const SOFT_WAIT: Duration = Duration::from_secs(2);
const SOFT_BYTES: usize = 4 * 1024 * 1024;
/// At most this many refused (503) connections close softly at once; past it the oldest is
/// closed at once.
const SOFT_503S: usize = 64;
/// The log's words for a peer outside the local network (SNA4).
pub const OUTSIDE: &str = "refused: not on this PC's local network";

// ---------- requests (pure) ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    /// The request target as sent.
    pub target: String,
    /// (1, 0) or (1, 1).
    pub version: (u8, u8),
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// A header's value (the first; names without regard to case).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> impl Iterator<Item = &str> {
        self.headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Whether the connection stays open after this request.
    pub fn keep_alive(&self) -> bool {
        let close = self.all("Connection").any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
        self.version == (1, 1) && !close
    }

    /// The body length: None (no body), Some(n), or an error status for a body we will not read.
    pub fn body(&self) -> Result<Option<u64>, u16> {
        if self.get("Transfer-Encoding").is_some() {
            return Err(if self.method == "PUT" { 411 } else { 400 });
        }
        let mut len: Option<u64> = None;
        for v in self.all("Content-Length") {
            // "5, 5" is one length said twice; anything else that differs is refused.
            for part in v.split(',') {
                let p = part.trim();
                if p.is_empty() || p.len() > 19 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(400);
                }
                let n: u64 = p.parse().map_err(|_| 400u16)?;
                if len.is_some_and(|l| l != n) {
                    return Err(400);
                }
                len = Some(n);
            }
        }
        Ok(len)
    }
}

/// Why a head was refused: the status to answer with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// 400
    Bad(&'static str),
    /// 414: the request line is over 8 KiB.
    LineTooLong,
    /// 431: the headers are over 16 KiB.
    HeadersTooLarge,
    /// 505
    Version,
}

impl HeadError {
    pub fn status(self) -> u16 {
        match self {
            HeadError::Bad(_) => 400,
            HeadError::LineTooLong => 414,
            HeadError::HeadersTooLarge => 431,
            HeadError::Version => 505,
        }
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Where a head ends in `buf` (after its blank line), if it is all there. Lines end in CRLF or a
/// bare LF.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(off) = buf[i..].iter().position(|&b| b == b'\n') {
        let nl = i + off;
        let next = nl + 1;
        if buf[next..].starts_with(b"\r\n") {
            return Some(next + 2);
        }
        if buf[next..].starts_with(b"\n") {
            return Some(next + 1);
        }
        i = next;
    }
    None
}

/// Check what has arrived so far against the caps (before the head is whole).
pub fn check_partial(buf: &[u8]) -> Result<(), HeadError> {
    match buf.iter().position(|&b| b == b'\n') {
        None if buf.len() > MAX_LINE => Err(HeadError::LineTooLong),
        Some(i) if i > MAX_LINE => Err(HeadError::LineTooLong),
        Some(i) if buf.len() - i > MAX_HEADERS + 4 => Err(HeadError::HeadersTooLarge),
        _ => Ok(()),
    }
}

/// Parse a whole head (the request line and the header lines, through the blank line). The
/// request line must be UTF-8 and header names are tokens (ASCII); a header value may carry
/// obs-text (bytes 0x80-0xFF, RFC 9110 5.5), taken as lossy UTF-8.
pub fn parse_head(raw: &[u8]) -> Result<Head, HeadError> {
    let mut lines = raw.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = lines.next().ok_or(HeadError::Bad("no request line"))?;
    if line.len() > MAX_LINE {
        return Err(HeadError::LineTooLong);
    }
    let line = std::str::from_utf8(line).map_err(|_| HeadError::Bad("a request line that is not text"))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(HeadError::Bad("a request line that is not METHOD TARGET VERSION"));
    };
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(HeadError::Bad("a bad method"));
    }
    if target.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(HeadError::Bad("a bad target"));
    }
    let version = match version {
        "HTTP/1.1" => (1, 1),
        "HTTP/1.0" => (1, 0),
        v if v.starts_with("HTTP/") => return Err(HeadError::Version),
        _ => return Err(HeadError::Bad("not HTTP")),
    };
    let mut headers = Vec::new();
    let mut size = 0usize;
    for l in lines {
        if l.is_empty() {
            break;
        }
        size += l.len() + 2;
        if size > MAX_HEADERS {
            return Err(HeadError::HeadersTooLarge);
        }
        if l.starts_with(b" ") || l.starts_with(b"\t") {
            return Err(HeadError::Bad("a folded header line"));
        }
        let colon = l.iter().position(|&b| b == b':').ok_or(HeadError::Bad("a header line without a colon"))?;
        let (name, value) = (&l[..colon], &l[colon + 1..]);
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            // Whitespace before the colon is how requests get smuggled: refused (RFC 9112 5.1).
            return Err(HeadError::Bad("a bad header name"));
        }
        let blank = |b: &u8| *b == b' ' || *b == b'\t';
        let start = value.iter().position(|b| !blank(b)).unwrap_or(value.len());
        let end = value.iter().rposition(|b| !blank(b)).map_or(start, |i| i + 1);
        let value = &value[start..end];
        if value.iter().any(|&b| (b < b' ' && b != b'\t') || b == 0x7f) {
            return Err(HeadError::Bad("a control character in a header"));
        }
        if headers.len() >= 100 {
            return Err(HeadError::HeadersTooLarge);
        }
        // A token is ASCII: the name is text.
        headers.push((String::from_utf8_lossy(name).into_owned(), String::from_utf8_lossy(value).into_owned()));
    }
    Ok(Head { method: method.to_string(), target: target.to_string(), version, headers })
}

/// The path of a request target: origin-form `/a/b?q`, or absolute-form `http://host/a/b`; the
/// query and fragment dropped. Then percent-decoded once: `%00`, a broken escape or invalid UTF-8
/// is refused.
pub fn target_path(target: &str) -> Result<String, &'static str> {
    let path = if target.starts_with('/') {
        target
    } else if let Some(rest) = target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://")) {
        match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        }
    } else {
        return Err("not a path");
    };
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            let (Some(h), Some(l)) = (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) else {
                return Err("a broken percent escape");
            };
            let v = (h * 16 + l) as u8;
            if v == 0 {
                return Err("%00");
            }
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "a path that is not UTF-8")
}

// ---------- who a request is for (SNA1: DNS rebinding) ----------

/// This PC's own names, lower case: its NetBIOS name and DNS host name, each also as
/// `<name>.local` (mDNS), and its full DNS name when it has a domain. Read once: Windows needs a
/// restart for a new name anyway.
pub fn own_names() -> &'static [String] {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsFullyQualified, ComputerNameDnsHostname, ComputerNameNetBIOS, GetComputerNameExW};
        let mut out: Vec<String> = Vec::new();
        for (kind, local) in [(ComputerNameNetBIOS, true), (ComputerNameDnsHostname, true), (ComputerNameDnsFullyQualified, false)] {
            let mut buf = [0u16; 512];
            let mut n = buf.len() as u32;
            // SAFETY: a buffer and its length in units; the call writes at most that.
            if unsafe { GetComputerNameExW(kind, buf.as_mut_ptr(), &mut n) } == 0 || n == 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&buf[..(n as usize).min(buf.len())]).to_ascii_lowercase();
            let mut add = |v: String| {
                if !out.contains(&v) {
                    out.push(v);
                }
            };
            if local {
                add(format!("{name}.local"));
            }
            add(name);
        }
        out
    })
}

/// Whether a Host header (or an absolute-form target's authority) names this PC: an IPv4
/// literal, an IPv6 literal in brackets (a zone id allowed), `localhost`, or one of `names`
/// (lower case), each with an optional port; one trailing dot on a name is fine. Pure. Anything
/// else is a name some DNS server answers for, which is how DNS rebinding gets a page from
/// another site the browser's same-origin access to this server.
pub fn host_allowed(host: &str, names: &[String]) -> bool {
    let port_ok = |after: &str| match after.strip_prefix(':') {
        None => after.is_empty(),
        Some(p) => p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().map_or(p.is_empty(), |n| n <= 65_535),
    };
    if let Some(rest) = host.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else { return false };
        let addr = inside.split_once('%').map_or(inside, |(a, _)| a);
        return addr.parse::<std::net::Ipv6Addr>().is_ok() && port_ok(after);
    }
    let (name, after) = host.split_at(host.find(':').unwrap_or(host.len()));
    if !port_ok(after) {
        return false;
    }
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    !name.is_empty() && (name.parse::<std::net::Ipv4Addr>().is_ok() || name == "localhost" || names.contains(&name))
}

/// The authority of an absolute-form target (`http://host:port/path`), if it is one.
fn authority(target: &str) -> Option<&str> {
    let rest = target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://"))?;
    Some(&rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())])
}

/// SNA1: a request that is not for this PC, in the log's words: no Host header (HTTP/1.0
/// included), two of them, or one (or an absolute-form target) naming another computer.
pub fn misdirected(head: &Head, names: &[String]) -> Option<String> {
    let shown = |h: &str| crate::text::clean(&h.chars().take(100).collect::<String>());
    let mut hosts = head.all("Host");
    let Some(host) = hosts.next() else { return Some("refused: no Host header (it must name this PC)".into()) };
    if hosts.next().is_some() {
        return Some("refused: two Host headers".into());
    }
    if !host_allowed(host, names) {
        return Some(format!("refused: the Host header names another computer ({})", shown(host)));
    }
    match authority(&head.target) {
        Some(a) if !host_allowed(a, names) => Some(format!("refused: the address names another computer ({})", shown(a))),
        _ => None,
    }
}

/// What a client that names another computer is told.
const MISDIRECTED: &str = "VibeServe only answers to this PC's own address or name.\n";

/// What a Range header asks of a file of `size` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Range {
    Full,
    /// First and last byte, inclusive.
    Part(u64, u64),
    Unsatisfiable,
}

/// One byte range (RFC 9110 14.1.2). Several ranges, other units or a malformed header: the
/// whole file (the RFC lets a server ignore Range).
pub fn range(header: Option<&str>, size: u64) -> Range {
    let Some(h) = header else { return Range::Full };
    let Some(spec) = h.trim().strip_prefix("bytes=") else { return Range::Full };
    if spec.contains(',') {
        return Range::Full;
    }
    let Some((a, b)) = spec.trim().split_once('-') else { return Range::Full };
    let num = |s: &str| if !s.is_empty() && s.len() <= 19 && s.bytes().all(|c| c.is_ascii_digit()) { s.parse::<u64>().ok() } else { None };
    match (a.trim(), b.trim()) {
        ("", n) => match num(n) {
            Some(0) => Range::Unsatisfiable,
            Some(_) if size == 0 => Range::Unsatisfiable,
            Some(n) => Range::Part(size.saturating_sub(n), size - 1),
            None => Range::Full,
        },
        (s, "") => match num(s) {
            Some(s) if s >= size => Range::Unsatisfiable,
            Some(s) => Range::Part(s, size - 1),
            None => Range::Full,
        },
        (s, e) => match (num(s), num(e)) {
            (Some(s), Some(e)) if s <= e => {
                if s >= size {
                    Range::Unsatisfiable
                } else {
                    Range::Part(s, e.min(size - 1))
                }
            }
            _ => Range::Full,
        },
    }
}

/// A small extension table; anything else is application/octet-stream.
pub fn mime(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "txt" | "log" | "cfg" | "conf" | "ini" | "md" | "sh" | "py" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

/// Files a browser may show in its own window: plain text, images other than SVG, PDF. Anything
/// else (HTML, SVG, XML, scripts: anyone with uploads on could have put them there) is a
/// download, so no page from the folder ever runs with this server as its origin.
pub fn inline(name: &str) -> bool {
    let m = mime(name);
    m.starts_with("text/plain") || m == "application/pdf" || (m.starts_with("image/") && m != "image/svg+xml")
}

/// Text in HTML: & < > " ' escaped.
pub fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// One path segment percent-encoded (everything but unreserved characters).
pub fn encode_segment(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// The upload page's script: the CSP lets this exact text run, nothing else.
pub const UPLOAD_SCRIPT: &str = "const f=document.getElementById('f'),s=document.getElementById('s');\nf.onchange=async()=>{let ok=0;s.textContent='';\nfor(const x of f.files){const r=await fetch(encodeURIComponent(x.name),{method:'PUT',body:x}).catch(()=>null);\nconst w=r?(r.status==201?'uploaded':r.status==409?'exists already':'failed ('+r.status+'): '+(await r.text().catch(()=>'')).trim()):'failed';ok+=r&&r.status==201?1:0;\nconst li=document.createElement('div');li.textContent=x.name+': '+w;s.appendChild(li);}\nif(ok)setTimeout(()=>location.reload(),1500);};\n";

/// SHA-256 (Windows' CNG).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};
    let mut out = [0u8; 32];
    // SAFETY: the built-in SHA-256 handle, no secret, an input and a 32-byte output.
    let r = unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, std::ptr::null(), 0, data.as_ptr(), data.len() as u32, out.as_mut_ptr(), 32) };
    assert!(r == 0, "BCryptHash failed: {r:#x}");
    out
}

pub fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(A[(n >> 18) as usize & 63] as char);
        o.push(A[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    o
}

/// The listing's Content-Security-Policy: nothing at all may load or run, but the inline styles,
/// and with uploads the one script (by its hash) and its PUTs to this server.
pub fn listing_csp(uploads: bool) -> String {
    let mut c = String::from("default-src 'none'; style-src 'unsafe-inline'");
    if uploads {
        c.push_str(&format!("; script-src 'sha256-{}'; connect-src 'self'", base64(&sha256(UPLOAD_SCRIPT.as_bytes()))));
    }
    c
}

/// A folder's listing page. `path` is the decoded request path ("/firmware/").
pub fn listing(path: &str, entries: &[crate::paths::Entry], more: usize, at_root: bool, uploads: bool) -> String {
    let title = html_escape(path);
    let mut h = String::with_capacity(4096 + entries.len() * 160);
    h.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>");
    h.push_str(&title);
    h.push_str("</title><style>body{font:14px 'Segoe UI',system-ui,sans-serif;margin:24px;color:#15171a;background:#f6f4ef}h1{font-size:14px;font-weight:600}table{border-collapse:collapse;font-family:'Cascadia Mono',Consolas,monospace;font-size:12px}td{padding:3px 16px 3px 0}td.n{text-align:right}a{color:#2b46c4;text-decoration:none}a:hover{text-decoration:underline}p{font-size:12px;color:#7a7f88}</style></head><body><h1>Index of ");
    h.push_str(&title);
    h.push_str("</h1><table>");
    if !at_root {
        h.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>");
    }
    for e in entries {
        let href = encode_segment(&e.name);
        let name = html_escape(&e.name);
        let when = crate::host::local_clock(e.modified).minutes();
        if e.dir {
            h.push_str(&format!("<tr><td><a href=\"{href}/\">{name}/</a></td><td class=\"n\">-</td><td>{when}</td></tr>"));
        } else {
            h.push_str(&format!("<tr><td><a href=\"{href}\">{name}</a></td><td class=\"n\">{}</td><td>{when}</td></tr>", crate::text::bytes(e.size)));
        }
    }
    h.push_str("</table>");
    if more > 0 {
        h.push_str(&format!("<p>{} more not listed (a listing shows at most {}).</p>", crate::text::thousands(more as u64), crate::text::thousands(crate::paths::MAX_LISTING as u64)));
    }
    if uploads {
        h.push_str("<p>Upload (no overwriting): <input type=\"file\" id=\"f\" multiple></p><div id=\"s\"></div><script>");
        h.push_str(UPLOAD_SCRIPT);
        h.push_str("</script>");
    }
    h.push_str("<p>VibeServe</p></body></html>");
    h
}

/// An HTTP date (IMF-fixdate) of a FILETIME: "Thu, 22 Oct 2026 12:03:07 GMT".
pub fn http_date(ft: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let c = crate::host::utc_clock(ft);
    format!("{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT", DAYS[c.weekday as usize % 7], c.day, MONTHS[(c.month.max(1) as usize - 1) % 12], c.year, c.hour, c.minute, c.second)
}

pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        206 => "Partial Content",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        416 => "Range Not Satisfiable",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => "Error",
    }
}

/// A response head: the status line, our fixed headers, `extra`, and Content-Length.
pub fn response_head(status: u16, extra: &[(&str, String)], length: u64, keep: bool) -> String {
    let mut h = format!("HTTP/1.1 {status} {}\r\nServer: VibeServe\r\nDate: {}\r\nX-Content-Type-Options: nosniff\r\n", reason(status), http_date(crate::host::now_filetime()));
    for (k, v) in extra {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str(&format!("Content-Length: {length}\r\n"));
    h.push_str(if keep { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    h.push_str("\r\n");
    h
}

// ---------- the server ----------

/// What the HTTP server runs with (tests shorten the timeouts).
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    pub idle: Duration,
    pub max_connections: usize,
    /// Connections one address may hold (IN-VibeServe-3).
    pub per_peer: usize,
    /// The slowest a download or upload body may run (IN-VibeServe-3).
    pub pace: crate::listen::Pace,
    /// Each GET waits this long before it opens its file, deaf to the stop (tests: an open a
    /// filter driver holds past the stop's wait, RL8-1). Zero in the app.
    pub hold: Duration,
    /// Each socket timeout of a download or an upload body is set this much shorter, as a
    /// coarse timer fires one early (tests: RL9-1). Zero in the app.
    pub early: Duration,
    /// Whether a peer may connect (SNA4): `listen::on_lan` in the app (tests: every peer is
    /// loopback, so they stand in another rule).
    pub lan: fn(std::net::IpAddr) -> bool,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning { idle: IDLE, max_connections: MAX_CONNECTIONS, per_peer: PER_PEER, pace: crate::listen::PACE, hold: Duration::ZERO, early: Duration::ZERO, lan: crate::listen::on_lan }
    }
}

impl Tuning {
    /// The socket timeout for a wait of `d` (`early` off it, at least 1 ms).
    fn timeout(&self, d: Duration) -> Duration {
        d.saturating_sub(self.early).max(Duration::from_millis(1))
    }
}

/// A socket call ended at its own timeout (not a reset or a close).
fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
}

/// A write to the client that failed, in the log's words (RSA-1): one that timed out waited the
/// idle time with nothing taken, so the client is still connected but stopped reading; any other
/// error is a close (a reset or an abort).
fn not_taken(e: &std::io::Error, idle: Duration) -> String {
    if timed_out(e) { format!("cut: the client stopped reading for {}", crate::text::duration(idle)) } else { "the client closed".into() }
}

pub struct Server {
    stop: Arc<Stop>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The connections' threads, handed over when the accept loop ends.
    handed: crate::listen::Handed,
    pub local: SocketAddr,
    pub connections: Arc<AtomicUsize>,
}

impl Server {
    /// Stop, waiting at most `HALT_WAIT`: how many threads were left running (a connection in a
    /// file open that ignores the stop, or a send to a client that stopped reading; it ends when
    /// that lets go, which may be never: see DECISIONS).
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

pub fn start(bind: &Bind, port: u16, share: Arc<Share>, tuning: Tuning, report: Arc<dyn Report>) -> Result<Server, BindError> {
    let l = crate::listen::tcp(bind, port)?;
    let local = l.local_addr().map_err(|e| BindError::Other(e.to_string()))?;
    let ready = Ready::new(&l, windows_sys::Win32::Networking::WinSock::FD_ACCEPT).map_err(|e| BindError::Other(e.to_string()))?;
    let stop = Stop::new();
    let connections: Arc<AtomicUsize> = Default::default();
    let handed: crate::listen::Handed = Default::default();
    let (st, cn, hd) = (stop.clone(), connections.clone(), handed.clone());
    let thread = std::thread::Builder::new()
        .name("http".into())
        .stack_size(256 * 1024)
        .spawn(move || accept_loop(l, ready, st, share, tuning, report, cn, hd))
        .map_err(|e| BindError::Other(e.to_string()))?;
    Ok(Server { stop, thread: Some(thread), handed, local, connections })
}

#[allow(clippy::too_many_arguments)]
fn accept_loop(l: TcpListener, ready: Ready, stop: Arc<Stop>, share: Arc<Share>, tuning: Tuning, report: Arc<dyn Report>, count: Arc<AtomicUsize>, handed: crate::listen::Handed) {
    let conns: Arc<Mutex<Vec<(u64, TcpStream)>>> = Default::default();
    let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut id = 0u64;
    // Refused connections closing softly: (since, bytes drained, the socket).
    let mut closing: Vec<(Instant, usize, TcpStream)> = Vec::new();
    let peers: Arc<crate::listen::Peers> = Default::default();
    loop {
        threads.retain(|t| !t.is_finished());
        drain_closing(&mut closing);
        // RL8-1: on every turn, not only when no connection waits (a steady stream of them
        // never keeps it open past its stop).
        if stop.stopped() {
            break;
        }
        match l.accept() {
            Ok((s, from)) => {
                let from = crate::listen::unmap(from);
                // SNA4: a peer outside the local network is closed at once, unanswered, whatever
                // the firewall let through.
                if !(tuning.lan)(from.ip()) {
                    drop(s);
                    report.entry(Kind::Http, Entry { at: crate::host::now_filetime(), peer: from, request: "(connection)".into(), bytes: 0, result: OUTSIDE.into(), outcome: Outcome::Refused, duration: Duration::ZERO });
                    continue;
                }
                if crate::listen::plain(&s).is_err() {
                    continue;
                }
                // Open connections, not live threads: a thread that has ended its connection
                // may take a moment more to finish.
                if count.load(Ordering::SeqCst) >= tuning.max_connections {
                    busy(s, "VibeServe is busy: 32 connections are open.\n", &mut closing);
                    report.entry(Kind::Http, Entry { at: crate::host::now_filetime(), peer: from, request: "(connection)".into(), bytes: 0, result: format!("503 refused: {} connections open", tuning.max_connections), outcome: Outcome::Refused, duration: Duration::ZERO });
                    continue;
                }
                // IN-VibeServe-3: one address never takes every slot.
                let Some(slot) = peers.take(from.ip(), tuning.per_peer) else {
                    busy(s, &format!("VibeServe is busy: {} connections from your address are open.\n", tuning.per_peer), &mut closing);
                    report.entry(Kind::Http, Entry { at: crate::host::now_filetime(), peer: from, request: "(connection)".into(), bytes: 0, result: format!("503 refused: {} connections open from this address", tuning.per_peer), outcome: Outcome::Refused, duration: Duration::ZERO });
                    continue;
                };
                id += 1;
                let Ok(clone) = s.try_clone() else { continue };
                conns.lock().unwrap_or_else(|e| e.into_inner()).push((id, clone));
                let (sh, rp, cs, me, st, ct) = (share.clone(), report.clone(), conns.clone(), id, stop.clone(), count.clone());
                count.fetch_add(1, Ordering::SeqCst);
                if let Ok(t) = std::thread::Builder::new().name("http-conn".into()).stack_size(256 * 1024).spawn(move || {
                    let _slot = slot;
                    connection(s, from, &sh, tuning, rp.as_ref(), &st);
                    cs.lock().unwrap_or_else(|e| e.into_inner()).retain(|(i, _)| *i != me);
                    ct.fetch_sub(1, Ordering::SeqCst);
                }) {
                    threads.push(t);
                } else {
                    count.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // While 503s close softly, wake now and then to drain them.
                let wait = (!closing.is_empty()).then_some(Duration::from_millis(50));
                if ready.wait(&stop, wait) == Woke::Stopped {
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
    for (_, c) in conns.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        let _ = c.shutdown(std::net::Shutdown::Both);
    }
    // `halt` waits for them (bounded).
    handed.lock().unwrap_or_else(|e| e.into_inner()).extend(threads);
}

/// A quick 503 with `body`, then the socket goes to `closing` (closed softly on the loop's
/// turns, so the request it is still sending never holds the loop).
fn busy(s: TcpStream, body: &str, closing: &mut Vec<(Instant, usize, TcpStream)>) {
    // The 503 is small enough for the socket's buffer: this write does not wait.
    let _ = s.set_write_timeout(Some(Duration::from_millis(200)));
    let _ = (&s).write_all(format!("{}{body}", response_head(503, &[("Content-Type", "text/plain; charset=utf-8".into()), ("Retry-After", "5".into())], body.len() as u64, false)).as_bytes());
    let _ = s.shutdown(std::net::Shutdown::Write);
    if s.set_nonblocking(true).is_ok() {
        if closing.len() >= SOFT_503S {
            closing.remove(0);
        }
        closing.push((Instant::now(), 0, s));
    }
}

/// Read and drop what the refused (503) connections still send, without waiting; close each at
/// its end, or past `SOFT_WAIT` or `SOFT_BYTES`.
fn drain_closing(closing: &mut Vec<(Instant, usize, TcpStream)>) {
    let mut buf = [0u8; 16 * 1024];
    closing.retain_mut(|(since, drained, s)| loop {
        if since.elapsed() >= SOFT_WAIT || *drained >= SOFT_BYTES {
            return false;
        }
        match s.read(&mut buf) {
            Ok(0) => return false,
            Ok(n) => *drained += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return true,
            Err(_) => return false,
        }
    });
}

/// How reading a head ended.
enum Got {
    Head(Head),
    /// The client closed (or the server stopped) between requests: nothing to say.
    Closed,
    Refused(HeadError),
    /// The head did not arrive in time.
    Slow(usize),
}

/// Read one head: it must be whole within `limit` of its first wait (idle between requests and
/// slowloris alike). `carry` holds bytes that arrived past the previous request.
fn read_head(s: &mut TcpStream, carry: &mut Vec<u8>, limit: Duration) -> Got {
    let deadline = Instant::now() + limit;
    let mut buf = std::mem::take(carry);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&buf) {
            let rest = buf.split_off(end);
            *carry = rest;
            return match parse_head(&buf) {
                Ok(h) => Got::Head(h),
                Err(e) => Got::Refused(e),
            };
        }
        if let Err(e) = check_partial(&buf) {
            return Got::Refused(e);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return if buf.iter().all(|b| b.is_ascii_whitespace()) { Got::Closed } else { Got::Slow(buf.len()) };
        }
        let _ = s.set_read_timeout(Some(left.max(Duration::from_millis(1))));
        match s.read(&mut chunk) {
            Ok(0) => return Got::Closed,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => return Got::Closed,
        }
    }
}

fn connection(mut s: TcpStream, peer: SocketAddr, share: &Share, tuning: Tuning, report: &dyn Report, stop: &Stop) {
    let _ = s.set_nodelay(true);
    let _ = s.set_write_timeout(Some(tuning.idle));
    let mut carry = Vec::new();
    loop {
        if stop.stopped() {
            return;
        }
        let at = crate::host::now_filetime();
        let t0 = Instant::now();
        let log = |request: String, bytes: u64, result: String, outcome: Outcome| {
            report.entry(Kind::Http, Entry { at, peer, request, bytes, result, outcome, duration: t0.elapsed() });
        };
        let head = match read_head(&mut s, &mut carry, tuning.idle) {
            Got::Head(h) => h,
            Got::Closed => return,
            Got::Slow(n) => {
                let _ = send_simple(&mut s, 408, "The request did not arrive in time.\n", false, false);
                log(format!("(incomplete request, {n} bytes)"), 0, "408 timed out waiting for the request".into(), Outcome::Refused);
                close_softly(&mut s);
                return;
            }
            Got::Refused(e) => {
                let st = e.status();
                let _ = send_simple(&mut s, st, &format!("{}.\n", reason(st)), false, false);
                let why = match e {
                    HeadError::Bad(w) => w.to_string(),
                    HeadError::LineTooLong => "a request line over 8 KiB".into(),
                    HeadError::HeadersTooLarge => "headers over 16 KiB".into(),
                    HeadError::Version => "an HTTP version other than 1.0 or 1.1".into(),
                };
                log("(bad request)".into(), 0, format!("{st} {why}"), Outcome::Refused);
                // The oversized or bad head is still arriving: closing on it would reset the
                // connection and could throw the answer away.
                close_softly(&mut s);
                return;
            }
        };
        let request = format!("{} {}", head.method, head.target.chars().take(512).collect::<String>());
        let (status, bytes, result, outcome, keep) = respond(&mut s, &head, share, &mut carry, tuning, stop);
        log(request, bytes, if result.is_empty() { status.to_string() } else if status == 0 { result } else { format!("{status} {result}") }, outcome);
        if !keep {
            close_softly(&mut s);
            return;
        }
    }
}

/// Close after an answer the client may still be sending into (a refused upload's body, an
/// oversized or slow head): say we are done, read and drop what arrives for a moment, then
/// close. Closing with unread bytes would reset the connection, and the client might never
/// read the answer.
fn close_softly(s: &mut TcpStream) {
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 16 * 1024];
    let mut drained = 0usize;
    let start = Instant::now();
    while drained < SOFT_BYTES && start.elapsed() < SOFT_WAIT {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn send_simple(s: &mut TcpStream, status: u16, body: &str, head_only: bool, keep: bool) -> std::io::Result<()> {
    let mut out = response_head(status, &[("Content-Type", "text/plain; charset=utf-8".into())], body.len() as u64, keep).into_bytes();
    if !head_only {
        out.extend_from_slice(body.as_bytes());
    }
    s.write_all(&out)
}

/// Answer one request: (status, body bytes sent, words for the log, outcome, keep the
/// connection).
fn respond(s: &mut TcpStream, head: &Head, share: &Share, carry: &mut Vec<u8>, tuning: Tuning, stop: &Stop) -> (u16, u64, String, Outcome, bool) {
    let body = head.body();
    // A body we do not read leaves the connection unusable: close after the answer.
    let keep = head.keep_alive() && matches!(body, Ok(None) | Ok(Some(0)));
    let simple = |s: &mut TcpStream, st: u16, words: &str, outcome: Outcome, keep: bool| {
        let ok = send_simple(s, st, &format!("{}.\n", reason(st)), head.method == "HEAD", keep).is_ok();
        (st, 0, words.to_string(), outcome, keep && ok)
    };
    // SNA1: before anything else, uploads included: a request for another name never reaches a
    // file. The connection closes after it.
    if let Some(words) = misdirected(head, own_names()) {
        let _ = send_simple(s, 421, MISDIRECTED, head.method == "HEAD", false);
        return (421, 0, words, Outcome::Refused, false);
    }
    let method = head.method.as_str();
    if !matches!(method, "GET" | "HEAD" | "PUT") {
        let out = response_head(405, &[("Allow", if share.writes.load(Ordering::SeqCst) { "GET, HEAD, PUT" } else { "GET, HEAD" }.into())], 0, keep);
        let ok = s.write_all(out.as_bytes()).is_ok();
        return (405, 0, format!("the method {} is not offered", crate::text::clean(method)), Outcome::Refused, keep && ok);
    }
    let path = match target_path(&head.target) {
        Ok(p) => p,
        Err(why) => return simple(s, 400, &format!("refused: {why}"), Outcome::Refused, keep),
    };
    let req = match crate::paths::validate(&path) {
        Ok(r) => r,
        Err(why) => return simple(s, 403, &format!("refused: {}", why.words()), Outcome::Refused, keep),
    };
    let Some(root) = share.root() else { return simple(s, 503, "no root folder", Outcome::Refused, keep) };
    if method == "PUT" {
        return put(s, head, &req, share, &root, body, carry, tuning, stop);
    }
    if let Err(st) = body {
        return simple(s, st, "a body this server does not read", Outcome::Refused, false);
    }
    if !tuning.hold.is_zero() {
        std::thread::sleep(tuning.hold);
    }
    let opened = root.open_read(&req);
    if stop.stopped() {
        // The server stopped while the open waited (a filter driver held it): nothing more.
        return (0, 0, STOPPED.into(), Outcome::Failed, false);
    }
    match opened {
        Ok(Found::Dir(folder)) => {
            if !req.dir {
                // A folder's address ends in "/": relative links in its listing need it.
                let loc: String = path.split('/').map(encode_segment).collect::<Vec<_>>().join("/") + "/";
                let out = response_head(301, &[("Location", loc)], 0, keep);
                let ok = s.write_all(out.as_bytes()).is_ok();
                return (301, 0, String::new(), Outcome::Ok, keep && ok);
            }
            let (entries, more) = match crate::paths::list(&folder) {
                Ok(x) => x,
                Err(m) => return simple(s, if m == Miss::NotFound { 404 } else { 403 }, &m.words(), Outcome::Failed, keep),
            };
            let shown = if req.parts.is_empty() { "/".to_string() } else { format!("/{}/", req.parts.join("/")) };
            let page = listing(&shown, &entries, more, folder.at_root, share.writes.load(Ordering::SeqCst));
            let out = response_head(200, &[("Content-Type", "text/html; charset=utf-8".into()), ("Content-Security-Policy", listing_csp(share.writes.load(Ordering::SeqCst))), ("Cache-Control", "no-store".into()), ("Referrer-Policy", "no-referrer".into())], page.len() as u64, keep);
            let mut all = out.into_bytes();
            if method == "GET" {
                all.extend_from_slice(page.as_bytes());
            }
            let ok = s.write_all(&all).is_ok();
            let sent = if method == "GET" { page.len() as u64 } else { 0 };
            (200, if ok { sent } else { 0 }, if more > 0 { format!("listing (partial: {more} not listed)") } else { "listing".into() }, if ok { Outcome::Ok } else { Outcome::Failed }, keep && ok)
        }
        // "/page.html/" names a folder: a file is not one (relative links would resolve wrong,
        // and every file would have a second address).
        Ok(Found::File(_)) if req.dir => simple(s, 404, "not found (a file asked for as a folder)", Outcome::Refused, keep),
        Ok(Found::File(mut f)) => {
            let r = range(head.get("Range"), f.size);
            // If-Range: only when it names this file's Last-Modified does the range stand.
            let last_mod = http_date(f.modified);
            let r = match head.get("If-Range") {
                Some(v) if v != last_mod => Range::Full,
                _ => r,
            };
            let name = req.parts.last().cloned().unwrap_or_default();
            let mut extra = vec![("Content-Type", mime(&name).to_string()), ("Last-Modified", last_mod), ("Accept-Ranges", "bytes".to_string())];
            if !inline(&name) {
                extra.push(("Content-Disposition", "attachment".to_string()));
            }
            let (status, start, len) = match r {
                Range::Full => (200, 0, f.size),
                Range::Part(a, b) => {
                    extra.push(("Content-Range", format!("bytes {a}-{b}/{}", f.size)));
                    (206, a, b - a + 1)
                }
                Range::Unsatisfiable => {
                    let out = response_head(416, &[("Content-Range", format!("bytes */{}", f.size))], 0, keep);
                    let ok = s.write_all(out.as_bytes()).is_ok();
                    return (416, 0, format!("a range past the end ({})", crate::text::clean(head.get("Range").unwrap_or(""))), Outcome::Refused, keep && ok);
                }
            };
            if let Err(e) = s.write_all(response_head(status, &extra, len, keep).as_bytes()) {
                return (status, 0, not_taken(&e, tuning.idle), Outcome::Failed, false);
            }
            if method == "HEAD" {
                return (status, 0, String::new(), Outcome::Ok, keep);
            }
            if start > 0 && f.file.seek(std::io::SeekFrom::Start(start)).is_err() {
                return (status, 0, "the file could not be read".into(), Outcome::Failed, false);
            }
            let mut left = len;
            let mut sent = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            // IN-VibeServe-3: the download keeps its pace; no write waits past it either.
            let (t, pace) = (Instant::now(), tuning.pace);
            let slow = |sent: u64| format!("cut: the client was too slow ({}) after {}", pace.words(), crate::text::bytes(sent));
            while left > 0 {
                if pace.behind(t, sent) {
                    return (status, sent, slow(sent), Outcome::Failed, false);
                }
                let want = (left as usize).min(buf.len());
                let n = match f.file.read(&mut buf[..want]) {
                    Ok(0) => return (status, sent, format!("the file got shorter while it was sent ({sent} of {len} bytes)"), Outcome::Failed, false),
                    Ok(n) => n,
                    Err(_) => return (status, sent, "the file could not be read".into(), Outcome::Failed, false),
                };
                let wait = pace.wait(t, sent, tuning.idle);
                let _ = s.set_write_timeout(Some(tuning.timeout(wait)));
                if let Err(e) = s.write_all(&buf[..n]) {
                    // RL9-1: a timeout the deadline set is the pace's, even one that fired a
                    // little early (a send that timed out can't be taken up again). One the idle
                    // time set is a client that stopped reading (RSA-1), not one that closed.
                    if pace.behind(t, sent) || (timed_out(&e) && wait < tuning.idle) {
                        return (status, sent, slow(sent), Outcome::Failed, false);
                    }
                    return (status, sent, format!("{} after {}", not_taken(&e, tuning.idle), crate::text::bytes(sent)), Outcome::Failed, false);
                }
                sent += n as u64;
                left -= n as u64;
            }
            let _ = s.set_write_timeout(Some(tuning.idle));
            (status, sent, String::new(), Outcome::Ok, keep)
        }
        Err(Miss::NotFound) => simple(s, 404, "not found", Outcome::Refused, keep),
        Err(m) => simple(s, 403, &format!("refused: {}", m.words()), Outcome::Refused, keep),
    }
}

#[allow(clippy::too_many_arguments)]
fn put(s: &mut TcpStream, head: &Head, req: &crate::paths::Request, share: &Share, root: &crate::paths::Root, body: Result<Option<u64>, u16>, carry: &mut Vec<u8>, tuning: Tuning, stop: &Stop) -> (u16, u64, String, Outcome, bool) {
    // Every refusal before the body closes the connection: its body is never read.
    let refuse = |s: &mut TcpStream, st: u16, words: String| {
        let _ = send_simple(s, st, &format!("{}.\n", reason(st)), false, false);
        (st, 0, words, Outcome::Refused, false)
    };
    if !share.writes.load(Ordering::SeqCst) {
        let out = response_head(405, &[("Allow", "GET, HEAD".into())], 0, false);
        let _ = s.write_all(out.as_bytes());
        return (405, 0, "refused: uploads are off".into(), Outcome::Refused, false);
    }
    let len = match body {
        Ok(Some(n)) => n,
        Ok(None) => return refuse(s, 411, "refused: no Content-Length".into()),
        Err(411) => return refuse(s, 411, "refused: chunked uploads are not taken".into()),
        Err(st) => return refuse(s, st, "refused: a bad Content-Length".into()),
    };
    let made = root.create_upload(req, Some(len), share.limits());
    if stop.stopped() {
        // The server stopped while the create waited: an upload made goes again (its Drop).
        return (0, 0, STOPPED.into(), Outcome::Failed, false);
    }
    let mut up = match made {
        Ok(u) => u,
        Err(e) => {
            let st = match e {
                WriteError::Exists => 409,
                WriteError::TooBig => 413,
                WriteError::DiskFull => 507,
                WriteError::NotAFile => 409,
                WriteError::Invisible => 403,
                WriteError::ExplorerActs => {
                    // SNA3: the uploader is told why, in words.
                    let _ = send_simple(s, 403, crate::paths::EXPLORER_ACTS, false, false);
                    return (403, 0, format!("refused: {}", e.words()), Outcome::Refused, false);
                }
                WriteError::Miss(Miss::NotFound) => 404,
                WriteError::Miss(_) => 403,
            };
            return refuse(s, st, format!("refused: {}", e.words()));
        }
    };
    if head.get("Expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        && let Err(e) = s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
    {
        // The 100 never reached the client and nothing was created: status 0, the words alone.
        return (0, 0, not_taken(&e, tuning.idle), Outcome::Failed, false);
    }
    let _ = s.set_read_timeout(Some(tuning.idle));
    let mut left = len;
    let mut got = 0u64;
    // Bytes that came with the head belong to the body first.
    let first: Vec<u8> = std::mem::take(carry);
    let (now, later) = first.split_at((left as usize).min(first.len()));
    *carry = later.to_vec();
    if !now.is_empty() {
        if let Err(e) = up.write(now) {
            return write_failed(s, e, got);
        }
        got += now.len() as u64;
        left -= now.len() as u64;
    }
    let mut buf = vec![0u8; 64 * 1024];
    // IN-VibeServe-3: the body keeps its pace; no read waits past it either.
    let (t, pace) = (Instant::now(), tuning.pace);
    let slow = |s: &mut TcpStream, got: u64| {
        let _ = send_simple(s, 408, "The upload was too slow.\n", false, false);
        (408, got, format!("cut: the upload was too slow ({}) after {} (temp file removed)", pace.words(), crate::text::bytes(got)), Outcome::Failed, false)
    };
    // The idle time runs from the last bytes that came.
    let mut heard = Instant::now();
    while left > 0 {
        if pace.behind(t, got) {
            return slow(s, got);
        }
        let want = (left as usize).min(buf.len());
        let idle = tuning.idle.saturating_sub(crate::listen::since(heard));
        let _ = s.set_read_timeout(Some(tuning.timeout(pace.wait(t, got, idle))));
        // A body that stops or stalls got no answer: status 0, the words alone (no "201": nothing
        // was created and no status was sent).
        let n = match s.read(&mut buf[..want]) {
            Ok(0) => return (0, got, format!("the upload stopped after {} of {} (temp file removed)", crate::text::bytes(got), crate::text::bytes(len)), Outcome::Failed, false),
            Ok(n) => n,
            Err(_) if pace.behind(t, got) => return slow(s, got),
            // RL9-1: a socket timeout can fire a little before the time asked (as in syslog's
            // reader): one before the deadline and the idle time is waited out.
            Err(e) if timed_out(&e) && crate::listen::since(heard) < tuning.idle => continue,
            Err(_) => return (0, got, format!("the upload stalled or broke after {} (temp file removed)", crate::text::bytes(got)), Outcome::Failed, false),
        };
        heard = Instant::now();
        if let Err(e) = up.write(&buf[..n]) {
            return write_failed(s, e, got);
        }
        got += n as u64;
        left -= n as u64;
    }
    match up.finish() {
        Ok(n) => {
            let loc: String = req.parts.iter().map(|p| encode_segment(p)).collect::<Vec<_>>().join("/");
            let keep = head.keep_alive();
            let body = "Created.\n";
            let out = response_head(201, &[("Location", format!("/{loc}")), ("Content-Type", "text/plain; charset=utf-8".into())], body.len() as u64, keep);
            let ok = s.write_all(format!("{out}{body}").as_bytes()).is_ok();
            (201, n, "created".into(), Outcome::Ok, keep && ok)
        }
        Err(e) => write_failed(s, e, got),
    }
}

fn write_failed(s: &mut TcpStream, e: WriteError, got: u64) -> (u16, u64, String, Outcome, bool) {
    let st = match e {
        WriteError::Exists => 409,
        WriteError::TooBig => 413,
        WriteError::DiskFull => 507,
        _ => 500,
    };
    let _ = send_simple(s, st, &format!("{}.\n", reason(st)), false, false);
    (st, got, format!("{} (temp file removed)", e.words()), if st == 409 || st == 413 || st == 507 { Outcome::Refused } else { Outcome::Failed }, false)
}
