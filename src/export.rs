//! Save view: the shown syslog rows as text or CSV.
//!
//! The CSV uses this user's list separator and decimal symbol (`GetLocaleInfoEx`, LOCALE_SLIST
//! and LOCALE_SDECIMAL), so it opens as columns in a Norwegian Excel too (";" and ","), with a
//! UTF-8 BOM (Excel takes the file as ANSI without it). Every field is cleaned as shown text is
//! (control, bidi and invisible characters), and a field that would start with = + - @ (a
//! formula, from a device or anyone who can send syslog) gets a leading apostrophe.

use crate::syslog::{Message, facility_name, severity_name};

/// What the CSV separates with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locale {
    pub list: char,
    pub decimal: char,
}

impl Default for Locale {
    fn default() -> Locale {
        Locale { list: ',', decimal: '.' }
    }
}

/// This user's list separator and decimal symbol (Control Panel > Region). A value that cannot
/// be read, or that is unusable as a separator (a quote, a line break, the decimal symbol
/// itself), falls back to the invariant culture's.
pub fn user_locale() -> Locale {
    use windows_sys::Win32::Globalization::{GetLocaleInfoEx, LOCALE_SDECIMAL, LOCALE_SLIST};
    let get = |what: u32| -> Option<char> {
        let mut buf = [0u16; 8];
        // SAFETY: the user's default locale (a null name); a buffer of its length.
        let n = unsafe { GetLocaleInfoEx(std::ptr::null(), what, buf.as_mut_ptr(), buf.len() as i32) };
        if n <= 1 {
            return None;
        }
        String::from_utf16(&buf[..(n as usize - 1)]).ok()?.chars().next()
    };
    sane(get(LOCALE_SLIST), get(LOCALE_SDECIMAL))
}

/// The locale's characters, or the fallbacks where they cannot serve.
pub fn sane(list: Option<char>, decimal: Option<char>) -> Locale {
    let decimal = decimal.filter(|c| !c.is_control() && *c != '"').unwrap_or('.');
    let list = list.filter(|c| !c.is_control() && !c.is_alphanumeric() && *c != '"' && *c != decimal && *c != '\'').unwrap_or(if decimal == ',' { ';' } else { ',' });
    Locale { list, decimal }
}

const COLUMNS: [&str; 12] = ["received", "source", "protocol", "facility", "severity", "device time", "host", "app", "procid", "msgid", "structured data", "message"];

fn shown(s: &str) -> String {
    crate::text::clean_max(s, 70_000)
}

/// A received time with milliseconds, the fraction after this locale's decimal symbol.
fn received(m: &Message, decimal: char) -> String {
    let c = crate::host::local_clock(m.received);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}{decimal}{:03}", c.year, c.month, c.day, c.hour, c.minute, c.second, c.ms)
}

fn fields(m: &Message, decimal: char) -> [String; 12] {
    let mut msg = shown(m.msg());
    msg.push_str(m.window_note());
    [
        received(m, decimal),
        m.source.ip().to_string(),
        if m.tcp { "tcp".into() } else { "udp".into() },
        facility_name(m.facility).into(),
        severity_name(m.severity).into(),
        shown(m.device_time()),
        shown(m.host()),
        shown(m.app()),
        shown(m.procid()),
        shown(m.msgid()),
        shown(m.sd()),
        msg,
    ]
}

/// One CSV field: a formula start defused, quoted when it holds the separator, a quote or a
/// line break.
pub fn csv_field(s: &str, sep: char) -> String {
    let mut v = s.to_string();
    if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        v.insert(0, '\'');
    }
    if v.contains(sep) || v.contains('"') || v.contains('\n') || v.contains('\r') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

/// The rows as CSV (UTF-8 with a BOM, CRLF lines, a header).
pub fn csv(rows: &[&Message], loc: Locale) -> String {
    let sep = loc.list.to_string();
    let mut out = String::from('\u{FEFF}');
    out.push_str(&COLUMNS.iter().map(|c| csv_field(c, loc.list)).collect::<Vec<_>>().join(&sep));
    out.push_str("\r\n");
    for m in rows {
        out.push_str(&fields(m, loc.decimal).iter().map(|f| csv_field(f, loc.list)).collect::<Vec<_>>().join(&sep));
        out.push_str("\r\n");
    }
    out
}

/// The rows as plain text: one tab-separated line each, a header first.
pub fn text(rows: &[&Message]) -> String {
    let mut out = COLUMNS.join("\t");
    out.push_str("\r\n");
    for m in rows {
        out.push_str(&fields(m, '.').map(|f| f.replace('\t', " ")).join("\t"));
        out.push_str("\r\n");
    }
    out
}
