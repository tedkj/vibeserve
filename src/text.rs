//! Text from outside (file names a client asks for, syslog messages, HTTP request lines, adapter
//! and process names, the helper's answers) as it may be shown: in the window, toasts, the status
//! line, the activity logs and saved views. Cleaned at display only: the bytes a server writes to
//! disk and the names handed to Windows stay raw.

/// Characters that change how the text around them reads without showing themselves: controls,
/// bidirectional embeddings, overrides, isolates and marks, zero-width spaces and line
/// separators, the soft hyphen and the Unicode tag characters (U+E0000..U+E007F). The joiners
/// U+200C (ZWNJ) and U+200D (ZWJ) are not among them: emoji sequences and Persian, Arabic and
/// Indic names need them (family rule, 2026-10-20). The template's set (VibeTemplate text.rs).
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// Outside text as it may be shown: invisible characters gone, runs of whitespace (a newline or
/// tab included) one space, trimmed, at most `max` characters (an ellipsis marks a cut).
pub fn clean_max(s: &str, max: usize) -> String {
    let max = max.max(1);
    let mut out = String::with_capacity(s.len().min(max.saturating_mul(4)));
    let mut space = false;
    let mut n = 0usize;
    let mut cut = false;
    for c in s.chars() {
        // A line break or tab is a gap between words, not nothing: "Version\n15.2" stays two words.
        if c.is_whitespace() || c == '\u{2028}' || c == '\u{2029}' {
            space = !out.is_empty();
            continue;
        }
        if invisible(c) {
            continue;
        }
        if space {
            if n + 1 >= max {
                cut = true;
                break;
            }
            out.push(' ');
            n += 1;
            space = false;
        }
        if n >= max {
            cut = true;
            break;
        }
        out.push(c);
        n += 1;
    }
    if cut {
        // Room for the ellipsis: drop the last character (a char, never a byte).
        out.pop();
        out.push('…');
    }
    out
}

/// Outside text, at most 255 characters.
pub fn clean(s: &str) -> String {
    clean_max(s, 255)
}

/// UTF-16 from Windows as shown text: a lone surrogate becomes U+FFFD, then cleaned (the
/// template's; About's install check names a signer with it).
pub fn clean_wide(w: &[u16], max: usize) -> String {
    clean_max(&String::from_utf16_lossy(w), max)
}

/// Bytes from the wire as text: UTF-8 where it is valid, each invalid sequence as U+FFFD, then
/// cleaned to at most `max` characters.
pub fn clean_bytes(b: &[u8], max: usize) -> String {
    clean_max(&String::from_utf8_lossy(b), max)
}

/// A path as it may be shown (a root folder, a saved file): invisible characters gone, nothing
/// else touched (spaces inside names are real), at most 1024 characters.
pub fn clean_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy();
    let s = s.strip_prefix(r"\\?\UNC\").map(|r| format!(r"\\{r}")).unwrap_or_else(|| s.strip_prefix(r"\\?\").unwrap_or(&s).to_string());
    let mut out: String = s.chars().filter(|c| !invisible(*c)).take(1024).collect();
    if s.chars().count() > 1024 {
        out.pop();
        out.push('…');
    }
    out
}

/// A count with thin groups the way VibeWare writes them: 1 204, 100 000.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// A byte count as people read it: 0 B, 812 B, 14.2 KB, 1.4 GB (1024-based, one decimal from KB,
/// cut, never rounded up: 1023.96 KB is "1023.9 KB", not "1.0 MB").
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut unit = 0;
    let mut div: u64 = 1024;
    while unit + 1 < UNITS.len() && n / div >= 1024 {
        unit += 1;
        div *= 1024;
    }
    let tenths = (n as u128 * 10 / div as u128) as u64;
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit])
}

/// A rate in bytes per second, as `bytes` writes sizes, with "/s".
pub fn rate(bytes_per_s: f64) -> String {
    if !bytes_per_s.is_finite() || bytes_per_s < 0.0 {
        return "-".into();
    }
    format!("{}/s", bytes(bytes_per_s as u64))
}

/// A duration as the logs show it: 12 ms, 1.24 s, 3 min 05 s (cut, not rounded).
pub fn duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{}.{:02} s", ms / 1000, (ms % 1000) / 10)
    } else {
        let s = ms / 1000;
        format!("{} min {:02} s", s / 60, s % 60)
    }
}
