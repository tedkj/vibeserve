//! The command line once the helper's own branch has passed (that one comes first in `main`).
//! A file dropped on the exe or its shortcut is a command-line argument: Windows starts the
//! app with the file's path. VibeServe takes no file on its command line, so a drop opens the
//! window and a toast says the file was left alone. Anything that looks like an option still
//! ends the process with exit code 2 before any window or file (the family rule).

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// The longest name a toast shows; a longer one keeps its start and end around an ellipsis.
const LONGEST: usize = 60;

/// What `main` does with its arguments.
#[derive(Debug, PartialEq)]
pub enum Start {
    /// No argument: the window.
    Window,
    /// Only plain paths (files dropped on the exe): the window, and this toast.
    Dropped(String),
    /// Anything else (an option, a blank argument, paths mixed with an option): exit 2.
    Refused,
}

/// The arguments after the exe's own name.
pub fn start(args: &[OsString]) -> Start {
    if args.is_empty() {
        Start::Window
    } else if args.iter().any(|a| !plain_path(a)) {
        Start::Refused
    } else {
        Start::Dropped(left_alone(args))
    }
}

/// Not blank, and no `-` or `/` first once the spaces and quotes around it are trimmed (lossy: a
/// name that is not Unicode keeps its other characters). The trim never removes a `-` or `/`, so
/// this covers the string as given too. The trim is for this test only; the toast keeps them.
fn plain_path(a: &OsStr) -> bool {
    let lossy = a.to_string_lossy();
    let t = lossy.trim_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');
    !t.is_empty() && !t.starts_with(['-', '/'])
}

/// The name a toast shows for a path (lossy). A Windows name never holds a `"`, so one is left
/// over from the command line's quoting (`"C:\Photos\"` ends in `\"`, an escaped quote): the
/// path is the text before it. Anything else, a `'` or a space included, belongs to the name. A
/// path with no name of its own shows its last folder (`C:\a\b\..` shows `a`) or its drive or
/// share (`C:\`), and a long name is cut in the middle.
fn shown(a: &OsStr) -> String {
    let lossy = a.to_string_lossy();
    let path = lossy.trim_start_matches('"').split('"').next().unwrap_or_default();
    let mut kept: Vec<Component> = Vec::new();
    for c in Path::new(path).components() {
        match (c, kept.last()) {
            (Component::ParentDir, Some(Component::Normal(_))) => {
                kept.pop();
            }
            (Component::ParentDir, Some(Component::RootDir)) => {}
            (c, _) => kept.push(c),
        }
    }
    let name = match kept.last() {
        Some(Component::Normal(n)) => n.to_string_lossy().into_owned(),
        Some(_) => kept.iter().collect::<PathBuf>().to_string_lossy().into_owned(),
        None => ".".to_string(),
    };
    let n = name.chars().count();
    if n <= LONGEST {
        return name;
    }
    let head: String = name.chars().take(LONGEST / 2).collect();
    let tail: String = name.chars().skip(n - (LONGEST - LONGEST / 2 - 1)).collect();
    format!("{head}\u{2026}{tail}")
}

/// The toast for dropped files: the first one's name (not its folder), and how many more.
fn left_alone(args: &[OsString]) -> String {
    let name = shown(&args[0]);
    let more = match args.len() - 1 {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    format!("VibeServe doesn't open files, so it left {name}{more} alone.")
}
