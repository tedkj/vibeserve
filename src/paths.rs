//! The one path validator TFTP and HTTP share, and the file system side behind it.
//!
//! A request names a file under the root folder. `validate` is pure: it splits on `/` and `\`,
//! takes a single leading separator as the root (every TFTP and HTTP client sends one), and
//! refuses everything that is not a plain relative name: drive letters, UNC and `\\?\` forms, `.`
//! and `..`, empty components, `:` anywhere (alternate data streams), DOS device names with any
//! extension (and their superscript-digit forms), trailing dots or spaces, control characters and
//! the characters Windows does not allow in names.
//!
//! Then the file is opened from the root's final path (`\\?\` form, so no name is reinterpreted)
//! and its own final path (`GetFinalPathNameByHandleW`) must lie inside the root's, compared
//! component by component without regard to case: a junction, symlink, mount point or 8.3 alias
//! that leads out is refused after the open, before a byte is read. Hidden and system files and
//! folders are treated as not there.
//!
//! Writes create new files only: they stream into `<name>.<6 hex>.vstmp` beside the target (the 6
//! hex are the transfer's own id), which is deleted by the system if the app dies (delete on
//! close) and by the app if the transfer fails; on success it is renamed by handle, without
//! replacing anything, and only then kept.

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};

/// Per file, at most 4 GiB.
pub const MAX_FILE: u64 = 4 * 1024 * 1024 * 1024;
/// A write never leaves less than 1 GiB free.
pub const MIN_FREE: u64 = 1024 * 1024 * 1024;
/// How often a running write asks for the free space again.
const FREE_CHECK_EVERY: u64 = 16 * 1024 * 1024;
/// A listing shows at most this many entries (and says how many it left out).
pub const MAX_LISTING: usize = 10_000;
/// The longest request taken (UTF-16 units of the joined relative path).
pub const MAX_REQUEST: usize = 4096;

// ---------- the validator (pure) ----------

/// Why a requested path was refused (said in the activity log, never to the client in detail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    DriveLetter,
    Unc,
    Verbatim,
    DotComponent,
    EmptyComponent,
    Colon,
    Device,
    TrailingDotOrSpace,
    Control,
    BadCharacter,
    TooLong,
}

impl Refused {
    pub fn words(self) -> &'static str {
        match self {
            Refused::DriveLetter => "a drive letter",
            Refused::Unc => "a network path",
            Refused::Verbatim => r"a \\?\ path",
            Refused::DotComponent => "a . or .. step",
            Refused::EmptyComponent => "an empty step (//)",
            Refused::Colon => "a colon (stream or drive)",
            Refused::Device => "a device name (CON, NUL, COM1…)",
            Refused::TrailingDotOrSpace => "a name ending in a dot or space",
            Refused::Control => "a control character",
            Refused::BadCharacter => "a character Windows does not allow in names",
            Refused::TooLong => "too long",
        }
    }
}

/// A request that passed: the names under the root, in order (none: the root itself), and
/// whether it ended in a separator (a folder, for HTTP).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub parts: Vec<String>,
    pub dir: bool,
}

impl Request {
    /// As the logs write it: `/firmware/c9300.bin`.
    pub fn shown(&self) -> String {
        let mut s = String::from("/");
        s.push_str(&self.parts.join("/"));
        if self.dir && !self.parts.is_empty() {
            s.push('/');
        }
        s
    }
}

fn is_sep(c: char) -> bool {
    c == '/' || c == '\\'
}

/// A DOS device name, whatever follows its first dot: CON, PRN, AUX, NUL, COM0-9, LPT0-9 (and the
/// superscript ¹ ² ³ forms), CONIN$, CONOUT$. Spaces before the dot count as nothing ("nul .txt").
pub fn is_device_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let up = base.to_uppercase();
    if matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    let mut cs = up.chars();
    let head: String = cs.by_ref().take(3).collect();
    let rest: Vec<char> = cs.collect();
    (head == "COM" || head == "LPT") && rest.len() == 1 && matches!(rest[0], '0'..='9' | '\u{00B9}' | '\u{00B2}' | '\u{00B3}')
}

/// Check one requested path. Pure: nothing is looked up.
pub fn validate(request: &str) -> Result<Request, Refused> {
    if request.encode_utf16().count() > MAX_REQUEST {
        return Err(Refused::TooLong);
    }
    if request.chars().any(|c| c.is_control()) {
        return Err(Refused::Control);
    }
    let mut s = request;
    let mut chars = s.chars();
    match (chars.next(), chars.next(), chars.next()) {
        // \\?\C:\..., //?/..., \\.\COM1
        (Some(a), Some(b), Some('?' | '.')) if is_sep(a) && is_sep(b) => return Err(Refused::Verbatim),
        (Some(a), Some(b), _) if is_sep(a) && is_sep(b) => return Err(Refused::Unc),
        (Some(a), _, _) if is_sep(a) => s = &s[a.len_utf8()..],
        _ => {}
    }
    if s.is_empty() {
        return Ok(Request { parts: Vec::new(), dir: true });
    }
    let dir = s.ends_with(is_sep);
    let body = if dir { &s[..s.len() - 1] } else { s };
    let mut parts = Vec::new();
    for (i, part) in body.split(is_sep).enumerate() {
        if part.is_empty() {
            return Err(Refused::EmptyComponent);
        }
        if part == "." || part == ".." {
            return Err(Refused::DotComponent);
        }
        if i == 0 && part.len() >= 2 && part.as_bytes()[0].is_ascii_alphabetic() && part.as_bytes()[1] == b':' {
            return Err(Refused::DriveLetter);
        }
        if part.contains(':') {
            return Err(Refused::Colon);
        }
        if part.chars().any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*')) {
            return Err(Refused::BadCharacter);
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(Refused::TrailingDotOrSpace);
        }
        if is_device_name(part) {
            return Err(Refused::Device);
        }
        if part.encode_utf16().count() > 255 {
            return Err(Refused::TooLong);
        }
        parts.push(part.to_string());
    }
    Ok(Request { parts, dir })
}

// ---------- the file system ----------

/// Why an open found nothing to serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Miss {
    /// Not there, hidden or system (the client is never told which).
    NotFound,
    /// It leads out of the root (a junction, symlink, mount point).
    Outside,
    /// Windows refused (permissions).
    Denied,
    /// Another program holds it.
    Busy,
    Io(String),
}

impl Miss {
    pub fn words(&self) -> String {
        match self {
            Miss::NotFound => "not found".into(),
            Miss::Outside => "refused: leads out of the root".into(),
            Miss::Denied => "access denied by Windows".into(),
            Miss::Busy => "in use by another program".into(),
            Miss::Io(e) => e.clone(),
        }
    }
}

fn miss_of(e: &std::io::Error) -> Miss {
    match e.raw_os_error() {
        Some(2 | 3 | 123 | 161 | 67 | 53) => Miss::NotFound, // file, path, name invalid, bad path, net name, net path
        Some(5) => Miss::Denied,
        Some(32 | 33) => Miss::Busy,
        _ => Miss::Io(e.to_string()),
    }
}

fn wide_of(units: &[u16]) -> Vec<u16> {
    units.iter().copied().chain(std::iter::once(0)).collect()
}

/// `CreateFileW` on exact units; the handle as a File.
fn create(path: &[u16], access: u32, share: u32, disposition: u32, flags: u32) -> std::io::Result<File> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::CreateFileW;
    let w = wide_of(path);
    // SAFETY: a NUL-terminated path; the handle goes to the File, which closes it.
    let h = unsafe { CreateFileW(w.as_ptr(), access, share, std::ptr::null(), disposition, flags, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(h as _) })
}

/// The final path of an open file or folder, `\\?\C:\...` or `\\?\UNC\server\share\...`.
pub fn final_path(f: &File) -> std::io::Result<Vec<u16>> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS};
    let mut buf = vec![0u16; 1024];
    for _ in 0..3 {
        // SAFETY: a buffer and its length in units.
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle() as _, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        buf = vec![0u16; n + 1];
    }
    Err(std::io::Error::other("the final path kept growing"))
}

/// Two names equal as Windows compares them (ordinal, ignoring case).
pub fn same_name(a: &[u16], b: &[u16]) -> bool {
    use windows_sys::Win32::Globalization::CompareStringOrdinal;
    // SAFETY: two buffers with their lengths.
    unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) == 2 }
}

fn components(p: &[u16]) -> Vec<&[u16]> {
    let mut v: Vec<&[u16]> = p.split(|&c| c == b'\\' as u16).collect();
    while v.last().is_some_and(|c| c.is_empty()) {
        v.pop();
    }
    v
}

/// A final path (`\\?\C:\`, `\\?\UNC\server\share`, `\\?\Volume{…}\`) that names a whole
/// volume or a whole network share: never a root (SEC-Serve-1). Pure.
pub fn volume_root(fin: &[u16]) -> bool {
    let s = String::from_utf16_lossy(fin).replace('/', "\\");
    let (unc, rest) = match s.strip_prefix(r"\\?\").or_else(|| s.strip_prefix(r"\\.\")) {
        Some(r) => match r.get(..4) {
            Some(p) if p.eq_ignore_ascii_case(r"UNC\") => (true, &r[4..]),
            _ => (false, r),
        },
        None => match s.strip_prefix(r"\\") {
            Some(r) => (true, r),
            None => (false, s.as_str()),
        },
    };
    let parts: Vec<&str> = rest.split('\\').filter(|c| !c.is_empty()).collect();
    if unc {
        parts.len() <= 2 // \\server\share
    } else if parts.first().is_some_and(|f| f.eq_ignore_ascii_case("GLOBALROOT")) {
        parts.len() <= 3 // \\?\GLOBALROOT\Device\HarddiskVolume3
    } else {
        parts.len() <= 1 // C:, Volume{…}
    }
}

/// The folder is the root of its volume wherever that is mounted (a drive letter, a folder, no
/// letter at all): its path within the volume is `\`.
fn at_volume_root(f: &File) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_NONE};
    let mut buf = [0u16; 8];
    // SAFETY: a buffer and its length in units.
    let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle() as _, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_NONE) } as usize;
    n > 0 && n < buf.len() && buf[..n].iter().all(|&c| c == b'\\' as u16)
}

/// Two final paths name the same folder (component by component, ignoring case).
fn same_path(a: &[u16], b: &[u16]) -> bool {
    inside(a, b) && inside(b, a)
}

/// An open file's or folder's identity: `FILE_ID_INFO` (volume serial, 128-bit id), else the
/// serial and the 64-bit index (FAT); None when it cannot be asked.
fn handle_id(f: &File) -> Option<crate::helper::FileIdent> {
    use windows_sys::Win32::Storage::FileSystem::*;
    let h = f.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    // SAFETY: plain structs filled by the calls, their sizes given; our open handle.
    unsafe {
        let mut info: FILE_ID_INFO = std::mem::zeroed();
        if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
            return Some((info.VolumeSerialNumber, info.FileId.Identifier));
        }
        let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        (GetFileInformationByHandle(h, &mut bh) != 0).then(|| crate::helper::fallback_id(bh.dwVolumeSerialNumber, bh.nFileIndexHigh, bh.nFileIndexLow))
    }
}

/// The identity of the folder at `units` (exact units, no NUL), None when it cannot be opened.
fn folder_id(units: &[u16]) -> Option<crate::helper::FileIdent> {
    let f = create(units, FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).ok()?;
    handle_id(&f)
}

/// `p` as a final path would spell it when it cannot be opened: absolute, `\\?\C:\…` or
/// `\\?\UNC\server\share\…`.
fn spelled_final(p: &Path) -> Vec<u16> {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let s = abs.to_string_lossy().replace('/', "\\");
    let s = if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        s
    } else if let Some(unc) = s.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{unc}")
    } else {
        format!(r"\\?\{s}")
    };
    s.encode_utf16().collect()
}

/// How a root relates to a user's profile folder (SEC-Serve-1, RIN1-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Holds {
    /// The root is the profile folder.
    Profile,
    /// The profile lies inside the root (`C:\Users`, `D:\Homes`).
    Parent,
}

/// Whether the root (its final path `fin`, its identity `id`) is the profile folder `p` or a
/// folder `p` lies inside. Judged on final paths, and by identity for `p` and every folder above
/// it up to its volume, so no other path to them (a share of this PC, `\\localhost\C$\Users`, a
/// mapped drive to one) is taken for a different folder (RIN1-2).
fn holds_profile(fin: &[u16], id: Option<crate::helper::FileIdent>, p: &Path) -> Option<Holds> {
    use std::os::windows::ffi::OsStrExt;
    let units: Vec<u16> = p.as_os_str().encode_wide().collect();
    let opened = create(&units, FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).ok();
    let pf = opened.as_ref().and_then(|f| final_path(f).ok()).unwrap_or_else(|| spelled_final(p));
    if inside(fin, &pf) {
        return Some(if same_path(fin, &pf) { Holds::Profile } else { Holds::Parent });
    }
    let id = id.filter(|&i| crate::helper::same_id(i, i))?;
    let parts = components(&pf);
    for n in (1..=parts.len()).rev() {
        let above = parts[..n].join(&(b'\\' as u16));
        if volume_root(&above) {
            break; // a whole volume or share is refused already
        }
        let theirs = if n == parts.len() { opened.as_ref().and_then(handle_id) } else { folder_id(&above) };
        if theirs.is_some_and(|t| crate::helper::same_id(t, id)) {
            return Some(if n == parts.len() { Holds::Profile } else { Holds::Parent });
        }
    }
    None
}

/// `inner` is `outer` or lies inside it, component by component, case-insensitively. A prefix of
/// characters is not enough: `C:\root2` is not inside `C:\root`.
pub fn inside(outer: &[u16], inner: &[u16]) -> bool {
    let (o, i) = (components(outer), components(inner));
    o.len() <= i.len() && o.iter().zip(i.iter()).all(|(a, b)| same_name(a, b))
}

fn attributes(path: &[u16]) -> Option<u32> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
    let w = wide_of(path);
    // SAFETY: a NUL-terminated path.
    let a = unsafe { GetFileAttributesW(w.as_ptr()) };
    (a != INVALID_FILE_ATTRIBUTES).then_some(a)
}

const HIDDEN_OR_SYSTEM: u32 = 0x2 | 0x4;
const DIRECTORY: u32 = 0x10;

/// Every step from below the root down to `fin` (both final paths) is neither hidden nor system.
/// A step whose attributes cannot be read counts as hidden: unknown is not "fine".
fn none_hidden(root: &[u16], fin: &[u16]) -> bool {
    let r = components(root).len();
    let parts = components(fin);
    for n in (r + 1)..=parts.len() {
        let prefix = parts[..n].join(&(b'\\' as u16));
        match attributes(&prefix) {
            Some(a) if a & HIDDEN_OR_SYSTEM == 0 => {}
            _ => return false,
        }
    }
    true
}

/// The root folder, held open (read, write and delete shared, so the user can still rename or
/// remove it; its final path follows a rename).
pub struct Root {
    dir: File,
    /// The folder as the user named it (for messages).
    pub shown: PathBuf,
}

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const SYNCHRONIZE: u32 = 0x0010_0000;
const OPEN_EXISTING: u32 = 3;
const CREATE_NEW: u32 = 1;

impl Root {
    /// Open the root folder, creating it (and its parents) first when `create` is set. It must
    /// be a folder, and neither a whole volume nor any of `profiles` nor a folder that holds one.
    pub fn open(path: &Path, create_it: bool, profiles: &[PathBuf]) -> Result<Root, String> {
        use std::os::windows::ffi::OsStrExt;
        let shown = crate::text::clean_path(path);
        if create_it && let Err(e) = std::fs::create_dir_all(path) {
            return Err(format!("The root folder {shown} could not be made: {e}"));
        }
        let units: Vec<u16> = path.as_os_str().encode_wide().collect();
        let dir = create(&units, FILE_READ_ATTRIBUTES | SYNCHRONIZE | 0x1 /* FILE_LIST_DIRECTORY */, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).map_err(|e| match miss_of(&e) {
            Miss::NotFound => format!("The root folder {shown} is not there."),
            Miss::Denied => format!("Windows refused to open the root folder {shown}."),
            _ => format!("The root folder {shown} could not be opened: {e}"),
        })?;
        let info = file_info(&dir).map_err(|e| format!("The root folder {shown} could not be read: {e}"))?;
        if info.attributes & DIRECTORY == 0 {
            return Err(format!("The root {shown} is a file, not a folder."));
        }
        // SEC-Serve-1 (Ted, 2026-10-28): never a whole drive or share, never the profile itself.
        // Judged by where the handle really is (Windows resolves junctions, symlinks, subst
        // drives, 8.3 names, case, `.`, `..` and separators), never by the spelling.
        let fin = final_path(&dir).map_err(|e| format!("The root folder {shown} could not be read: {e}"))?;
        if volume_root(&fin) || at_volume_root(&dir) {
            return Err(format!("VibeServe never shares a whole drive or network share ({shown}): pick a folder in it."));
        }
        // Never a user's profile folder, nor a folder one lies inside (`C:\Users`): RIN1-1/2.
        let id = handle_id(&dir);
        for p in profiles {
            match holds_profile(&fin, id, p) {
                Some(Holds::Profile) => return Err(format!("VibeServe never shares a whole user folder ({shown}): pick a folder in it.")),
                Some(Holds::Parent) => return Err(format!("VibeServe never shares a folder that holds a user folder ({shown}): pick a folder inside a user folder, or elsewhere.")),
                None => {}
            }
        }
        Ok(Root { dir, shown: path.to_path_buf() })
    }

    /// The root's final path now (it follows a rename of the folder).
    pub fn final_path(&self) -> Result<Vec<u16>, Miss> {
        final_path(&self.dir).map_err(|e| miss_of(&e))
    }

    /// The final path of the folder that would hold `req` (its parts but the last), opened and
    /// checked to lie inside the root and be neither hidden nor system.
    fn checked(&self, root: &[u16], f: &File) -> Result<Vec<u16>, Miss> {
        let fin = final_path(f).map_err(|e| miss_of(&e))?;
        if !inside(root, &fin) {
            return Err(Miss::Outside);
        }
        if !none_hidden(root, &fin) {
            return Err(Miss::NotFound);
        }
        Ok(fin)
    }

    fn target(root: &[u16], parts: &[String]) -> Vec<u16> {
        let mut t = root.to_vec();
        for p in parts {
            if t.last() != Some(&(b'\\' as u16)) {
                t.push(b'\\' as u16);
            }
            t.extend(p.encode_utf16());
        }
        t
    }

    /// Open what `req` names for reading: a file (with its size and time) or a folder.
    pub fn open_read(&self, req: &Request) -> Result<Found, Miss> {
        let root = self.final_path()?;
        let target = Self::target(&root, &req.parts);
        let f = create(&target, GENERIC_READ, 0x1 | 0x4 /* read, delete */, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | 0x0800_0000 /* sequential */).map_err(|e| miss_of(&e))?;
        let fin = self.checked(&root, &f)?;
        let info = file_info(&f).map_err(|e| miss_of(&e))?;
        if info.attributes & DIRECTORY != 0 {
            return Ok(Found::Dir(Folder { path: fin, at_root: req.parts.is_empty() }));
        }
        Ok(Found::File(Opened { file: f, size: info.size, modified: info.modified }))
    }

    /// Start a new file at `req` (create-new: an existing name is refused). `size` is the
    /// announced size when the client gave one (TFTP tsize, HTTP Content-Length).
    pub fn create_upload(&self, req: &Request, size: Option<u64>, limits: Limits) -> Result<Upload, WriteError> {
        let Some((name, folder)) = req.parts.split_last() else { return Err(WriteError::NotAFile) };
        if req.dir {
            return Err(WriteError::NotAFile);
        }
        // IN-VibeServe-1: a name that hides characters (a bidi override faking the extension)
        // is never made.
        if req.parts.iter().any(|p| p.chars().any(crate::text::invisible)) {
            return Err(WriteError::Invisible);
        }
        // SNA3: nothing Explorer acts on just by showing the folder.
        if explorer_acts_on(name) {
            return Err(WriteError::ExplorerActs);
        }
        if let Some(n) = size
            && n > limits.max_file {
                return Err(WriteError::TooBig);
            }
        let root = self.final_path().map_err(WriteError::Miss)?;
        let parent_path = Self::target(&root, folder);
        let parent = create(&parent_path, FILE_READ_ATTRIBUTES | SYNCHRONIZE | 0x1 | 0x2 | 0x4 /* list, add file, add subdir */, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).map_err(|e| WriteError::Miss(miss_of(&e)))?;
        let parent_fin = self.checked(&root, &parent).map_err(WriteError::Miss)?;
        if file_info(&parent).map_err(|e| WriteError::Miss(miss_of(&e)))?.attributes & DIRECTORY == 0 {
            return Err(WriteError::Miss(Miss::NotFound));
        }
        let mut target = parent_fin.clone();
        target.push(b'\\' as u16);
        target.extend(name.encode_utf16());
        if attributes(&target).is_some() {
            return Err(WriteError::Exists);
        }
        let free = free_space(&parent_fin).ok_or(WriteError::Miss(Miss::Io("the free space could not be read".into())))?;
        if free < limits.min_free || free - limits.min_free < size.unwrap_or(0) {
            return Err(WriteError::DiskFull);
        }
        // The temp name: the target's name, the transfer's own 6 hex, ".vstmp".
        let mut id = [0u8; 3];
        crate::host::random_bytes(&mut id);
        let tag: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let temp_name = format!("{name}.{tag}.vstmp");
        if temp_name.encode_utf16().count() > 255 {
            return Err(WriteError::Miss(Miss::Io("the name is too long for a temporary file beside it".into())));
        }
        let mut temp = parent_fin.clone();
        temp.push(b'\\' as u16);
        temp.extend(temp_name.encode_utf16());
        // On a local NTFS or ReFS volume the system deletes the temp when its handle closes,
        // however the app ends (delete on close, cleared on success); elsewhere (FAT, exFAT,
        // shares) clearing it may not be offered, so the app deletes it by handle itself.
        let on_close = local_ntfs(&parent, &parent_fin);
        // Two handles to the one new file, together shared with nobody (nobody reads it
        // half-written, renames or deletes it): the bytes go through one with write access that
        // lets only delete access in, rename and delete go through the other, with delete access
        // only, which lets only the first one's writes in. One handle could not do both: while a
        // handle with delete access is open, NTFS lets no other stream of the file be opened, and
        // the Mark of the Web is one (SNA3), written between the two opens.
        let file = create(&temp, 0x4000_0000 /* GENERIC_WRITE */ | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0x4 /* share delete */, CREATE_NEW, 0x80 /* normal */)
            .map_err(|e| WriteError::Miss(miss_of(&e)))?;
        // SNA3: marked before a byte comes; a mark that failed takes the temp with it (the
        // Upload's Drop, below).
        let marked = mark_from_elsewhere(&temp, &parent);
        let Some(del) = reopen(&file, 0x0001_0000 /* DELETE */ | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0x2 /* share write */, if on_close { FILE_FLAG_DELETE_ON_CLOSE } else { 0 }) else {
            let e = std::io::Error::last_os_error();
            // No handle that can delete it: by its name, which only this handle holds open.
            drop(file);
            let _ = std::fs::remove_file(PathBuf::from(<std::ffi::OsString as std::os::windows::ffi::OsStringExt>::from_wide(&temp)));
            return Err(WriteError::Miss(miss_of(&e)));
        };
        let up = Upload { file: Some(file), del: Some(del), parent: Some(parent), name: name.clone(), temp_name, on_close, written: 0, checked_at: 0, limits, parent_path: parent_fin };
        marked?;
        Ok(up)
    }
}

/// `ReOpenFile`: the same file again with other access, never another file of its name.
fn reopen(f: &File, access: u32, share: u32, flags: u32) -> Option<File> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::ReOpenFile;
    // SAFETY: our open handle; the new one goes to the File, which closes it.
    let h = unsafe { ReOpenFile(f.as_raw_handle() as _, access, share, flags) };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return None;
    }
    Some(unsafe { File::from_raw_handle(h as _) })
}

/// What an uploader is told when the name is one Explorer acts on (SNA3).
pub const EXPLORER_ACTS: &str = "VibeServe doesn't take shortcuts, .url, .website, .pif, .scf, .library-ms, .searchConnector-ms or desktop.ini files: Windows acts on them just by showing the folder they are in.\n";

/// SNA3: names Windows Explorer acts on just by showing their folder: it reads them for an icon,
/// a location or the folder's look, and can reach out to another computer while doing it (and
/// send it the user's Windows sign-in hash). `.website` and `.pif` are shortcut types too, whose
/// icon location Explorer reads like a `.url`'s (rev-wave2 RW2). Upper-cased as Windows compares
/// names, so `ſ` counts as `s`. Pure.
pub fn explorer_acts_on(name: &str) -> bool {
    let n = name.to_uppercase();
    n == "DESKTOP.INI" || [".LNK", ".URL", ".WEBSITE", ".PIF", ".SCF", ".LIBRARY-MS", ".SEARCHCONNECTOR-MS"].iter().any(|e| n.ends_with(e))
}

/// The Mark of the Web: the Internet zone, as a browser marks a download.
const ZONE_MARK: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

/// SNA3: mark a new upload (its temp file, before the rename, which keeps the stream) as coming
/// from another computer: a `Zone.Identifier` stream with ZoneId=3, so SmartScreen, Office's
/// Protected View and Windows' "open file" warning treat it as they treat a download. A volume
/// without named streams (FAT, exFAT) cannot hold the mark: there the file is taken unmarked, as a
/// browser's download is. Anywhere else a mark that cannot be written refuses the upload.
fn mark_from_elsewhere(temp: &[u16], parent: &File) -> Result<(), WriteError> {
    use std::io::Write;
    let mut ads = temp.to_vec();
    ads.extend(":Zone.Identifier".encode_utf16());
    let written = create(&ads, 0x4000_0000 /* GENERIC_WRITE */, 0, CREATE_NEW, 0x80 /* normal */).and_then(|mut f| f.write_all(ZONE_MARK));
    match written {
        Ok(()) => Ok(()),
        Err(_) if !named_streams(parent) => Ok(()),
        Err(e) => Err(WriteError::Miss(Miss::Io(format!("the file could not be marked as coming from another computer ({e})")))),
    }
}

/// Whether the volume of this folder keeps named streams. A volume that cannot be asked counts as
/// one that does: then a mark that failed refuses the upload.
fn named_streams(dir: &File) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
    let mut flags = 0u32;
    // SAFETY: our handle and one out value; no names asked for.
    let ok = unsafe { GetVolumeInformationByHandleW(dir.as_raw_handle() as _, std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut flags, std::ptr::null_mut(), 0) } != 0;
    !ok || flags & FILE_NAMED_STREAMS != 0
}

/// What a read found.
pub enum Found {
    File(Opened),
    Dir(Folder),
}

pub struct Opened {
    pub file: File,
    pub size: u64,
    /// FILETIME (100 ns since 1601, UTC).
    pub modified: u64,
}

pub struct Folder {
    /// Its final path.
    pub path: Vec<u16>,
    pub at_root: bool,
}

/// One entry of a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub dir: bool,
    pub size: u64,
    pub modified: u64,
}

/// A folder's entries: no hidden or system ones, none the validator would refuse (they could not
/// be fetched), at most `MAX_LISTING` (the second value counts the rest). Folders first, then by
/// name (ordinal, ignoring case, then exact: a total order).
pub fn list(folder: &Folder) -> Result<(Vec<Entry>, usize), Miss> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{FIND_FIRST_EX_LARGE_FETCH, FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, WIN32_FIND_DATAW};
    let mut pattern = folder.path.clone();
    pattern.extend("\\*".encode_utf16());
    let w = wide_of(&pattern);
    // SAFETY: zeroed is a valid WIN32_FIND_DATAW; the handle is closed below.
    let mut d: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let h = unsafe { FindFirstFileExW(w.as_ptr(), FindExInfoBasic, (&mut d as *mut WIN32_FIND_DATAW).cast(), FindExSearchNameMatch, std::ptr::null(), FIND_FIRST_EX_LARGE_FETCH) };
    if h == INVALID_HANDLE_VALUE {
        let e = std::io::Error::last_os_error();
        return if e.raw_os_error() == Some(2) { Ok((Vec::new(), 0)) } else { Err(miss_of(&e)) };
    }
    let mut out = Vec::new();
    let mut more = 0usize;
    loop {
        let len = d.cFileName.iter().position(|&c| c == 0).unwrap_or(d.cFileName.len());
        let units = &d.cFileName[..len];
        // A name that is not Unicode (a lone surrogate) cannot be asked for in a URL or TFTP
        // request: it is left out like the refused ones.
        if let Ok(name) = String::from_utf16(units)
            && name != "."
            && name != ".."
            && d.dwFileAttributes & HIDDEN_OR_SYSTEM == 0
            && validate(&name).is_ok_and(|r| r.parts.len() == 1)
        {
            if out.len() < MAX_LISTING {
                out.push(Entry {
                    name,
                    dir: d.dwFileAttributes & DIRECTORY != 0,
                    size: ((d.nFileSizeHigh as u64) << 32) | d.nFileSizeLow as u64,
                    modified: ((d.ftLastWriteTime.dwHighDateTime as u64) << 32) | d.ftLastWriteTime.dwLowDateTime as u64,
                });
            } else {
                more += 1;
            }
        }
        // SAFETY: the find handle and the data struct from above.
        if unsafe { FindNextFileW(h, &mut d) } == 0 {
            break;
        }
    }
    unsafe { FindClose(h) };
    sort_entries(&mut out);
    Ok((out, more))
}

/// Folders first, then names ordinal ignoring case, then exact (a total order: the sort can
/// never panic on odd names).
pub fn sort_entries(v: &mut [Entry]) {
    v.sort_by(|a, b| {
        b.dir.cmp(&a.dir).then_with(|| {
            let (x, y): (Vec<u16>, Vec<u16>) = (a.name.to_lowercase().encode_utf16().collect(), b.name.to_lowercase().encode_utf16().collect());
            x.cmp(&y).then_with(|| a.name.cmp(&b.name))
        })
    });
}

struct Info {
    attributes: u32,
    size: u64,
    modified: u64,
}

fn file_info(f: &File) -> std::io::Result<Info> {
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    // SAFETY: zeroed is valid for the struct the call fills.
    let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut i) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Info {
        attributes: i.dwFileAttributes,
        size: ((i.nFileSizeHigh as u64) << 32) | i.nFileSizeLow as u64,
        modified: ((i.ftLastWriteTime.dwHighDateTime as u64) << 32) | i.ftLastWriteTime.dwLowDateTime as u64,
    })
}

/// Free bytes available to this user on the volume holding `path` (a final path).
pub fn free_space(path: &[u16]) -> Option<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut dir = path.to_vec();
    if dir.last() != Some(&(b'\\' as u16)) {
        dir.push(b'\\' as u16);
    }
    let w = wide_of(&dir);
    let mut free = 0u64;
    // SAFETY: a NUL-terminated folder path and one out value.
    (unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) } != 0).then_some(free)
}

const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

/// Clear the delete-on-close a temp file was opened with (FileDispositionInfoEx): it then
/// survives its handle. False when the file system does not offer it.
fn keep_on_close(f: &File) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{FILE_DISPOSITION_FLAG_ON_CLOSE, FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle};
    let info = FILE_DISPOSITION_INFO_EX { Flags: FILE_DISPOSITION_FLAG_ON_CLOSE };
    // SAFETY: our handle and a struct of the size given.
    unsafe { SetFileInformationByHandle(f.as_raw_handle() as _, FileDispositionInfoEx, (&info as *const FILE_DISPOSITION_INFO_EX).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32) != 0 }
}

/// A folder on a local NTFS or ReFS volume (not a share): there a temp file can be opened
/// delete-on-close and kept later (measured on Windows 11: clearing works, setting it afterwards
/// does not, error 50).
fn local_ntfs(dir: &File, fin: &[u16]) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    let unc: Vec<u16> = r"\\?\UNC\".encode_utf16().collect();
    if fin.len() >= unc.len() && same_name(&fin[..unc.len()], &unc) {
        return false;
    }
    let mut fs = [0u16; 64];
    // SAFETY: our handle and a buffer for the file system's name.
    let ok = unsafe { GetVolumeInformationByHandleW(dir.as_raw_handle() as _, std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs.as_mut_ptr(), fs.len() as u32) } != 0;
    let len = fs.iter().position(|&c| c == 0).unwrap_or(0);
    let name = String::from_utf16_lossy(&fs[..len]);
    ok && (name == "NTFS" || name == "ReFS")
}

/// Delete the file this handle has open (it must have DELETE access): never another file of the
/// same name.
fn delete_by_handle(f: &File) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle};
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: our handle and a struct of the size given.
    unsafe { SetFileInformationByHandle(f.as_raw_handle() as _, FileDispositionInfo, (&info as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) != 0 }
}

/// Rename the open file to `target` (a full final path), never over an existing file. (A name
/// relative to a RootDirectory handle is refused by SetFileInformationByHandle: error 87,
/// measured.)
fn rename_to(f: &File, target: &[u16]) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle};
    // FILE_RENAME_INFO ends in a variable-length name: a buffer of u64s holds it aligned.
    let size = std::mem::size_of::<FILE_RENAME_INFO>() + target.len() * 2;
    let mut buf = vec![0u64; size.div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut FILE_RENAME_INFO;
    // SAFETY: the buffer is large enough for the struct and the name after it.
    unsafe {
        (*p).Anonymous.ReplaceIfExists = false;
        (*p).RootDirectory = std::ptr::null_mut();
        (*p).FileNameLength = (target.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(target.as_ptr(), (*p).FileName.as_mut_ptr(), target.len());
        if SetFileInformationByHandle(f.as_raw_handle() as _, FileRenameInfo, p as *const _, size as u32) == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// What a server serves, changed while it runs (no restart): the root folder in use (None:
/// not open), whether writes are on, and the write caps.
pub struct Share {
    pub root: std::sync::Mutex<Option<std::sync::Arc<Root>>>,
    pub writes: std::sync::atomic::AtomicBool,
    pub caps: std::sync::Mutex<Limits>,
}

impl Share {
    pub fn new(root: Option<std::sync::Arc<Root>>, writes: bool) -> std::sync::Arc<Share> {
        std::sync::Arc::new(Share { root: std::sync::Mutex::new(root), writes: std::sync::atomic::AtomicBool::new(writes), caps: std::sync::Mutex::new(Limits::default()) })
    }

    pub fn root(&self) -> Option<std::sync::Arc<Root>> {
        self.root.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_root(&self, r: Option<std::sync::Arc<Root>>) {
        *self.root.lock().unwrap_or_else(|e| e.into_inner()) = r;
    }

    pub fn limits(&self) -> Limits {
        *self.caps.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The write caps (tests lower them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_file: u64,
    pub min_free: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_file: MAX_FILE, min_free: MIN_FREE }
    }
}

/// Why a write was refused or stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The name is taken (create-new only).
    Exists,
    /// The request names a folder.
    NotAFile,
    /// Over the per-file cap.
    TooBig,
    /// It would leave less than the minimum free.
    DiskFull,
    /// The name has a character that does not show (a bidi override, a zero-width space): it
    /// could fake its extension in Explorer and the listing (IN-VibeServe-1).
    Invisible,
    /// A kind of file Explorer acts on just by showing its folder (SNA3).
    ExplorerActs,
    Miss(Miss),
}

impl WriteError {
    pub fn words(&self) -> String {
        match self {
            WriteError::Exists => "the name exists (no overwriting)".into(),
            WriteError::NotAFile => "not a file name".into(),
            WriteError::TooBig => format!("over the {} cap", crate::text::bytes(MAX_FILE)),
            WriteError::DiskFull => "the disk would have less than 1 GiB free".into(),
            WriteError::Invisible => "a name with a character that does not show".into(),
            WriteError::ExplorerActs => "a kind of file Windows acts on just by showing its folder".into(),
            WriteError::Miss(m) => m.words(),
        }
    }
}

/// A file being written. Dropped without `finish`, its temp file is deleted.
pub struct Upload {
    /// The temp file, for its bytes.
    file: Option<File>,
    /// The temp file again, for its rename and its delete (see `create_upload`).
    del: Option<File>,
    parent: Option<File>,
    parent_path: Vec<u16>,
    name: String,
    pub temp_name: String,
    /// The system deletes the temp if the app dies (delete on close is set).
    on_close: bool,
    written: u64,
    checked_at: u64,
    limits: Limits,
}

impl Upload {
    pub fn written(&self) -> u64 {
        self.written
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Append bytes: refused past the cap or when the disk gets too full (checked every 16 MiB).
    pub fn write(&mut self, b: &[u8]) -> Result<(), WriteError> {
        use std::io::Write;
        if self.written + b.len() as u64 > self.limits.max_file {
            return Err(WriteError::TooBig);
        }
        if self.written + b.len() as u64 >= self.checked_at + FREE_CHECK_EVERY {
            self.checked_at = self.written;
            match free_space(&self.parent_path) {
                Some(f) if f >= self.limits.min_free => {}
                Some(_) => return Err(WriteError::DiskFull),
                None => return Err(WriteError::Miss(Miss::Io("the free space could not be read".into()))),
            }
        }
        let f = self.file.as_mut().ok_or(WriteError::Miss(Miss::Io("already closed".into())))?;
        f.write_all(b).map_err(|e| if e.raw_os_error() == Some(112) { WriteError::DiskFull } else { WriteError::Miss(miss_of(&e)) })?;
        self.written += b.len() as u64;
        Ok(())
    }

    /// Done: flush, rename to the name (never over an existing file), keep it. The folder must
    /// still be where it was checked (its final path is read again now).
    pub fn finish(mut self) -> Result<u64, WriteError> {
        let (Some(f), Some(del), Some(parent)) = (self.file.as_ref(), self.del.as_ref(), self.parent.as_ref()) else { return Err(WriteError::Miss(Miss::Io("already closed".into()))) };
        if let Err(e) = f.sync_all() {
            return Err(WriteError::Miss(miss_of(&e)));
        }
        match final_path(parent) {
            Ok(now) if now == self.parent_path => {}
            Ok(_) => return Err(WriteError::Miss(Miss::Io("the folder moved while the file was written".into()))),
            Err(e) => return Err(WriteError::Miss(miss_of(&e))),
        }
        let mut target = self.parent_path.clone();
        if target.last() != Some(&(b'\\' as u16)) {
            target.push(b'\\' as u16);
        }
        target.extend(self.name.encode_utf16());
        if let Err(e) = rename_to(del, &target) {
            return Err(match e.raw_os_error() {
                Some(183 | 80) => WriteError::Exists, // ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS
                _ => WriteError::Miss(miss_of(&e)),
            });
        }
        // Renamed: now the file must survive its handle.
        if self.on_close && !keep_on_close(del) {
            // Cannot be kept: it goes (as a failed transfer) rather than half-kept.
            return Err(WriteError::Miss(Miss::Io("the finished file could not be kept".into())));
        }
        self.on_close = false;
        let written = self.written;
        self.file = None;
        self.del = None;
        self.parent = None;
        Ok(written)
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        let file = self.file.take();
        if let Some(d) = self.del.take() {
            // Our own temp, by handle: never another file of its name.
            if !self.on_close {
                let _ = delete_by_handle(&d);
            }
            drop(d);
        }
        drop(file); // with delete on close set, the last of the two handles removes it
    }
}
