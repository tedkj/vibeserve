//! The one step that needs admin, inbound firewall rules for the servers, runs in a helper: this
//! same exe relaunched elevated (`ShellExecuteExW` "runas": one UAC prompt, which the user may
//! decline) as `VibeServe.exe --firewall <32 hex> <parent pid>`. The app never runs elevated.
//!
//! The app makes a named pipe with a random name (128 bits from the system's generator) and a
//! DACL with one entry, the current user's SID; first instance only, no remote clients. It takes
//! as its client only the process it launched, running this exe (`QueryFullProcessImageNameW`,
//! compared by file identity, `FILE_ID_INFO`, never by path); the helper connects at
//! identification level only and checks the pipe's server the same way.
//!
//! The helper takes from the pipe only what its requests may say: which servers (three words),
//! TCP or UDP, and the ports (1-65535), at most 8 rules; its own path comes from
//! `GetModuleFileNameW`, the rules' names, scope (this exe, `LocalSubnet`) and group are its own.
//! It sets the rules to exactly the list it is sent, removes rules a crashed VibeServe left
//! (their owner, a process id with its start time, is gone), and removes its own when told,
//! when the pipe closes, when the parent exits (it waits on the parent's handle) and after 24 h
//! at the most. Its answers are untrusted input to the app: one line of at most 4 KiB, strict
//! JSON, counts in range.

use crate::firewall::{self, Firewall, NewRule, Owner, Purpose};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

/// The command-line switch the helper runs under.
pub const ARG: &str = "--firewall";
/// A message on the pipe: one JSON line of at most this many bytes.
pub const MAX_LINE: usize = 4096;
/// The helper's hard limit.
pub const MAX_LIFE: Duration = Duration::from_secs(24 * 3600);
/// How long the app waits for the helper to connect once the prompt is up (the user may take
/// a while to answer it).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
/// At most this many rules in one request (three servers, syslog on two protocols: 4).
pub const MAX_RULES: usize = 8;

/// One rule the app wants: a server, its protocol and port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Want {
    pub purpose: Purpose,
    pub tcp: bool,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// "set" (make our rules exactly `rules`), "close" (remove ours and leave), "clean" (remove
    /// rules crashed instances left, and leave).
    pub op: String,
    #[serde(default)]
    pub rules: Vec<Want>,
    /// With the first "set": also remove Windows' block rules for this exe.
    #[serde(default)]
    pub remove_blocks: bool,
    /// The app's user (its token's SID): the rules name it, and the helper checks it against
    /// its parent's token (R-SERVE-5: the admin who answered the prompt is not the user).
    #[serde(default)]
    pub user: String,
}

impl Request {
    pub fn set(rules: Vec<Want>, remove_blocks: bool) -> Request {
        Request { op: "set".into(), rules, remove_blocks, user: firewall::user_sid().into() }
    }

    pub fn close() -> Request {
        Request { op: "close".into(), rules: Vec::new(), remove_blocks: false, user: firewall::user_sid().into() }
    }

    pub fn clean() -> Request {
        Request { op: "clean".into(), rules: Vec::new(), remove_blocks: false, user: firewall::user_sid().into() }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Reply {
    pub ok: bool,
    /// Rules added now.
    pub added: u32,
    /// Our own rules removed now.
    pub removed: u32,
    /// Rules of crashed instances removed.
    pub stale: u32,
    /// Windows' block rules for this exe removed.
    pub blocks: u32,
    /// Our rules in place after the request.
    pub active: u32,
    pub error: String,
}

/// A line read from a pipe, at most `MAX_LINE` bytes, or why not.
fn read_line(r: &mut impl Read) -> Result<String, String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => return Err("the pipe closed".into()),
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) => {
                out.push(b[0]);
                if out.len() > MAX_LINE {
                    return Err("a message longer than 4 KiB".into());
                }
            }
            Err(e) => return Err(format!("the pipe failed ({e})")),
        }
    }
    String::from_utf8(out).map_err(|_| "a message that is not text".into())
}

fn line(v: &impl Serialize) -> Vec<u8> {
    let mut s = serde_json::to_vec(v).unwrap_or_default();
    s.push(b'\n');
    s
}

/// The reply as the app takes it: strict, bounded, and an ok with an error is no ok.
pub fn parse_reply(s: &str) -> Result<Reply, String> {
    if s.len() > MAX_LINE {
        return Err("the helper's answer is too long".into());
    }
    let r: Reply = serde_json::from_str(s).map_err(|_| "the helper's answer is not one it gives".to_string())?;
    if r.ok && !r.error.is_empty() {
        return Err("the helper's answer contradicts itself".into());
    }
    if r.added as usize > MAX_RULES || r.active as usize > MAX_RULES || r.removed > 1000 || r.stale > 1000 || r.blocks > 1000 {
        return Err("the helper's answer has impossible counts".into());
    }
    Ok(Reply { error: crate::text::clean(&r.error), ..r })
}

/// A request as the helper takes it: strict, at most 8 rules, every port in range, no rule twice.
pub fn parse_request(s: &str) -> Result<Request, String> {
    let r: Request = serde_json::from_str(s).map_err(|_| "not a request".to_string())?;
    if !r.user.is_empty() && !firewall::sid_shaped(&r.user) {
        return Err("a user that is not a SID".into());
    }
    match r.op.as_str() {
        "set" => {
            if r.rules.len() > MAX_RULES {
                return Err("more than 8 rules".into());
            }
            if r.rules.iter().any(|w| w.port == 0) {
                return Err("a port outside 1-65535".into());
            }
            let mut seen = std::collections::HashSet::new();
            if !r.rules.iter().all(|w| seen.insert((w.tcp, w.port))) {
                return Err("a port and protocol twice".into());
            }
            Ok(r)
        }
        "close" | "clean" if r.rules.is_empty() && !r.remove_blocks => Ok(r),
        _ => Err("an unknown request".into()),
    }
}

// ---------- the helper (elevated) ----------

/// The user the helper's rules name: its parent's, read from the parent's token. The app's word
/// for it must agree (a mismatch ends the session); when the token cannot be read, the app's
/// word stands (the pipe's server was checked: the parent, running this exe).
pub fn rules_user(parent: Option<&str>, claimed: &str) -> Result<String, String> {
    match parent {
        Some(p) if !claimed.is_empty() && !claimed.eq_ignore_ascii_case(p) => Err("the app named a user other than the one it runs as".into()),
        Some(p) => Ok(p.to_string()),
        None => Ok(claimed.to_string()),
    }
}

/// One request, done against `fw` for `user` (the SID the rules name, and whose crashed
/// instances' rules are stale). `first`: the session's first "set" also removes what crashed
/// instances left (and Windows' block rules, when asked).
#[allow(clippy::too_many_arguments)]
pub fn handle(fw: &dyn Firewall, exe: &Path, owner: Owner, user: &str, req: &Request, first: &mut bool, alive: &dyn Fn(Owner) -> bool) -> Reply {
    let mut r = Reply::default();
    let res: Result<(), String> = (|| {
        match req.op.as_str() {
            "clean" => {
                r.stale = fw.remove(&|x| firewall::stale_for(x, user, alive))? as u32;
            }
            "close" => {
                r.removed = fw.remove(&|x| firewall::mine(x, owner))? as u32;
            }
            _ => {
                if *first {
                    *first = false;
                    r.stale = fw.remove(&|x| firewall::stale_for(x, user, alive))? as u32;
                    if req.remove_blocks {
                        r.blocks = fw.remove(&|x| firewall::blocks_this_exe(x, exe))? as u32;
                    }
                }
                let want: Vec<NewRule> = req.rules.iter().map(|w| NewRule::server(exe, w.purpose, w.tcp, w.port, owner, user)).collect();
                r.removed = fw.remove(&|x| firewall::mine(x, owner) && !want.iter().any(|n| n.matches(x)))? as u32;
                let have: Vec<firewall::Rule> = fw.rules()?.into_iter().filter(|x| firewall::mine(x, owner)).collect();
                for n in &want {
                    if !have.iter().any(|x| n.matches(x)) {
                        fw.add(n)?;
                        r.added += 1;
                    }
                }
                r.active = want.len() as u32;
            }
        }
        Ok(())
    })();
    match res {
        Ok(()) => r.ok = true,
        Err(e) => {
            r.error = e;
            r.active = 0;
        }
    }
    r
}

/// The helper's whole job on an open pipe: requests until "close" or "clean", the pipe's end,
/// the parent's exit, or `life`; then its own rules go in every case. A reader thread reads,
/// does and answers each request (one thread per pipe end: synchronous I/O on one handle is
/// serialised); this thread waits for the parent, the reader's end or the time limit. A reader
/// still waiting in a read then is left behind (the helper's process ends with `run`).
/// `parent_user`: the parent's user from its token (None: unreadable), see `rules_user`.
#[allow(clippy::too_many_arguments)]
pub fn serve(pipe: std::fs::File, parent: RawHandle, owner: Owner, parent_user: Option<String>, fw: std::sync::Arc<dyn Firewall + Send + Sync>, exe: &Path, life: Duration) -> i32 {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let lock = Arc::new(Mutex::new(()));
    let over = Arc::new(AtomicBool::new(false));
    // SAFETY: an unnamed manual-reset event; it stays open while the reader may set it.
    let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) } as usize;
    let (l2, o2, f2, exe2) = (lock.clone(), over.clone(), fw.clone(), exe.to_path_buf());
    let reader = std::thread::Builder::new().name("firewall-pipe".into()).spawn(move || {
        let mut pipe = pipe;
        let mut first = true;
        loop {
            let parsed = read_line(&mut pipe).and_then(|l| parse_request(&l)).and_then(|r| rules_user(parent_user.as_deref(), &r.user).map(|u| (r, u)));
            let (req, user) = match parsed {
                Ok(r) => r,
                Err(e) => {
                    // The pipe's end, or something that is not a request: the end.
                    let _ = pipe.write_all(&line(&Reply { error: e, ..Reply::default() }));
                    break;
                }
            };
            let reply = {
                let _g = l2.lock().unwrap_or_else(|e| e.into_inner());
                if o2.load(Ordering::SeqCst) {
                    break; // the helper is ending: nothing more is added
                }
                handle(f2.as_ref(), &exe2, owner, &user, &req, &mut first, &firewall::alive)
            };
            let sent = pipe.write_all(&line(&reply)).is_ok();
            if req.op != "set" || !sent {
                break;
            }
        }
        // SAFETY: the event is never closed while a reader may run (see below).
        unsafe { SetEvent(ev as HANDLE) };
    });
    if reader.is_err() {
        let _ = fw.remove(&|x| firewall::mine(x, owner));
        return 1;
    }
    let handles = [parent as HANDLE, ev as HANDLE];
    let ms = life.as_millis().min(u32::MAX as u128 - 1) as u32;
    // SAFETY: two handles; a bounded wait. A parent handle the wait refuses still leaves the
    // pipe and the time limit.
    let w = unsafe {
        match WaitForMultipleObjects(2, handles.as_ptr(), 0, ms) {
            WAIT_FAILED => WaitForSingleObject(handles[1], ms),
            w => w,
        }
    };
    {
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        over.store(true, Ordering::SeqCst);
        let _ = fw.remove(&|x| firewall::mine(x, owner));
    }
    if w == WAIT_OBJECT_0 + 1 {
        // The reader has finished: its event can go. (Else it is left open with the reader.)
        unsafe { CloseHandle(ev as HANDLE) };
    }
    0
}

/// `VibeServe.exe --firewall <32 hex> <parent pid>`. Exit codes: 0 done, 2 bad arguments, 3 not
/// elevated, 4 the hard limit, 5 the pipe or its server was wrong, 6 the parent is gone.
pub fn run(args: &[std::ffi::OsString]) -> i32 {
    let Some((id, pid)) = parse_args(args) else { return 2 };
    if !firewall::elevated() {
        return 3;
    }
    std::thread::spawn(|| {
        std::thread::sleep(MAX_LIFE + Duration::from_secs(60));
        // SAFETY: ends this process (the next start removes what it left).
        unsafe { ExitProcess(4) };
    });
    let Some(exe) = crate::host::own_exe() else { return 5 };
    // The parent first, then its pipe: the pipe's server must be that process, running this exe.
    // SAFETY: plain arguments; the handle is closed by the OwnedHandle.
    let parent = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if parent.is_null() {
        return 6;
    }
    let parent = unsafe { OwnedHandle::from_raw_handle(parent as RawHandle) };
    let Some(started) = firewall::started(pid) else { return 6 };
    let Some(pipe) = connect(&pipe_path(&id), pid, &exe) else { return 5 };
    let user = firewall::process_user(parent.as_handle());
    serve(pipe, parent.as_raw_handle(), Owner { pid, started }, user, std::sync::Arc::new(firewall::System), &exe, MAX_LIFE)
}

/// Exactly `--firewall <32 lower-case hex> <pid>`, nothing else.
pub fn parse_args(args: &[std::ffi::OsString]) -> Option<(String, u32)> {
    if args.len() != 4 || args[1] != ARG {
        return None;
    }
    let id = args[2].to_str()?;
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let pid = args[3].to_str()?;
    if pid.is_empty() || pid.len() > 10 || !pid.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((id.to_string(), pid.parse().ok().filter(|p| *p != 0)?))
}

pub fn pipe_path(id: &str) -> String {
    format!(r"\\.\pipe\vibeserve-fw-{id}")
}

// ---------- who is at the other end: file identity, not names ----------

/// A file identity: the volume serial and the 128-bit file id.
pub(crate) type FileIdent = (u64, [u8; 16]);

/// Two identities are one file: equal, and neither the serial nor the id is zero (a zero is
/// "unknown", never "the same": VIBEWARE "Identity, not names").
pub(crate) fn same_id(a: FileIdent, b: FileIdent) -> bool {
    a == b && a.0 != 0 && a.1 != [0; 16]
}

/// The identity where a file system has no `FILE_ID_INFO` (FAT, exFAT): the 32-bit serial and
/// the 64-bit index in the low 8 bytes, the high 8 bytes zero.
pub(crate) fn fallback_id(serial: u32, index_high: u32, index_low: u32) -> FileIdent {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&((u64::from(index_high) << 32) | u64::from(index_low)).to_le_bytes());
    (u64::from(serial), id)
}

/// A file's identity (`FILE_ID_INFO`, else the serial and 64-bit index); None when the file
/// cannot be opened or asked.
fn file_id(path: &Path) -> Option<FileIdent> {
    use windows_sys::Win32::Storage::FileSystem::*;
    let p = crate::host::wide_path(path);
    // SAFETY: a NUL-terminated path, attributes only, sharing everything; closed below.
    let h = unsafe { CreateFileW(p.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: plain structs filled by the calls, sizes given; the handle just opened.
    let id = unsafe {
        let mut info: FILE_ID_INFO = std::mem::zeroed();
        if GetFileInformationByHandleEx(h, FileIdInfo, (&mut info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32) != 0 {
            Some((info.VolumeSerialNumber, info.FileId.Identifier))
        } else {
            let mut bh: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            (GetFileInformationByHandle(h, &mut bh) != 0).then(|| fallback_id(bh.dwVolumeSerialNumber, bh.nFileIndexHigh, bh.nFileIndexLow))
        }
    };
    unsafe { CloseHandle(h) };
    id
}

/// Two paths name the same file: by identity, never by name (a subst or mapped drive, a
/// junction, a hard link, a `\\?\` or 8.3 spelling of the very same exe still match; a zero id
/// never does).
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (file_id(a), file_id(b)) {
        (Some(x), Some(y)) => same_id(x, y),
        _ => false,
    }
}

/// The image path of process `pid` (None when it cannot be opened or asked).
fn image_of(pid: u32) -> Option<std::path::PathBuf> {
    // SAFETY: a query-only open of a process by id; closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32_768];
    let mut n = buf.len() as u32;
    // SAFETY: a buffer and its length in units.
    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } != 0;
    unsafe { CloseHandle(h) };
    ok.then(|| crate::host::path_from_wide(&buf[..n as usize]))
}

/// Process `pid` is a real one and runs `exe` (the same file, by identity).
fn runs(pid: u32, exe: &Path) -> bool {
    pid != 0 && image_of(pid).is_some_and(|img| same_file(&img, exe))
}

/// The app's pipe's client is process `pid` (the one the app launched), running `exe`.
fn client_is(pipe: HANDLE, pid: u32, exe: &Path) -> bool {
    let mut client = 0u32;
    // SAFETY: our pipe handle and an out value.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut client) } != 0;
    ok && client == pid && runs(client, exe)
}

/// The helper's end: identification level only (the app cannot act as the helper), and the
/// pipe's server must be `parent`, running `exe` (this exe, by identity). Nothing is read from
/// the pipe before that holds.
fn connect(path: &str, parent: u32, exe: &Path) -> Option<std::fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
    let w = crate::host::wide(path);
    for _ in 0..20 {
        // SAFETY: a NUL-terminated name; the handle goes to the File.
        let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            if unsafe { GetLastError() } == ERROR_PIPE_BUSY {
                unsafe { WaitNamedPipeW(w.as_ptr(), 500) };
            } else {
                std::thread::sleep(Duration::from_millis(100));
            }
            continue;
        }
        let f = unsafe { std::fs::File::from_raw_handle(h as RawHandle) };
        let mut server = 0u32;
        // SAFETY: our pipe handle and an out value.
        if unsafe { GetNamedPipeServerProcessId(h, &mut server) } == 0 || server != parent || !runs(server, exe) {
            return None;
        }
        return Some(f);
    }
    None
}

// ---------- the app's side ----------

/// How the helper is started: elevated for real, a thread in tests.
pub trait Launcher: Send + Sync {
    /// Start the helper with these arguments (the UAC prompt owned by `hwnd`); its process
    /// handle, or why not.
    fn launch(&self, args: &str, hwnd: isize) -> Result<OwnedHandle, Launch>;
}

/// Why there is no helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launch {
    /// The user said no at the UAC prompt.
    Declined,
    Failed(String),
}

/// `ShellExecuteExW` with the "runas" verb on this exe: one UAC prompt. Blocks until the prompt
/// is answered: call it on a worker.
pub struct Elevated;

impl Launcher for Elevated {
    fn launch(&self, args: &str, hwnd: isize) -> Result<OwnedHandle, Launch> {
        use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
        use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
        let exe = crate::host::own_exe().ok_or(Launch::Failed("this program's own path could not be read".into()))?;
        let verb = crate::host::wide("runas");
        let file = crate::host::wide_path(&exe);
        let params = crate::host::wide(args);
        // SAFETY: COM for the shell on this (worker) thread; a filled-in struct whose strings
        // outlive the call; the process handle comes back ours to close.
        unsafe {
            CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
            let mut info: windows_sys::Win32::UI::Shell::SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            info.hwnd = hwnd as _;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                let e = GetLastError();
                return Err(if e == ERROR_CANCELLED { Launch::Declined } else { Launch::Failed(format!("Windows did not start the firewall helper ({})", std::io::Error::from_raw_os_error(e as i32))) });
            }
            if info.hProcess.is_null() {
                return Err(Launch::Failed("Windows started the firewall helper without a handle to it".into()));
            }
            Ok(OwnedHandle::from_raw_handle(info.hProcess as RawHandle))
        }
    }
}

/// A security descriptor whose DACL allows only the current user (read and write).
struct UserOnly {
    _token_user: Vec<u64>,
    _acl: Vec<u64>,
    sd: Box<windows_sys::Win32::Security::SECURITY_DESCRIPTOR>,
}

fn user_only() -> Option<UserOnly> {
    use windows_sys::Win32::Security::*;
    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: the current process's token, query only; closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return None;
    }
    let mut need = 0u32;
    unsafe { GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need) };
    let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
    let ok = unsafe { GetTokenInformation(tok, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } != 0;
    unsafe { CloseHandle(tok) };
    if !ok {
        return None;
    }
    // SAFETY: the buffer holds a TOKEN_USER written by the call above.
    let sid = unsafe { (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid };
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    let acl_len = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>() + sid_len;
    let mut acl = vec![0u64; acl_len.div_ceil(8)];
    let pacl = acl.as_mut_ptr() as *mut ACL;
    // SAFETY: an ACL buffer of `acl_len` bytes; one ACE for the user's SID.
    unsafe {
        if InitializeAcl(pacl, acl_len as u32, ACL_REVISION) == 0 || AddAccessAllowedAce(pacl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, sid) == 0 {
            return None;
        }
    }
    let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
    let psd = (&mut *sd as *mut SECURITY_DESCRIPTOR).cast();
    // SAFETY: a descriptor in our memory, the DACL above (both outlive the pipe's creation).
    unsafe {
        if InitializeSecurityDescriptor(psd, 1 /* SECURITY_DESCRIPTOR_REVISION */) == 0 || SetSecurityDescriptorDacl(psd, 1, pacl, 0) == 0 {
            return None;
        }
    }
    Some(UserOnly { _token_user: tu, _acl: acl, sd })
}

/// The app's end of a pipe: a random name, the current user only, one instance, local clients
/// only, overlapped (every wait has a deadline). Its handle and its 32-hex id.
fn make_pipe() -> Result<(OwnedHandle, String), String> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
    let sec = user_only().ok_or("the pipe's permissions could not be made")?;
    let mut id = [0u8; 16];
    crate::host::random_bytes(&mut id);
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let name = crate::host::wide(&pipe_path(&id));
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: (&*sec.sd as *const _) as *mut _, bInheritHandle: 0 };
    // SAFETY: a NUL-terminated name and the attributes above, alive through the call.
    let h = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &sa) };
    drop(sec);
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("the helper's pipe could not be made ({})", std::io::Error::last_os_error()));
    }
    Ok((unsafe { OwnedHandle::from_raw_handle(h as RawHandle) }, id))
}

/// One overlapped read or write on the app's pipe, done within `timeout` or cancelled.
fn ov_io(h: HANDLE, buf: &mut [u8], write: bool, timeout: Duration) -> Result<usize, String> {
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    // SAFETY: an event for this operation, closed by the OwnedHandle; the OVERLAPPED and the
    // buffer outlive the operation (it is complete, or cancelled and complete, before return).
    unsafe {
        let ev = OwnedHandle::from_raw_handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) as RawHandle);
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.hEvent = ev.as_raw_handle() as HANDLE;
        let mut n = 0u32;
        let ok = if write { WriteFile(h, buf.as_ptr(), buf.len() as u32, &mut n, &mut ov) } else { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, &mut ov) };
        if ok == 0 && GetLastError() != ERROR_IO_PENDING {
            return Err(format!("the pipe failed ({})", std::io::Error::last_os_error()));
        }
        if GetOverlappedResultEx(h, &ov, &mut n, timeout.as_millis().min(u32::MAX as u128 - 1) as u32, 0) == 0 {
            let e = GetLastError();
            if e == WAIT_TIMEOUT || e == ERROR_IO_INCOMPLETE {
                CancelIoEx(h, &ov);
                GetOverlappedResultEx(h, &ov, &mut n, INFINITE, 0);
                return Err("the helper did not answer in time".into());
            }
            return Err(format!("the pipe failed ({})", std::io::Error::from_raw_os_error(e as i32)));
        }
        Ok(n as usize)
    }
}

fn read_reply(h: HANDLE, timeout: Duration) -> Result<Reply, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut out = Vec::new();
    let mut b = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err("the helper did not answer in time".into());
        }
        let n = ov_io(h, &mut b, false, left)?;
        if n == 0 {
            return Err("the helper closed the pipe".into());
        }
        out.extend_from_slice(&b[..n]);
        if let Some(i) = out.iter().position(|c| *c == b'\n') {
            return parse_reply(std::str::from_utf8(&out[..i]).map_err(|_| "the helper's answer is not text")?);
        }
        if out.len() > MAX_LINE {
            return Err("the helper's answer is too long".into());
        }
    }
}

/// The helper at work for the app (the rules exist while it lives).
pub struct Session {
    pipe: OwnedHandle,
    process: OwnedHandle,
}

// SAFETY: the handles are used by one thread at a time (the controller's firewall worker).
unsafe impl Send for Session {}

/// Start the helper and send it its first request: the session and the helper's answer, or why
/// not. Blocks (the UAC prompt, then up to two minutes): call it on a worker.
pub fn start(launcher: &dyn Launcher, hwnd: isize, first: &Request) -> Result<(Session, Reply), Launch> {
    let (pipe, id) = make_pipe().map_err(Launch::Failed)?;
    let h = pipe.as_raw_handle() as HANDLE;
    // Listen before launching: the helper may connect at once.
    // SAFETY: an event for the connect, closed by the OwnedHandle; the OVERLAPPED lives until
    // the connect completed or was cancelled.
    let ev = unsafe { OwnedHandle::from_raw_handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) as RawHandle) };
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.as_raw_handle() as HANDLE;
    let cancel = |ov: &OVERLAPPED| unsafe {
        CancelIoEx(h, ov);
        let mut n = 0;
        GetOverlappedResultEx(h, ov, &mut n, INFINITE, 0);
    };
    let pending = unsafe {
        if ConnectNamedPipe(h, &mut ov) != 0 {
            false
        } else {
            match GetLastError() {
                ERROR_IO_PENDING => true,
                ERROR_PIPE_CONNECTED => false,
                e => return Err(Launch::Failed(format!("the helper's pipe failed ({})", std::io::Error::from_raw_os_error(e as i32)))),
            }
        }
    };
    let process = match launcher.launch(&format!("{ARG} {id} {}", std::process::id()), hwnd) {
        Ok(p) => p,
        Err(e) => {
            if pending {
                cancel(&ov);
            }
            return Err(e);
        }
    };
    if pending {
        let handles = [ev.as_raw_handle() as HANDLE, process.as_raw_handle() as HANDLE];
        // SAFETY: two valid handles; a bounded wait.
        let w = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, CONNECT_TIMEOUT.as_millis() as u32) };
        if w != WAIT_OBJECT_0 {
            cancel(&ov);
            return Err(Launch::Failed(if w == WAIT_OBJECT_0 + 1 { "the firewall helper ended before it connected".into() } else { "the firewall helper did not connect in time".into() }));
        }
    }
    // Only the process we launched, running this very exe, may be the client.
    // SAFETY: our process handle.
    let theirs = unsafe { GetProcessId(process.as_raw_handle() as HANDLE) };
    let own = crate::host::own_exe().unwrap_or_default();
    if !client_is(h, theirs, &own) {
        return Err(Launch::Failed("something other than the firewall helper connected to its pipe: it was closed".into()));
    }
    let s = Session { pipe, process };
    let reply = s.send(first).map_err(Launch::Failed)?;
    if !reply.ok {
        return Err(Launch::Failed(if reply.error.is_empty() { "the firewall helper could not change the rules".into() } else { reply.error.clone() }));
    }
    Ok((s, reply))
}

impl Session {
    /// One request and its answer (blocking, bounded).
    pub fn send(&self, req: &Request) -> Result<Reply, String> {
        let h = self.pipe.as_raw_handle() as HANDLE;
        let mut msg = line(req);
        ov_io(h, &mut msg, true, Duration::from_secs(5))?;
        read_reply(h, Duration::from_secs(30))
    }

    /// Whether the helper is still there (it may have been ended from outside).
    pub fn alive(&self) -> bool {
        let mut avail = 0u32;
        // SAFETY: our handles; the peek reads nothing.
        unsafe {
            WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 0) == WAIT_TIMEOUT
                && PeekNamedPipe(self.pipe.as_raw_handle() as HANDLE, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) != 0
        }
    }

    /// Tell the helper to remove the rules and leave; its answer (or why there is none).
    pub fn close(self) -> Result<Reply, String> {
        let r = self.send(&Request::close());
        // SAFETY: our process handle; a bounded wait for the helper to leave.
        unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 5000) };
        r
    }
}
