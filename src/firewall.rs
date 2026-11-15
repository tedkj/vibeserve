//! Windows Defender Firewall through its COM API (`INetFwPolicy2`, `INetFwRules`,
//! `INetFwRule`), with hand-written vtables (windows-sys has the constants, not the COM
//! interfaces; the slot numbers are netfw.h's). The same code as VibePerf's, copied (the family
//! shares nothing at run time), with an owner in each rule.
//!
//! Reading (is the firewall on for the current network, does it block all incoming, which rules
//! name this exe) needs no admin and runs in the app. Adding and removing rules needs admin and
//! runs only in the elevated helper (`helper.rs`). A rule is removed only after it was renamed to
//! a name nobody else has, so `Remove(name)` can never take another rule with the same name.
//!
//! Every rule VibeServe adds is named `VibeWare VibeServe <server> (<protocol> <port>)`, is in
//! the group `VibeWare VibeServe`, and says in its description which VibeServe added it (the
//! process id and its start time): a rule whose owner is gone was left by a crash, and another
//! instance's rules are never touched.

use std::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::{SysAllocString, SysFreeString};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::*;
use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::System::Variant::{VARIANT, VT_DISPATCH, VariantClear};
use windows_sys::core::{BSTR, GUID, HRESULT};

/// The group every rule VibeServe adds carries, and the start of their names.
pub const GROUP: &str = "VibeWare VibeServe";

const CLSID_NET_FW_POLICY2: GUID = GUID::from_u128(0xE2B3C97F_6AE1_41AC_817A_F6F92166D7DD);
const IID_INET_FW_POLICY2: GUID = GUID::from_u128(0x98325047_C671_4174_8D81_DEFCD3F03186);
const CLSID_NET_FW_RULE: GUID = GUID::from_u128(0x2C5BC43E_3369_4C33_AB0C_BE9469677AF4);
const IID_INET_FW_RULE: GUID = GUID::from_u128(0xAF230D27_BABA_4E42_ACED_F524F22CFCE2);
const IID_IENUM_VARIANT: GUID = GUID::from_u128(0x00020404_0000_0000_C000_000000000046);

/// E_ACCESSDENIED: what an unelevated Add or Remove gets.
pub const E_ACCESSDENIED: HRESULT = 0x8007_0005_u32 as i32;

// Vtable slots (0-based: IUnknown 0..2, IDispatch 3..6).
mod slot {
    pub const QUERY_INTERFACE: usize = 0;
    pub const RELEASE: usize = 2;
    // INetFwPolicy2
    pub const CURRENT_PROFILE_TYPES: usize = 7;
    pub const FIREWALL_ENABLED: usize = 8;
    pub const BLOCK_ALL_INBOUND: usize = 12;
    pub const RULES: usize = 18;
    // INetFwRules
    pub const ADD: usize = 8;
    pub const REMOVE: usize = 9;
    pub const NEW_ENUM: usize = 11;
    // INetFwRule
    pub const GET_NAME: usize = 7;
    pub const PUT_NAME: usize = 8;
    pub const GET_DESCRIPTION: usize = 9;
    pub const PUT_DESCRIPTION: usize = 10;
    pub const GET_APPLICATION: usize = 11;
    pub const PUT_APPLICATION: usize = 12;
    pub const GET_PROTOCOL: usize = 15;
    pub const PUT_PROTOCOL: usize = 16;
    pub const GET_LOCAL_PORTS: usize = 17;
    pub const PUT_LOCAL_PORTS: usize = 18;
    pub const GET_REMOTE_ADDRESSES: usize = 23;
    pub const PUT_REMOTE_ADDRESSES: usize = 24;
    pub const GET_DIRECTION: usize = 27;
    pub const PUT_DIRECTION: usize = 28;
    pub const GET_ENABLED: usize = 33;
    pub const PUT_ENABLED: usize = 34;
    pub const GET_GROUPING: usize = 35;
    pub const PUT_GROUPING: usize = 36;
    pub const GET_PROFILES: usize = 37;
    pub const PUT_PROFILES: usize = 38;
    pub const GET_ACTION: usize = 41;
    pub const PUT_ACTION: usize = 42;
    // IEnumVARIANT
    pub const ENUM_NEXT: usize = 3;
}

/// A COM interface pointer we own one reference to.
struct Obj(*mut c_void);

impl Obj {
    /// The function in vtable slot `n`.
    ///
    /// # Safety
    /// `n` is a slot this object's interface has, and the caller casts it to that slot's type.
    unsafe fn f(&self, n: usize) -> *const c_void {
        // SAFETY: a live COM object starts with its vtable pointer.
        unsafe { *(*(self.0 as *const *const *const c_void)).add(n) }
    }
}

impl Drop for Obj {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: IUnknown::Release in slot 2 of every COM interface.
            unsafe {
                let f: extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(self.f(slot::RELEASE));
                f(self.0);
            }
        }
    }
}

fn check(hr: HRESULT, what: &str) -> Result<(), String> {
    if hr >= 0 { Ok(()) } else { Err(format!("{what} failed (0x{:08X})", hr as u32)) }
}

/// A BSTR we free.
struct Bstr(BSTR);

impl Bstr {
    fn new(s: &str) -> Bstr {
        let w = crate::host::wide(s);
        // SAFETY: a NUL-terminated string; the copy is ours to free.
        Bstr(unsafe { SysAllocString(w.as_ptr()) })
    }

    fn text(&self) -> String {
        if self.0.is_null() {
            return String::new();
        }
        // SAFETY: a BSTR the API gave us, NUL-terminated.
        unsafe {
            let len = (0..).take_while(|&i| *self.0.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(self.0, len))
        }
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by SysAllocString or handed to us by the API.
            unsafe { SysFreeString(self.0) };
        }
    }
}

/// COM for this thread while it lives (multithreaded apartment; an STA already there is used).
pub struct Com(bool);

impl Com {
    pub fn init() -> Com {
        // SAFETY: no reserved argument; balanced in Drop when it succeeded.
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        Com(hr >= 0)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: this thread's successful CoInitializeEx.
            unsafe { CoUninitialize() };
        }
    }
}

fn create(clsid: &GUID, iid: &GUID) -> Result<Obj, String> {
    let mut p: *mut c_void = std::ptr::null_mut();
    // SAFETY: an out pointer for the interface asked for.
    let hr = unsafe { CoCreateInstance(clsid, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, iid, &mut p) };
    check(hr, "Windows Firewall's COM object")?;
    Ok(Obj(p))
}

fn policy() -> Result<Obj, String> {
    create(&CLSID_NET_FW_POLICY2, &IID_INET_FW_POLICY2)
}

fn rules_of(p: &Obj) -> Result<Obj, String> {
    let mut r: *mut c_void = std::ptr::null_mut();
    // SAFETY: INetFwPolicy2::get_Rules(INetFwRules**).
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT = std::mem::transmute(p.f(slot::RULES));
        f(p.0, &mut r)
    };
    check(hr, "Reading the firewall rules")?;
    Ok(Obj(r))
}

// ---------- reading ----------

/// The firewall as it stands for the networks this computer is on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// On for at least one active profile.
    pub enabled: bool,
    /// "Block all incoming connections" on an active profile where the firewall is on.
    pub block_all: bool,
    /// The active profiles' bits.
    pub active: i32,
    /// The active profiles, in words ("Private", "Public, Domain").
    pub profiles: String,
}

pub fn status() -> Result<Status, String> {
    let _com = Com::init();
    let p = policy()?;
    let mut types: i32 = 0;
    // SAFETY: get_CurrentProfileTypes(long*).
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *mut i32) -> HRESULT = std::mem::transmute(p.f(slot::CURRENT_PROFILE_TYPES));
        f(p.0, &mut types)
    };
    check(hr, "Reading the network profile")?;
    let mut s = Status { active: types, ..Status::default() };
    let mut names = Vec::new();
    for (bit, name) in [(NET_FW_PROFILE2_DOMAIN, "Domain"), (NET_FW_PROFILE2_PRIVATE, "Private"), (NET_FW_PROFILE2_PUBLIC, "Public")] {
        if types & bit == 0 {
            continue;
        }
        names.push(name);
        let (mut on, mut block): (i16, i16) = (0, 0);
        // SAFETY: get_FirewallEnabled and get_BlockAllInboundTraffic(profile, VARIANT_BOOL*).
        unsafe {
            let f: extern "system" fn(*mut c_void, i32, *mut i16) -> HRESULT = std::mem::transmute(p.f(slot::FIREWALL_ENABLED));
            check(f(p.0, bit, &mut on), "Reading whether the firewall is on")?;
            let f: extern "system" fn(*mut c_void, i32, *mut i16) -> HRESULT = std::mem::transmute(p.f(slot::BLOCK_ALL_INBOUND));
            check(f(p.0, bit, &mut block), "Reading the firewall's inbound setting")?;
        }
        if on != 0 {
            s.enabled = true;
            s.block_all |= block != 0;
        }
    }
    s.profiles = names.join(", ");
    Ok(s)
}

/// One rule, as read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub app: String,
    pub inbound: bool,
    pub allow: bool,
    pub enabled: bool,
    pub grouping: String,
    /// 6 TCP, 17 UDP, 256 any.
    pub protocol: i32,
    pub ports: String,
    pub remote: String,
    pub profiles: i32,
}

fn bstr_get(o: &Obj, n: usize) -> String {
    let mut b: BSTR = std::ptr::null_mut();
    // SAFETY: a get_X(BSTR*) slot; the BSTR is ours to free.
    unsafe {
        let f: extern "system" fn(*mut c_void, *mut BSTR) -> HRESULT = std::mem::transmute(o.f(n));
        if f(o.0, &mut b) < 0 {
            return String::new();
        }
    }
    Bstr(b).text()
}

fn i32_get(o: &Obj, n: usize) -> i32 {
    let mut v: i32 = 0;
    // SAFETY: a get_X(long*) (or enum*) slot.
    unsafe {
        let f: extern "system" fn(*mut c_void, *mut i32) -> HRESULT = std::mem::transmute(o.f(n));
        f(o.0, &mut v);
    }
    v
}

fn bool_get(o: &Obj, n: usize) -> bool {
    let mut v: i16 = 0;
    // SAFETY: a get_X(VARIANT_BOOL*) slot.
    unsafe {
        let f: extern "system" fn(*mut c_void, *mut i16) -> HRESULT = std::mem::transmute(o.f(n));
        f(o.0, &mut v);
    }
    v != 0
}

fn read_rule(o: &Obj) -> Rule {
    Rule {
        name: bstr_get(o, slot::GET_NAME),
        description: bstr_get(o, slot::GET_DESCRIPTION),
        app: bstr_get(o, slot::GET_APPLICATION),
        inbound: i32_get(o, slot::GET_DIRECTION) == NET_FW_RULE_DIR_IN,
        allow: i32_get(o, slot::GET_ACTION) == NET_FW_ACTION_ALLOW,
        enabled: bool_get(o, slot::GET_ENABLED),
        grouping: bstr_get(o, slot::GET_GROUPING),
        protocol: i32_get(o, slot::GET_PROTOCOL),
        ports: bstr_get(o, slot::GET_LOCAL_PORTS),
        remote: bstr_get(o, slot::GET_REMOTE_ADDRESSES),
        profiles: i32_get(o, slot::GET_PROFILES),
    }
}

/// Every rule, each with its live object (for a rename and removal).
fn each_rule(rules: &Obj) -> Result<Vec<(Rule, Obj)>, String> {
    let mut unk: *mut c_void = std::ptr::null_mut();
    // SAFETY: INetFwRules::get__NewEnum(IUnknown**).
    unsafe {
        let f: extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT = std::mem::transmute(rules.f(slot::NEW_ENUM));
        check(f(rules.0, &mut unk), "Listing the firewall rules")?;
    }
    let unk = Obj(unk);
    let mut en: *mut c_void = std::ptr::null_mut();
    // SAFETY: IUnknown::QueryInterface for IEnumVARIANT.
    unsafe {
        let f: extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT = std::mem::transmute(unk.f(slot::QUERY_INTERFACE));
        check(f(unk.0, &IID_IENUM_VARIANT, &mut en), "Listing the firewall rules")?;
    }
    let en = Obj(en);
    let mut out = Vec::new();
    // A firewall has hundreds of rules, not millions: a bound against a broken enumerator.
    for _ in 0..100_000 {
        // SAFETY: a zeroed VARIANT the call fills; cleared below.
        let mut v: VARIANT = unsafe { std::mem::zeroed() };
        let mut got: u32 = 0;
        let hr = unsafe {
            let f: extern "system" fn(*mut c_void, u32, *mut VARIANT, *mut u32) -> HRESULT = std::mem::transmute(en.f(slot::ENUM_NEXT));
            f(en.0, 1, &mut v, &mut got)
        };
        if hr != 0 || got == 0 {
            break; // S_FALSE: the end
        }
        // SAFETY: the variant's type says which member holds the value.
        unsafe {
            if v.Anonymous.Anonymous.vt == VT_DISPATCH {
                let d = v.Anonymous.Anonymous.Anonymous.pdispVal;
                if !d.is_null() {
                    let disp = Obj(d);
                    let mut r: *mut c_void = std::ptr::null_mut();
                    let f: extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT = std::mem::transmute(disp.f(slot::QUERY_INTERFACE));
                    if f(disp.0, &IID_INET_FW_RULE, &mut r) >= 0 && !r.is_null() {
                        let rule = Obj(r);
                        out.push((read_rule(&rule), rule));
                    }
                    // `disp` releases the variant's reference: the variant must not as well.
                    std::mem::forget(disp);
                }
            }
            VariantClear(&mut v);
        }
    }
    Ok(out)
}

/// Every rule (no admin needed).
pub fn rules() -> Result<Vec<Rule>, String> {
    let _com = Com::init();
    let p = policy()?;
    let r = rules_of(&p)?;
    Ok(each_rule(&r)?.into_iter().map(|(rule, _)| rule).collect())
}

// ---------- what the rules mean (pure) ----------

/// The same program, as rules write paths: any case, either slash, quotes, %VARIABLES%.
pub fn same_app(rule_app: &str, exe: &Path) -> bool {
    let norm = |s: &str| s.trim().trim_matches('"').replace('/', "\\").to_lowercase();
    let a = norm(&expand(rule_app));
    !a.is_empty() && a == norm(&exe.to_string_lossy())
}

fn expand(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let w = crate::host::wide(s);
    let mut out = vec![0u16; 4096];
    // SAFETY: a NUL-terminated input and an output buffer of the size given.
    let n = unsafe { windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW(w.as_ptr(), out.as_mut_ptr(), out.len() as u32) } as usize;
    if n == 0 || n > out.len() { s.to_string() } else { String::from_utf16_lossy(&out[..n - 1]) }
}

/// Rules VibeServe added (its group and name).
pub fn is_ours(r: &Rule) -> bool {
    r.grouping == GROUP && r.name.starts_with(GROUP)
}

/// A VibeServe process: its id and its start time (a FILETIME): never the id alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Owner {
    pub pid: u32,
    pub started: u64,
}

impl Owner {
    /// The text a rule's description ends in: "[owner 1234.133456789012345678 S-1-5-21-…]", the
    /// user's SID last (another signed-in user's rules are never this user's leftovers).
    pub fn tag(&self) -> String {
        self.tag_for(user_sid())
    }

    /// The tag naming `sid` as the user (the helper names the user who runs VibeServe, its
    /// parent, not the account that answered the UAC prompt); "" names none.
    pub fn tag_for(&self, sid: &str) -> String {
        match sid {
            "" => format!("[owner {}.{}]", self.pid, self.started),
            sid => format!("[owner {}.{} {sid}]", self.pid, self.started),
        }
    }
}

/// "S-1-" and digits and dashes, at most 184 characters: the shape a SID string has.
pub fn sid_shaped(u: &str) -> bool {
    u.len() <= 184 && u.strip_prefix("S-1-").is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

/// The owner a rule of ours names and the user it names, if any (None: no owner, or not in our
/// form).
fn owner_tag(r: &Rule) -> Option<(Owner, Option<&str>)> {
    let t = r.description.rsplit_once("[owner ")?.1.strip_suffix(']')?;
    let (t, user) = match t.split_once(' ') {
        Some((t, u)) => {
            if !sid_shaped(u) {
                return None;
            }
            (t, Some(u))
        }
        None => (t, None),
    };
    let (pid, started) = t.split_once('.')?;
    let all_digits = |s: &str| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(pid) || !all_digits(started) {
        return None;
    }
    Some((Owner { pid: pid.parse().ok()?, started: started.parse().ok()? }, user))
}

/// The owner a rule of ours names (None: none, or not in our form).
pub fn owner_of(r: &Rule) -> Option<Owner> {
    owner_tag(r).map(|(o, _)| o)
}

/// A rule of ours whose owner is not running any more (left by a crash), or that names no owner
/// we can read: ours to remove. A rule that names another user is never this user's to remove
/// (their VibeServe may run in another session, where its process cannot be opened from here).
/// `alive` asks whether a process still runs.
pub fn stale(r: &Rule, alive: &dyn Fn(Owner) -> bool) -> bool {
    stale_for(r, user_sid(), alive)
}

/// `stale` for the user `me` (the helper asks for its parent's user).
pub fn stale_for(r: &Rule, me: &str, alive: &dyn Fn(Owner) -> bool) -> bool {
    if !is_ours(r) {
        return false;
    }
    match owner_tag(r) {
        None => true,
        Some((_, Some(u))) if !u.eq_ignore_ascii_case(me) => false,
        Some((o, _)) => !alive(o),
    }
}

/// This process's user as a SID string ("S-1-5-21-…"), read once; "" when it cannot be read.
pub fn user_sid() -> &'static str {
    static SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SID.get_or_init(|| process_user(this_process()).unwrap_or_default())
}

/// This process's pseudo handle (never closed, always valid).
fn this_process() -> std::os::windows::io::BorrowedHandle<'static> {
    // SAFETY: GetCurrentProcess's pseudo handle (-1) is valid for the whole process, and
    // BorrowedHandle may hold it.
    unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(windows_sys::Win32::System::Threading::GetCurrentProcess() as std::os::windows::io::RawHandle) }
}

/// The user a process runs as, from its token, as a SID string (None when its token cannot be
/// read). `process` needs PROCESS_QUERY_LIMITED_INFORMATION; an elevated admin may read another
/// user's token (Windows grants Administrators TOKEN_QUERY on it).
pub fn process_user(process: std::os::windows::io::BorrowedHandle<'_>) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: a process handle the borrow keeps open; the token, query only, is closed below.
    if unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut tok) } == 0 {
        return None;
    }
    let mut need = 0u32;
    // SAFETY: a size query, then a buffer of that size (8-aligned).
    unsafe { GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut need) };
    let mut tu = vec![0u64; (need as usize).div_ceil(8).max(8)];
    let ok = unsafe { GetTokenInformation(tok, TokenUser, tu.as_mut_ptr().cast(), (tu.len() * 8) as u32, &mut need) } != 0;
    unsafe { CloseHandle(tok) };
    if !ok {
        return None;
    }
    // SAFETY: the buffer holds a TOKEN_USER written by the call above; its SID lives in `tu`.
    unsafe {
        let sid = (*(tu.as_ptr() as *const TOKEN_USER)).User.Sid;
        if IsValidSid(sid) == 0 {
            return None;
        }
        let auth = (*GetSidIdentifierAuthority(sid)).Value.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
        let mut s = format!("S-1-{auth}");
        for i in 0..*GetSidSubAuthorityCount(sid) {
            s.push_str(&format!("-{}", *GetSidSubAuthority(sid, i as u32)));
        }
        Some(s)
    }
}

/// A rule this VibeServe (`me`) added.
pub fn mine(r: &Rule, me: Owner) -> bool {
    is_ours(r) && owner_of(r) == Some(me)
}

/// Inbound block rules for this exe (Windows makes them when its "allow access?" prompt is
/// dismissed; a block rule beats every allow rule).
pub fn blocks_this_exe(r: &Rule, exe: &Path) -> bool {
    r.inbound && !r.allow && r.enabled && same_app(&r.app, exe)
}

fn port_in(ports: &str, port: u16) -> bool {
    let p = ports.trim();
    if p.is_empty() || p == "*" || p.eq_ignore_ascii_case("any") {
        return true;
    }
    p.split(',').any(|part| match part.trim().split_once('-') {
        Some((a, b)) => matches!((a.trim().parse::<u16>(), b.trim().parse::<u16>()), (Ok(a), Ok(b)) if a <= port && port <= b),
        None => part.trim().parse::<u16>() == Ok(port),
    })
}

/// An enabled inbound allow rule of someone else's already lets this exe take `protocol` on
/// `port` (from any address on the local subnet at least) for every active profile: no rule
/// needed, no prompt.
pub fn allowed_already(rules: &[Rule], exe: &Path, port: u16, protocol: i32, active_profiles: i32) -> bool {
    let remote_ok = |r: &str| {
        let r = r.trim();
        r.is_empty() || r == "*" || r.eq_ignore_ascii_case("any") || r.eq_ignore_ascii_case("LocalSubnet")
    };
    rules.iter().any(|r| {
        r.inbound && r.allow && r.enabled && !is_ours(r) && same_app(&r.app, exe) && (r.protocol == protocol || r.protocol == 256) && port_in(&r.ports, port) && remote_ok(&r.remote) && (r.profiles & active_profiles) == active_profiles
    })
}

// ---------- changing (admin) ----------

/// Which server a rule is for (the helper takes only these words from the pipe).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Tftp,
    Syslog,
    Http,
}

impl Purpose {
    pub fn words(self) -> &'static str {
        match self {
            Purpose::Tftp => "TFTP",
            Purpose::Syslog => "syslog",
            Purpose::Http => "HTTP",
        }
    }
}

/// The Private network profile: the only one VibeServe's rules apply on (SEC-Serve-1).
pub const PRIVATE: i32 = NET_FW_PROFILE2_PRIVATE;

/// A rule to add: inbound, allow, this exe only, one protocol and port, the local subnet only,
/// Private networks only, in VibeServe's group, with its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewRule {
    pub name: String,
    pub description: String,
    pub app: String,
    pub protocol: i32,
    pub port: u16,
    /// The remote addresses it lets in.
    pub remote: String,
    /// The network profiles it applies on (NET_FW_PROFILE2_* bits).
    pub profiles: i32,
}

impl NewRule {
    /// `user`: the SID of the user who runs the VibeServe that wants it ("" names none).
    pub fn server(app: &Path, purpose: Purpose, tcp: bool, port: u16, owner: Owner, user: &str) -> NewRule {
        let p = if tcp { "TCP" } else { "UDP" };
        NewRule {
            name: format!("{GROUP} {} ({p} {port})", purpose.words()),
            description: format!("Added by VibeServe while its {} server runs; removed when it stops. {}", purpose.words(), owner.tag_for(user)),
            app: app.to_string_lossy().into_owned(),
            protocol: if tcp { NET_FW_IP_PROTOCOL_TCP } else { NET_FW_IP_PROTOCOL_UDP },
            port,
            remote: "LocalSubnet".into(),
            // SEC-Serve-1 (Ted, 2026-10-28): Private networks only, never Public.
            profiles: PRIVATE,
        }
    }

    /// The same rule as one already there (name, protocol, port, program, where it applies).
    pub fn matches(&self, r: &Rule) -> bool {
        r.name == self.name && r.protocol == self.protocol && r.ports == self.port.to_string() && r.app.eq_ignore_ascii_case(&self.app) && r.profiles == self.profiles && r.remote.eq_ignore_ascii_case(&self.remote)
    }
}

/// What the helper does to the firewall (the tests hand it a fake).
pub trait Firewall {
    fn rules(&self) -> Result<Vec<Rule>, String>;
    fn add(&self, r: &NewRule) -> Result<(), String>;
    /// Remove every rule `pick` chooses; returns how many.
    fn remove(&self, pick: &dyn Fn(&Rule) -> bool) -> Result<usize, String>;
}

pub struct System;

fn put_bstr(o: &Obj, n: usize, s: &str) -> Result<(), String> {
    let b = Bstr::new(s);
    // SAFETY: a put_X(BSTR) slot; the string is copied by the callee.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, BSTR) -> HRESULT = std::mem::transmute(o.f(n));
        f(o.0, b.0)
    };
    check(hr, "Setting a rule's property")
}

fn put_i32(o: &Obj, n: usize, v: i32) -> Result<(), String> {
    // SAFETY: a put_X(long) (or enum) slot.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, i32) -> HRESULT = std::mem::transmute(o.f(n));
        f(o.0, v)
    };
    check(hr, "Setting a rule's property")
}

fn put_bool(o: &Obj, n: usize, v: bool) -> Result<(), String> {
    // SAFETY: a put_X(VARIANT_BOOL) slot.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, i16) -> HRESULT = std::mem::transmute(o.f(n));
        f(o.0, if v { -1 } else { 0 })
    };
    check(hr, "Setting a rule's property")
}

/// A rule object with every property of `r` set (not added anywhere yet).
fn rule_object(r: &NewRule) -> Result<Obj, String> {
    let o = create(&CLSID_NET_FW_RULE, &IID_INET_FW_RULE)?;
    put_bstr(&o, slot::PUT_NAME, &r.name)?;
    put_bstr(&o, slot::PUT_DESCRIPTION, &r.description)?;
    put_bstr(&o, slot::PUT_APPLICATION, &r.app)?;
    put_i32(&o, slot::PUT_PROTOCOL, r.protocol)?;
    put_bstr(&o, slot::PUT_LOCAL_PORTS, &r.port.to_string())?;
    put_bstr(&o, slot::PUT_REMOTE_ADDRESSES, &r.remote)?;
    put_i32(&o, slot::PUT_DIRECTION, NET_FW_RULE_DIR_IN)?;
    put_i32(&o, slot::PUT_ACTION, NET_FW_ACTION_ALLOW)?;
    put_i32(&o, slot::PUT_PROFILES, r.profiles)?;
    put_bstr(&o, slot::PUT_GROUPING, GROUP)?;
    put_bool(&o, slot::PUT_ENABLED, true)?;
    Ok(o)
}

/// Add a rule object to the policy's rules: Ok, or the HRESULT (E_ACCESSDENIED unelevated).
fn add_object(o: &Obj) -> Result<(), HRESULT> {
    let p = policy().map_err(|_| -1)?;
    let rules = rules_of(&p).map_err(|_| -1)?;
    // SAFETY: INetFwRules::Add(INetFwRule*): the collection takes its own reference.
    let hr = unsafe {
        let f: extern "system" fn(*mut c_void, *mut c_void) -> HRESULT = std::mem::transmute(rules.f(slot::ADD));
        f(rules.0, o.0)
    };
    if hr >= 0 { Ok(()) } else { Err(hr) }
}

impl Firewall for System {
    fn rules(&self) -> Result<Vec<Rule>, String> {
        rules()
    }

    fn add(&self, r: &NewRule) -> Result<(), String> {
        let _com = Com::init();
        let o = rule_object(r)?;
        add_object(&o).map_err(|hr| format!("Adding the firewall rule failed (0x{:08X})", hr as u32))
    }

    fn remove(&self, pick: &dyn Fn(&Rule) -> bool) -> Result<usize, String> {
        let _com = Com::init();
        let p = policy()?;
        let rules = rules_of(&p)?;
        let chosen: Vec<Obj> = each_rule(&rules)?.into_iter().filter(|(r, _)| pick(r)).map(|(_, o)| o).collect();
        let mut n = 0;
        for o in chosen {
            // A name nobody else has: Remove(name) then takes this rule and no other.
            let mut tag = [0u8; 8];
            crate::host::random_bytes(&mut tag);
            let unique = format!("{GROUP} removing {}", tag.iter().map(|b| format!("{b:02x}")).collect::<String>());
            put_bstr(&o, slot::PUT_NAME, &unique)?;
            let b = Bstr::new(&unique);
            // SAFETY: INetFwRules::Remove(BSTR).
            let hr = unsafe {
                let f: extern "system" fn(*mut c_void, BSTR) -> HRESULT = std::mem::transmute(rules.f(slot::REMOVE));
                f(rules.0, b.0)
            };
            check(hr, "Removing a firewall rule")?;
            n += 1;
        }
        Ok(n)
    }
}

/// Whether this process runs elevated.
pub fn elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: this process's token, closed below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(t, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) != 0;
        CloseHandle(t);
        ok && e.TokenIsElevated != 0
    }
}

/// A process's start time (FILETIME), None when it cannot be opened (gone, or not ours to ask).
pub fn started(pid: u32) -> Option<u64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject};
    // SAFETY: a query-only open; closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
    if h.is_null() {
        return None;
    }
    let z = || FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut c, mut e, mut k, mut u) = (z(), z(), z(), z());
    // SAFETY: our handle; out structs. A process that has exited (but whose handle lives) is gone.
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } != 0;
    let running = unsafe { WaitForSingleObject(h, 0) } == WAIT_TIMEOUT;
    unsafe { CloseHandle(h) };
    (ok && running).then_some(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
}

/// This process as an owner.
pub fn me() -> Owner {
    Owner { pid: std::process::id(), started: started(std::process::id()).unwrap_or(0) }
}

/// Whether the process an owner names still runs (the same id and the same start time).
pub fn alive(o: Owner) -> bool {
    started(o.pid) == Some(o.started)
}
