//! Sockets the way the servers need them, which std cannot make: `SO_EXCLUSIVEADDRUSE` before the
//! bind, a dual-stack `[::]` socket with `IPV6_V6ONLY` off for "All addresses", and on the TFTP
//! socket `IP_PKTINFO` / `IPV6_PKTINFO` with `WSARecvMsg`, so each transfer answers from the
//! address its request arrived at. Waits go through `WSAEventSelect` with a stop event beside
//! them: an idle server costs no wake-ups and stops at once.
//!
//! Also: who owns a port (`GetExtendedTcpTable` / `GetExtendedUdpTable` plus the process's
//! image name), and the addresses of the adapters that are up (the bind picker, the cards).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, UdpSocket};
use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects};

/// WinSock for this process (std starts it lazily; the raw calls here may come first).
pub fn winsock() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: an out struct; never cleaned up (the process ends with it).
        let mut d: WSADATA = unsafe { std::mem::zeroed() };
        unsafe { WSAStartup(0x0202, &mut d) };
    });
}

/// Where a server listens.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Bind {
    /// Every address: one dual-stack `[::]` socket.
    All,
    /// One address (with its scope, for an IPv6 link-local one).
    One(IpAddr, u32),
}

impl Bind {
    /// The key prefs keep: "all", "192.168.1.20", "fe80::1%12".
    pub fn key(&self) -> String {
        match self {
            Bind::All => "all".into(),
            Bind::One(IpAddr::V6(a), s) if *s != 0 => format!("{a}%{s}"),
            Bind::One(a, _) => a.to_string(),
        }
    }

    pub fn from_key(k: &str) -> Option<Bind> {
        if k == "all" {
            return Some(Bind::All);
        }
        if let Some((a, s)) = k.split_once('%') {
            return Some(Bind::One(IpAddr::V6(a.parse().ok()?), s.parse().ok()?));
        }
        Some(Bind::One(k.parse().ok()?, 0))
    }

    pub fn loopback(&self) -> bool {
        matches!(self, Bind::One(a, _) if a.is_loopback())
    }
}

// ---------- socket addresses as bytes ----------

const AF_INET_: u16 = 2;
const AF_INET6_: u16 = 23;

/// A socket address as WinSock takes it (sockaddr_in or sockaddr_in6) and its length.
pub fn sockaddr(a: &SocketAddr) -> ([u8; 28], i32) {
    let mut b = [0u8; 28];
    match a {
        SocketAddr::V4(v) => {
            b[0..2].copy_from_slice(&AF_INET_.to_le_bytes());
            b[2..4].copy_from_slice(&v.port().to_be_bytes());
            b[4..8].copy_from_slice(&v.ip().octets());
            (b, 16)
        }
        SocketAddr::V6(v) => {
            b[0..2].copy_from_slice(&AF_INET6_.to_le_bytes());
            b[2..4].copy_from_slice(&v.port().to_be_bytes());
            b[4..8].copy_from_slice(&v.flowinfo().to_le_bytes());
            b[8..24].copy_from_slice(&v.ip().octets());
            b[24..28].copy_from_slice(&v.scope_id().to_le_bytes());
            (b, 28)
        }
    }
}

/// A sockaddr from WinSock's bytes; an IPv4-mapped IPv6 address comes back as plain IPv4.
pub fn parse_sockaddr(b: &[u8]) -> Option<SocketAddr> {
    if b.len() < 2 {
        return None;
    }
    match u16::from_le_bytes([b[0], b[1]]) {
        AF_INET_ if b.len() >= 8 => Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(b[4], b[5], b[6], b[7]), u16::from_be_bytes([b[2], b[3]])))),
        AF_INET6_ if b.len() >= 28 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[8..24]);
            let ip = Ipv6Addr::from(o);
            let port = u16::from_be_bytes([b[2], b[3]]);
            if let Some(v4) = ip.to_ipv4_mapped() {
                return Some(SocketAddr::V4(SocketAddrV4::new(v4, port)));
            }
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, u32::from_le_bytes([b[4], b[5], b[6], b[7]]), u32::from_le_bytes([b[24], b[25], b[26], b[27]]))))
        }
        _ => None,
    }
}

/// An address without IPv4-mapped IPv6 forms (a dual-stack socket reports IPv4 peers that way).
pub fn unmap(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v) => match v.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v.port())),
            None => a,
        },
        _ => a,
    }
}

// ---------- making sockets ----------

/// Why a server could not listen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindError {
    /// Another socket has the port (WSAEADDRINUSE, or WSAEACCES from an exclusive owner).
    InUse,
    /// WSAEACCES with nobody holding the port: an excluded port range (Hyper-V, WinNAT).
    Reserved,
    /// The address is not on this computer (WSAEADDRNOTAVAIL).
    NoAddress,
    Other(String),
}

fn last_wsa() -> i32 {
    // SAFETY: no arguments.
    unsafe { WSAGetLastError() }
}

/// A socket we own until it is handed to std.
struct Raw(SOCKET);

impl Drop for Raw {
    fn drop(&mut self) {
        if self.0 != INVALID_SOCKET {
            // SAFETY: our socket, closed once.
            unsafe { closesocket(self.0) };
        }
    }
}

impl Raw {
    fn take(mut self) -> SOCKET {
        std::mem::replace(&mut self.0, INVALID_SOCKET)
    }
}

fn set_int(s: SOCKET, level: i32, opt: i32, v: i32) -> bool {
    // SAFETY: a 4-byte option value.
    unsafe { setsockopt(s, level, opt, (&v as *const i32).cast(), 4) == 0 }
}

fn new_socket(v6: bool, udp: bool) -> Result<Raw, BindError> {
    winsock();
    let (ty, proto) = if udp { (SOCK_DGRAM, IPPROTO_UDP) } else { (SOCK_STREAM, IPPROTO_TCP) };
    // SAFETY: plain arguments; the socket is owned by `Raw`.
    let s = unsafe { WSASocketW(if v6 { AF_INET6 as i32 } else { AF_INET as i32 }, ty, proto, std::ptr::null(), 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT) };
    if s == INVALID_SOCKET {
        return Err(BindError::Other(format!("no socket ({})", std::io::Error::from_raw_os_error(last_wsa()))));
    }
    if udp {
        // An ICMP "port unreachable" for an earlier datagram would otherwise fail the next
        // receive with WSAECONNRESET (a Windows quirk): off.
        let off: u32 = 0;
        let mut n = 0u32;
        // SAFETY: a 4-byte input; no output.
        unsafe { WSAIoctl(s, SIO_UDP_CONNRESET, (&off as *const u32).cast(), 4, std::ptr::null_mut(), 0, &mut n, std::ptr::null_mut(), None) };
    }
    Ok(Raw(s))
}

fn bind_raw(s: &Raw, addr: &SocketAddr) -> Result<(), BindError> {
    let (b, len) = sockaddr(addr);
    // SAFETY: a sockaddr of `len` bytes.
    if unsafe { bind(s.0, b.as_ptr().cast(), len) } != 0 {
        return Err(match last_wsa() {
            WSAEADDRINUSE => BindError::InUse,
            WSAEACCES => BindError::Reserved, // the caller tells "in use" from the tables
            WSAEADDRNOTAVAIL => BindError::NoAddress,
            e => BindError::Other(std::io::Error::from_raw_os_error(e).to_string()),
        });
    }
    Ok(())
}

fn listen_addr(bind: &Bind, port: u16) -> (SocketAddr, bool) {
    match bind {
        Bind::All => (SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)), true),
        Bind::One(IpAddr::V4(a), _) => (SocketAddr::V4(SocketAddrV4::new(*a, port)), false),
        Bind::One(IpAddr::V6(a), s) => (SocketAddr::V6(SocketAddrV6::new(*a, port, 0, *s)), false),
    }
}

/// A server's socket on `bind`:`port`: exclusive, dual-stack for All, IPv4 and IPv6 packet
/// info when `pktinfo` (TFTP).
fn server_socket(bind: &Bind, port: u16, udp: bool, pktinfo: bool) -> Result<Raw, BindError> {
    let (addr, dual) = listen_addr(bind, port);
    let s = new_socket(addr.is_ipv6(), udp)?;
    if !set_int(s.0, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1) {
        return Err(BindError::Other("the socket refused exclusive use".into()));
    }
    if dual && !set_int(s.0, IPPROTO_IPV6, IPV6_V6ONLY, 0) {
        return Err(BindError::Other("the socket refused dual-stack".into()));
    }
    if pktinfo {
        // On a dual-stack socket the IPv4 option covers the IPv4 packets.
        if addr.is_ipv6() {
            set_int(s.0, IPPROTO_IPV6, IPV6_PKTINFO, 1);
        }
        if addr.is_ipv4() || dual {
            set_int(s.0, IPPROTO_IP, IP_PKTINFO, 1);
        }
    }
    bind_raw(&s, &addr)?;
    Ok(s)
}

/// A UDP server socket.
pub fn udp(bind: &Bind, port: u16, pktinfo: bool) -> Result<UdpSocket, BindError> {
    let s = server_socket(bind, port, true, pktinfo)?;
    // SAFETY: a valid socket we own; std takes it over.
    Ok(unsafe { UdpSocket::from_raw_socket(s.take() as RawSocket) })
}

/// A TCP server socket, listening.
pub fn tcp(bind: &Bind, port: u16) -> Result<TcpListener, BindError> {
    let s = server_socket(bind, port, false, false)?;
    // SAFETY: a bound socket.
    if unsafe { listen(s.0, 128) } != 0 {
        return Err(match last_wsa() {
            WSAEADDRINUSE => BindError::InUse,
            e => BindError::Other(std::io::Error::from_raw_os_error(e).to_string()),
        });
    }
    // SAFETY: as above.
    Ok(unsafe { TcpListener::from_raw_socket(s.take() as RawSocket) })
}

/// A transfer's own UDP socket (its TID): `local` with an ephemeral port.
pub fn udp_from(local: IpAddr, scope: u32) -> std::io::Result<UdpSocket> {
    let addr = match local {
        IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, 0)),
        IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, 0, 0, scope)),
    };
    let s = new_socket(addr.is_ipv6(), true).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    bind_raw(&s, &addr).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    // SAFETY: a bound socket we own.
    Ok(unsafe { UdpSocket::from_raw_socket(s.take() as RawSocket) })
}

/// A socket's receive buffer (SO_RCVBUF), best effort.
pub fn set_recv_buffer(sock: &impl AsRawSocket, bytes: i32) {
    set_int(sock.as_raw_socket() as SOCKET, SOL_SOCKET, SO_RCVBUF, bytes);
}

// ---------- waiting ----------

/// A manual-reset event that stops a server: every wait of its threads watches it. Without the
/// event (CreateEventW failed: a handle quota, no memory) the flag alone stops it, and the waits
/// look at the flag every `POLL` (fable-audit FA15): a failed wait on a null handle would make
/// every loop paced by `sleep` spin, and every listener read its wait as the stop.
pub struct Stop {
    /// Null when it could not be made.
    ev: HANDLE,
    flag: AtomicBool,
}

/// How often a wait on a `Stop` without its event looks at the flag.
const POLL: Duration = Duration::from_millis(20);

// SAFETY: an event handle may be used from any thread.
unsafe impl Send for Stop {}
unsafe impl Sync for Stop {}

impl Stop {
    pub fn new() -> Arc<Stop> {
        // SAFETY: an unnamed manual-reset event, closed in Drop; null when it can't be made.
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        Arc::new(Stop { ev, flag: AtomicBool::new(false) })
    }

    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
        if !self.ev.is_null() {
            // SAFETY: our event.
            unsafe { SetEvent(self.ev) };
        }
    }

    pub fn stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Sleep up to `d`, or less when stopped.
    pub fn sleep(&self, d: Duration) {
        if self.ev.is_null() {
            let until = Instant::now() + d;
            while !self.stopped() {
                let now = Instant::now();
                if now >= until {
                    break;
                }
                std::thread::sleep(POLL.min(until - now));
            }
            return;
        }
        // SAFETY: our event; a bounded wait.
        unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(self.ev, d.as_millis().min(u32::MAX as u128 - 1) as u32) };
    }
}

impl Drop for Stop {
    fn drop(&mut self) {
        if !self.ev.is_null() {
            // SAFETY: created in `new`, closed once.
            unsafe { CloseHandle(self.ev) };
        }
    }
}

/// Stopping a server waits at most this long for its threads (DECISIONS: "a few seconds").
pub const HALT_WAIT: Duration = Duration::from_secs(5);

/// The threads a server's loop hands over when it ends (transfers, connections), for `halt`.
pub type Handed = Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>;

/// Wait for a thread to end, at most until `until`: whether it did.
pub fn wait_for(t: &std::thread::JoinHandle<()>, until: Instant) -> bool {
    while !t.is_finished() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// Stop a server: its loop threads end, then the threads they handed over, all within `within`.
/// Returns the ones still running then: each is in a call that ignores the stop (a file open a
/// filter driver holds), is left to end on its own when that call returns, and does nothing
/// more then (it checks the stop).
///
/// Once only (RL9-3): a later halt (a server's drop after its stop) takes nothing from the
/// hand-over list. What the first one left, and what a left loop hands over later, are that
/// stop's `Left` to watch.
pub fn halt(stop: &Stop, loops: Vec<std::thread::JoinHandle<()>>, handed: &Handed, within: Duration) -> Left {
    if stop.flag.swap(true, Ordering::SeqCst) {
        return Left { threads: loops, handed: Default::default() };
    }
    stop.stop();
    let until = Instant::now() + within;
    let mut left = Vec::new();
    for t in loops {
        if wait_for(&t, until) {
            let _ = t.join();
        } else {
            left.push(t);
        }
    }
    let rest: Vec<_> = handed.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
    for t in rest {
        if wait_for(&t, until) {
            let _ = t.join();
        } else {
            left.push(t);
        }
    }
    Left { threads: left, handed: handed.clone() }
}

/// The threads a stop left running (RL8-1). The sockets they hold (a listener, a transfer's or
/// a connection's) close only when they end, so a server is closed only once they have.
pub struct Left {
    threads: Vec<std::thread::JoinHandle<()>>,
    /// Where a left loop hands its threads over when it ends.
    handed: Handed,
}

impl Left {
    pub fn count(&self) -> usize {
        self.threads.len()
    }

    /// Every left thread has ended, and every thread a left loop handed over since: the sockets
    /// they held are closed.
    pub fn ended(&self) -> bool {
        // The loops first: one hands its threads over before it ends.
        self.threads.iter().all(|t| t.is_finished()) && self.handed.lock().unwrap_or_else(|e| e.into_inner()).iter().all(|t| t.is_finished())
    }
}

/// How a wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    Ready,
    Timeout,
    Stopped,
}

/// A socket's readiness event (WSAEventSelect: the socket turns non-blocking). It must drop
/// before its socket closes: its drop deselects by handle, and a closed socket's handle may
/// already be another socket's.
pub struct Ready {
    ev: HANDLE,
    sock: SOCKET,
}

// SAFETY: as Stop.
unsafe impl Send for Ready {}

impl Ready {
    /// Watch `sock` for `events` (FD_READ, FD_ACCEPT).
    pub fn new(sock: &impl AsRawSocket, events: u32) -> std::io::Result<Ready> {
        // SAFETY: an unnamed manual-reset event, closed in Drop.
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if ev.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let s = sock.as_raw_socket() as SOCKET;
        // SAFETY: our socket and event.
        if unsafe { WSAEventSelect(s, ev as WSAEVENT, events as i32) } != 0 {
            let e = std::io::Error::from_raw_os_error(last_wsa());
            unsafe { CloseHandle(ev) };
            return Err(e);
        }
        Ok(Ready { ev, sock: s })
    }

    /// Wait until the socket may have something, the stop, or `timeout`. Call it only after a
    /// read said "would block": the event is reset here, and the next read re-arms it.
    pub fn wait(&self, stop: &Stop, timeout: Option<Duration>) -> Woke {
        if stop.stopped() {
            return Woke::Stopped;
        }
        if stop.ev.is_null() {
            return self.wait_polling(stop, timeout);
        }
        let handles = [self.ev, stop.ev];
        let ms = timeout.map_or(u32::MAX, |d| d.as_millis().min(u32::MAX as u128 - 2) as u32);
        // SAFETY: two live handles; bounded or infinite (the stop event ends it).
        let w = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, ms) };
        if w == WAIT_OBJECT_0 {
            self.woke()
        } else if w == WAIT_OBJECT_0 + 1 {
            Woke::Stopped
        } else if w == WAIT_TIMEOUT {
            Woke::Timeout
        } else {
            // A failed wait: never spin; act as if stopped.
            unsafe { ResetEvent(self.ev) };
            Woke::Stopped
        }
    }

    /// The socket's event is set: reset by the enumeration, and the next "would block" read
    /// re-arms it.
    fn woke(&self) -> Woke {
        let mut ne: WSANETWORKEVENTS = unsafe { std::mem::zeroed() };
        // SAFETY: our socket and event.
        unsafe { WSAEnumNetworkEvents(self.sock, self.ev as WSAEVENT, &mut ne) };
        Woke::Ready
    }

    /// `wait` for a stop without its event (FA15): the socket's event in slices of `POLL`, the
    /// stop's flag between them.
    fn wait_polling(&self, stop: &Stop, timeout: Option<Duration>) -> Woke {
        let until = timeout.map(|d| Instant::now() + d);
        loop {
            if stop.stopped() {
                return Woke::Stopped;
            }
            let slice = match until {
                Some(u) => match u.checked_duration_since(Instant::now()) {
                    Some(left) if !left.is_zero() => POLL.min(left),
                    _ => return Woke::Timeout,
                },
                None => POLL,
            };
            // SAFETY: our event; a bounded wait.
            let w = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(self.ev, slice.as_millis().max(1) as u32) };
            if w == WAIT_OBJECT_0 {
                return self.woke();
            }
            if w != WAIT_TIMEOUT {
                // A failed wait: never spin; act as if stopped.
                unsafe { ResetEvent(self.ev) };
                return Woke::Stopped;
            }
        }
    }
}

impl Drop for Ready {
    fn drop(&mut self) {
        // SAFETY: deselect, then close our event.
        unsafe {
            let _failed = WSAEventSelect(self.sock, 0, 0) != 0;
            CloseHandle(self.ev);
        }
    }
}

/// A socket accepted from a listener under WSAEventSelect inherits its selection: undo it, so
/// the connection is an ordinary blocking socket with timeouts.
pub fn plain(s: &std::net::TcpStream) -> std::io::Result<()> {
    // SAFETY: our socket; no event.
    unsafe { WSAEventSelect(s.as_raw_socket() as SOCKET, 0, 0) };
    s.set_nonblocking(false)
}

/// A datagram's length, its sender, and the local address (and interface) it was sent to.
pub type Received = (usize, SocketAddr, Option<(IpAddr, u32)>);

/// Receive one datagram with the local address it was sent to (IP_PKTINFO / IPV6_PKTINFO) when
/// the socket has packet info on. The socket is non-blocking (a `Ready` watches it).
pub fn recv_msg(sock: &UdpSocket, buf: &mut [u8]) -> std::io::Result<Received> {
    static RECVMSG: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let s = sock.as_raw_socket() as SOCKET;
    let f = *RECVMSG.get_or_init(|| {
        let mut f: usize = 0;
        let mut n = 0u32;
        // SAFETY: asks for the WSARecvMsg extension pointer.
        unsafe {
            WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (&WSAID_WSARECVMSG as *const windows_sys::core::GUID).cast(), std::mem::size_of::<windows_sys::core::GUID>() as u32, (&mut f as *mut usize).cast(), std::mem::size_of::<usize>() as u32, &mut n, std::ptr::null_mut(), None);
        }
        f
    });
    if f == 0 {
        let (n, peer) = sock.recv_from(buf)?;
        return Ok((n, unmap(peer), None));
    }
    // SAFETY: the pointer WSAIoctl handed out has WSARecvMsg's signature.
    let recvmsg: unsafe extern "system" fn(SOCKET, *mut WSAMSG, *mut u32, *mut windows_sys::Win32::System::IO::OVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) -> i32 = unsafe { std::mem::transmute(f) };
    let mut name = [0u8; 28];
    let mut control = [0u64; 16];
    let mut data = WSABUF { len: buf.len().min(u32::MAX as usize) as u32, buf: buf.as_mut_ptr() };
    let mut msg = WSAMSG {
        name: name.as_mut_ptr().cast(),
        namelen: name.len() as i32,
        lpBuffers: &mut data,
        dwBufferCount: 1,
        Control: WSABUF { len: (control.len() * 8) as u32, buf: control.as_mut_ptr().cast() },
        dwFlags: 0,
    };
    let mut got = 0u32;
    // SAFETY: every buffer in `msg` lives through the call; no overlapped.
    if unsafe { recvmsg(s, &mut msg, &mut got, std::ptr::null_mut(), None) } != 0 {
        let e = last_wsa();
        // A datagram larger than the buffer: the bytes that fit, the rest is gone (UDP).
        if e != WSAEMSGSIZE {
            return Err(std::io::Error::from_raw_os_error(e));
        }
        got = data.len;
    }
    let peer = parse_sockaddr(&name[..(msg.namelen.max(0) as usize).min(28)]).ok_or_else(|| std::io::Error::other("a datagram without a sender"))?;
    // SAFETY: the control buffer is ours; its length came back in msg.
    let ctl = unsafe { std::slice::from_raw_parts(control.as_ptr() as *const u8, (msg.Control.len as usize).min(control.len() * 8)) };
    Ok((got as usize, peer, parse_pktinfo(ctl)))
}

/// The destination address (and interface) in a control buffer from WSARecvMsg: the first
/// IP_PKTINFO or IPV6_PKTINFO, an IPv4-mapped one as IPv4. Pure: every length is checked.
pub fn parse_pktinfo(ctl: &[u8]) -> Option<(IpAddr, u32)> {
    const W: usize = std::mem::size_of::<usize>();
    let hdr = W + 8;
    let align = |n: usize| (n + 7) & !7;
    let data_at = align(hdr);
    let mut at = 0usize;
    while at + hdr <= ctl.len() {
        let mut lenb = [0u8; W];
        lenb.copy_from_slice(&ctl[at..at + W]);
        let len = usize::from_le_bytes(lenb);
        if len < hdr || at.checked_add(len)? > ctl.len() {
            return None;
        }
        let level = i32::from_le_bytes(ctl[at + W..at + W + 4].try_into().ok()?);
        let ty = i32::from_le_bytes(ctl[at + W + 4..at + W + 8].try_into().ok()?);
        let data = ctl.get(at + data_at..at + len).unwrap_or(&[]);
        if level == IPPROTO_IP && ty == IP_PKTINFO && data.len() >= 8 {
            return Some((IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])), u32::from_le_bytes(data[4..8].try_into().ok()?)));
        }
        if level == IPPROTO_IPV6 && ty == IPV6_PKTINFO && data.len() >= 20 {
            let mut o = [0u8; 16];
            o.copy_from_slice(&data[..16]);
            let ip = Ipv6Addr::from(o);
            let ifx = u32::from_le_bytes(data[16..20].try_into().ok()?);
            return Some(match ip.to_ipv4_mapped() {
                Some(v4) => (IpAddr::V4(v4), ifx),
                None => (IpAddr::V6(ip), ifx),
            });
        }
        at += align(len);
    }
    None
}

// ---------- port owners ----------

/// A process holding a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    /// The exe's file name ("tftpd64.exe"), or empty when Windows would not say.
    pub name: String,
}

impl Owner {
    /// "tftpd64.exe", "HTTP.sys (a Windows service registered port 80)", "PID 1234".
    pub fn words(&self, tcp: bool, port: u16) -> String {
        if self.pid == 4 && tcp {
            return format!("HTTP.sys (a Windows service registered port {port})");
        }
        if self.pid == 4 {
            return "Windows (System)".into();
        }
        if self.name.is_empty() { format!("PID {}", self.pid) } else { format!("{} (PID {})", self.name, self.pid) }
    }
}

/// A process's exe file name (no folder), cleaned; empty when it cannot be asked.
pub fn process_name(pid: u32) -> String {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    if pid == 0 {
        return "System Idle Process".into();
    }
    if pid == 4 {
        return "System".into();
    }
    // SAFETY: a query-only open; closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return String::new();
    }
    let mut buf = vec![0u16; 32_768];
    let mut n = buf.len() as u32;
    // SAFETY: a buffer and its length in units.
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n) } != 0;
    unsafe { CloseHandle(h) };
    if !ok {
        return String::new();
    }
    let full = String::from_utf16_lossy(&buf[..n as usize]);
    crate::text::clean(full.rsplit('\\').next().unwrap_or(""))
}

/// Rows of a table (a DWORD count, then rows), cut to what the bytes hold.
fn rows<T: Copy>(buf: &[u8]) -> Vec<T> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let size = std::mem::size_of::<T>();
    let fit = (buf.len() - 4) / size;
    // SAFETY: inside the buffer (checked above); the row types are plain old data.
    (0..n.min(fit)).map(|i| unsafe { std::ptr::read_unaligned(buf.as_ptr().add(4 + i * size) as *const T) }).collect()
}

fn fetch(call: impl Fn(*mut core::ffi::c_void, &mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size: u32 = 16 * 1024;
    for _ in 0..8 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut got = (buf.len() * 8) as u32;
        let r = call(buf.as_mut_ptr().cast(), &mut got);
        if r == 0 {
            // SAFETY: a u64 buffer seen as its bytes.
            return Some(unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) }.to_vec());
        }
        if r != 122 {
            return None; // not ERROR_INSUFFICIENT_BUFFER
        }
        size = got.max(size).saturating_add(8 * 1024);
    }
    None
}

/// Every process that has `port` open for `tcp` (listening) or UDP, on any local address, IPv4
/// or IPv6. None when the tables could not be read.
pub fn owners(tcp: bool, port: u16) -> Option<Vec<Owner>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    let pport = |d: u32| u16::from_be(d as u16);
    let mut pids: Vec<u32> = Vec::new();
    let mut add = |pid: u32| {
        if !pids.contains(&pid) {
            pids.push(pid);
        }
    };
    for af in [AF_INET, AF_INET6] {
        if tcp {
            // SAFETY: the sizing protocol of GetExtendedTcpTable.
            let b = fetch(|p, n| unsafe { GetExtendedTcpTable(p, n, 0, af as u32, TCP_TABLE_OWNER_PID_LISTENER, 0) })?;
            if af == AF_INET {
                rows::<MIB_TCPROW_OWNER_PID>(&b).iter().filter(|r| pport(r.dwLocalPort) == port).for_each(|r| add(r.dwOwningPid));
            } else {
                rows::<MIB_TCP6ROW_OWNER_PID>(&b).iter().filter(|r| pport(r.dwLocalPort) == port).for_each(|r| add(r.dwOwningPid));
            }
        } else {
            // SAFETY: the sizing protocol of GetExtendedUdpTable.
            let b = fetch(|p, n| unsafe { GetExtendedUdpTable(p, n, 0, af as u32, UDP_TABLE_OWNER_PID, 0) })?;
            if af == AF_INET {
                rows::<MIB_UDPROW_OWNER_PID>(&b).iter().filter(|r| pport(r.dwLocalPort) == port).for_each(|r| add(r.dwOwningPid));
            } else {
                rows::<MIB_UDP6ROW_OWNER_PID>(&b).iter().filter(|r| pport(r.dwLocalPort) == port).for_each(|r| add(r.dwOwningPid));
            }
        }
    }
    Some(pids.into_iter().map(|pid| Owner { pid, name: process_name(pid) }).collect())
}

// ---------- the adapters' addresses ----------

/// One address of an adapter that is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAddr {
    pub addr: IpAddr,
    /// The IPv6 scope (interface index) for a link-local address, else 0.
    pub scope: u32,
    /// "Ethernet", "Wi-Fi" (cleaned).
    pub adapter: String,
}

impl LocalAddr {
    /// "192.168.1.20", "fe80::1%12".
    pub fn text(&self) -> String {
        match self.addr {
            IpAddr::V6(a) if self.scope != 0 => format!("{a}%{}", self.scope),
            a => a.to_string(),
        }
    }

    pub fn bind(&self) -> Bind {
        Bind::One(self.addr, self.scope)
    }

    pub fn link_local(&self) -> bool {
        matches!(self.addr, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80)
    }
}

/// Every unicast address of every adapter that is up (loopback left out), IPv4 first; IPv6
/// temporary (privacy) and deprecated addresses left out (they change or go).
pub fn adapters() -> Result<Vec<LocalAddr>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: an 8-byte aligned buffer of `size` bytes; the API fills a list inside it.
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
        match r {
            0 => break,
            111 if tries < 4 => tries += 1,
            232 => return Ok(Vec::new()),
            e => return Err(format!("Windows did not list the network adapters (error {e}).")),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a node of the list in `buf`, which outlives the loop.
        let a = unsafe { &*p };
        p = a.Next;
        if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let name = {
            let w = a.FriendlyName;
            // SAFETY: a NUL-terminated string in the buffer.
            let len = if w.is_null() { 0 } else { (0..).take_while(|&i| unsafe { *w.add(i) } != 0).count() };
            crate::text::clean(&String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(w, len) }))
        };
        let ifx6 = a.Ipv6IfIndex;
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: as above.
            let ua = unsafe { &*u };
            u = ua.Next;
            if ua.DadState != IpDadStatePreferred || ua.SuffixOrigin == IpSuffixOriginRandom {
                continue;
            }
            let sa = ua.Address.lpSockaddr;
            let len = (ua.Address.iSockaddrLength.max(0) as usize).min(28);
            if sa.is_null() || len < 8 {
                continue;
            }
            // SAFETY: a sockaddr of `len` bytes inside the buffer.
            let bytes = unsafe { std::slice::from_raw_parts(sa as *const u8, len) };
            let Some(sock) = parse_sockaddr(bytes) else { continue };
            let addr = sock.ip();
            let link_local = matches!(addr, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80);
            out.push(LocalAddr { addr, scope: if link_local { ifx6 } else { 0 }, adapter: name.clone() });
        }
    }
    out.sort_by_key(|l| (l.addr.is_ipv6(), l.link_local()));
    Ok(out)
}

// ---------- the local network (SNA4) ----------

/// Whether `ip` is in a range that is local wherever this PC is: loopback, the RFC 1918 private
/// ranges, IPv4 link-local (169.254/16), IPv6 link-local (fe80::/10) and unique local
/// (fc00::/7). Pure. Shared carrier-grade NAT space (100.64/10) is not among them: other
/// customers of the same provider live there. It counts only as an on-link subnet of one of this
/// PC's adapters (`on_link`), like any other range.
pub fn private_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => private_range(IpAddr::V4(v4)),
            None => a.is_loopback() || a.segments()[0] & 0xffc0 == 0xfe80 || a.segments()[0] & 0xfe00 == 0xfc00,
        },
    }
}

/// Whether `ip` lies in `net`/`len`. Pure. An on-link prefix shorter than /8 (IPv4) or /32
/// (IPv6) never matches: no local network is that big, and such a prefix would let most of the
/// internet in.
pub fn in_prefix(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    let ip = match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) if (8..=32).contains(&len) => {
            let mask = u32::MAX << (32 - len as u32);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) if (32..=128).contains(&len) => {
            let mask = u128::MAX << (128 - len as u32);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Every unicast address of every adapter that is up, with its on-link prefix length (the
/// subnets Windows Firewall's `LocalSubnet` means).
pub fn on_link() -> Result<Vec<(IpAddr, u8)>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: an 8-byte aligned buffer of `size` bytes; the API fills a list inside it.
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
        match r {
            0 => break,
            111 if tries < 4 => tries += 1,
            232 => return Ok(Vec::new()),
            e => return Err(format!("error {e}")),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a node of the list in `buf`, which outlives the loop.
        let a = unsafe { &*p };
        p = a.Next;
        if a.OperStatus != IfOperStatusUp {
            continue;
        }
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: as above.
            let ua = unsafe { &*u };
            u = ua.Next;
            let sa = ua.Address.lpSockaddr;
            let len = (ua.Address.iSockaddrLength.max(0) as usize).min(28);
            if sa.is_null() || len < 8 {
                continue;
            }
            // SAFETY: a sockaddr of `len` bytes inside the buffer.
            let bytes = unsafe { std::slice::from_raw_parts(sa as *const u8, len) };
            if let Some(sock) = parse_sockaddr(bytes) {
                out.push((sock.ip(), ua.OnLinkPrefixLength));
            }
        }
    }
    Ok(out)
}

/// How long a read of the on-link subnets is used for. A peer outside every private range is
/// judged on a read at most this old, never on an older one.
const ON_LINK_FRESH: Duration = Duration::from_secs(2);

/// SNA4: whether a peer may use the servers: a private range (`private_range`) or an on-link
/// subnet of one of this PC's adapters, read again when the last read is older than
/// `ON_LINK_FRESH`. Adapters that cannot be read add nothing (the fail-safe side): then only the
/// private ranges count.
pub fn on_lan(ip: IpAddr) -> bool {
    if private_range(ip) {
        return true;
    }
    /// When the subnets were read, and what they were.
    type Read = Option<(Instant, Vec<(IpAddr, u8)>)>;
    static READ: std::sync::Mutex<Read> = std::sync::Mutex::new(None);
    let mut r = READ.lock().unwrap_or_else(|e| e.into_inner());
    if r.as_ref().is_none_or(|(at, _)| since(*at) >= ON_LINK_FRESH) {
        *r = Some((Instant::now(), on_link().unwrap_or_default()));
    }
    r.as_ref().is_some_and(|(_, nets)| nets.iter().any(|&(net, len)| in_prefix(ip, net, len)))
}

/// When an address comes or goes (a cable, Wi-Fi, a VPN): `f` runs on a system thread. Dropped,
/// it stops.
pub struct Watch(HANDLE, *mut Box<dyn Fn() + Send + Sync>);

// SAFETY: the handle and the boxed callback are only touched at drop.
unsafe impl Send for Watch {}

unsafe extern "system" fn changed(ctx: *const core::ffi::c_void, _row: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_UNICASTIPADDRESS_ROW, _ty: windows_sys::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE) {
    // SAFETY: the context is the Box made in `watch`, alive until CancelMibChangeNotify2 returns.
    let f = unsafe { &*(ctx as *const Box<dyn Fn() + Send + Sync>) };
    f();
}

pub fn watch(f: Box<dyn Fn() + Send + Sync>) -> Option<Watch> {
    use windows_sys::Win32::NetworkManagement::IpHelper::NotifyUnicastIpAddressChange;
    let ctx = Box::into_raw(Box::new(f));
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: a static callback and a context that lives until the cancel in Drop.
    let r = unsafe { NotifyUnicastIpAddressChange(AF_UNSPEC, Some(changed), ctx as *const _, false, &mut h) };
    if r != 0 {
        // SAFETY: never registered: ours to free.
        drop(unsafe { Box::from_raw(ctx) });
        return None;
    }
    Some(Watch(h, ctx))
}

impl Drop for Watch {
    fn drop(&mut self) {
        use windows_sys::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2;
        // SAFETY: the registration from `watch`; after the cancel no callback runs.
        unsafe {
            CancelMibChangeNotify2(self.0);
            drop(Box::from_raw(self.1));
        }
    }
}

/// How long ago `t` was, never negative.
pub fn since(t: Instant) -> Duration {
    Instant::now().saturating_duration_since(t)
}

// ---------- fair shares (IN-VibeServe-3) ----------

/// The slowest a transfer may run: after `grace`, at least `min_rate` bytes a second on average
/// since it began. A slow-drip client holds its slot only as long as it moves data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pace {
    pub grace: Duration,
    pub min_rate: u64,
}

/// 30 s to get going, then 1 KB/s on average: far below any real LAN or TFTP transfer.
pub const PACE: Pace = Pace { grace: Duration::from_secs(30), min_rate: 1024 };

impl Pace {
    /// When a transfer that began at `start` and has moved `done` bytes falls behind.
    pub fn deadline(&self, start: Instant, done: u64) -> Instant {
        let ms = done.saturating_mul(1000) / self.min_rate.max(1);
        // Capped: an Instant far out must not overflow.
        start + self.grace + Duration::from_millis(ms.min(365 * 24 * 3600 * 1000))
    }

    /// The transfer is behind its pace now.
    pub fn behind(&self, start: Instant, done: u64) -> bool {
        Instant::now() > self.deadline(start, done)
    }

    /// How long a read or write may wait now: at most `idle`, never past the deadline (at
    /// least 1 ms: a zero timeout is refused by the socket calls).
    pub fn wait(&self, start: Instant, done: u64, idle: Duration) -> Duration {
        self.deadline(start, done).saturating_duration_since(Instant::now()).min(idle).max(Duration::from_millis(1))
    }

    /// "slower than 1.0 KB/s"
    pub fn words(&self) -> String {
        format!("slower than {}/s", crate::text::bytes(self.min_rate))
    }
}

/// Slots per peer address, beside each server's global cap: one host on the network cannot take
/// every slot. A slot is given back when its `Slot` drops.
#[derive(Default)]
pub struct Peers(std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>);

/// One peer's slot, held while its connection or transfer runs.
pub struct Slot {
    peers: Arc<Peers>,
    ip: IpAddr,
}

/// Who a slot is counted against (RIN1-4): an IPv4 address as it is; an IPv6 one by its /64,
/// since one host can take any number of addresses in its own prefix (SLAAC, privacy and
/// link-local addresses). An IPv4-mapped address counts as its IPv4 one.
pub fn peer_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v) & !((1u128 << 64) - 1))),
        },
    }
}

impl Peers {
    /// A slot for `ip` (counted per `peer_of`), unless that peer already holds `max`.
    pub fn take(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<Slot> {
        let ip = peer_of(ip);
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(Slot { peers: self.clone(), ip })
    }

    /// The slots the peer of `ip` holds now.
    pub fn held(&self, ip: IpAddr) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(&peer_of(ip)).copied().unwrap_or(0)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut m = self.peers.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}
