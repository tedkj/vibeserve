//! The window's brain. It lives on the UI thread: it keeps the prefs (in memory, saved on the
//! prefs thread), the servers' switches and what runs, the root folder, the firewall's state and
//! the helper's session, the logs, and the toasts. The .slint files lay out what it hands them;
//! every word and choice is made here (and in `view`).
//!
//! Work never runs on the UI thread: binding a server, opening the root, reading the firewall,
//! the UAC prompt, the adapters, saving a view all run on workers, and every answer carries the
//! epoch it was asked for (a server's, the root's, the firewall's); an answer for another epoch
//! does nothing. Servers and workers report through one inbox: the first message after a quiet
//! spell wakes the window at once, then at most every 100 ms (one wake-up per batch).

use crate::activity::{Entry, Kind, Log, LOG_CAP, Report};
use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::export::Locale;
use crate::firewall::{Purpose, Rule, Status};
use crate::gate::{Gate, GateSession};
use crate::helper::{Launch, Reply, Request, Want};
use crate::host::Paths;
use crate::listen::{Bind, BindError, LocalAddr, Owner as PortOwner};
use crate::logview::{Change as ViewChange, Filter, Store as SyslogStore};
use crate::paths::{Root, Share};
use crate::prefs::{Change, Store};
use crate::syslog::{FileLimits, FileLog, FileState, Message};
use crate::{AddrLine, AppWindow, CardView, CheckDot, CheckRow, ConsentView, FirewallView, LogRow, Prefs, SyslogDetail, SyslogRow, Theme, ToastItem, ToastKind, TransferRow};
use slint::{ComponentHandle, Model, ModelNotify, ModelRc, ModelTracker, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KINDS: [Kind; 3] = [Kind::Tftp, Kind::Syslog, Kind::Http];

fn idx(k: Kind) -> usize {
    match k {
        Kind::Tftp => 0,
        Kind::Syslog => 1,
        Kind::Http => 2,
    }
}

fn kind_of(i: i32) -> Option<Kind> {
    match i {
        0 => Some(Kind::Tftp),
        1 => Some(Kind::Syslog),
        2 => Some(Kind::Http),
        _ => None,
    }
}

fn lock<X>(m: &Mutex<X>) -> std::sync::MutexGuard<'_, X> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

/// The servers' timeouts and caps (tests shorten them).
#[derive(Clone, Copy)]
pub struct Tuning {
    pub tftp: crate::tftp::Tuning,
    pub http: crate::http::Tuning,
    pub syslog: crate::syslog::Tuning,
    pub file: FileLimits,
    /// How long closing the window waits for the servers, the helper and the log writer.
    pub exit_wait: Duration,
    /// Each stop holds its server this long before closing it (tests: messages in flight at
    /// the close, a slow stop). Zero in the app.
    pub stop_delay: Duration,
    /// Each bind waits this long before it is made (tests: a firewall read that lands while a
    /// server starts). Zero in the app.
    pub start_delay: Duration,
    /// Each bind's answer waits this long after the bind is made (tests: a read that lands
    /// between a bind and its answer reaching the window). Zero in the app.
    pub bound_delay: Duration,
}

/// Closing waits at most this long (DECISIONS: "a few seconds at most").
pub const EXIT_WAIT: Duration = Duration::from_secs(6);

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning { tftp: Default::default(), http: Default::default(), syslog: Default::default(), file: Default::default(), exit_wait: EXIT_WAIT, stop_delay: Duration::ZERO, start_delay: Duration::ZERO, bound_delay: Duration::ZERO }
    }
}

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    pub copy: Box<dyn Fn(&str) -> bool>,
    /// A file shown selected in Explorer (a toast's "Show").
    pub reveal: Box<dyn Fn(&Path)>,
    /// A folder opened in Explorer (the root's Open).
    pub open_folder: Box<dyn Fn(&Path)>,
    /// The folder picker (owner window, title, start folder); the answer comes on its thread.
    #[allow(clippy::type_complexity)]
    pub pick_folder: Box<dyn Fn(isize, &str, Option<PathBuf>, Box<dyn FnOnce(Option<PathBuf>) + Send>)>,
    /// Save As (owner, default name); the answer (path, CSV?) comes on its thread.
    #[allow(clippy::type_complexity)]
    pub save_as: Box<dyn Fn(isize, String, Box<dyn FnOnce(Option<(PathBuf, bool)>) + Send>)>,
    #[allow(clippy::type_complexity)]
    pub adapters: Arc<dyn Fn() -> Result<Vec<LocalAddr>, String> + Send + Sync>,
    #[allow(clippy::type_complexity)]
    pub owners: Arc<dyn Fn(bool, u16) -> Option<Vec<PortOwner>> + Send + Sync>,
    pub gate: Arc<dyn Gate>,
    /// The window in front, for the UAC prompt and the pickers.
    pub hwnd: Box<dyn Fn() -> isize>,
    pub paths: Paths,
    /// What "All addresses" binds: `[::]` for real; the tests bind loopback (a server on every
    /// address would wake Windows Firewall's own prompt). A loopback address here stands in for
    /// every address: a socket bound on it counts as beyond this PC (RL7-1), so it must not be
    /// `PC_ONLY`'s 127.0.0.1.
    pub all_bind: Bind,
    pub locale: Locale,
    /// Follow address changes (cables, Wi-Fi, VPNs).
    pub watch_addresses: bool,
    /// Servers to turn on at start (dev hooks: measurements).
    pub autostart: Vec<Kind>,
    pub tuning: Tuning,
    /// A web page in the browser (About's link).
    pub open_url: Box<dyn Fn(&str)>,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

impl Services {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `net::fetch_release_list`, and is the only place that names it.
    pub fn system(paths: Paths, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        Services {
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            reveal: Box::new(|p| {
                let _ = crate::host::reveal(p, true);
            }),
            open_folder: Box::new(|p| {
                let _ = crate::host::reveal(p, false);
            }),
            pick_folder: Box::new(crate::dialogs::pick_folder),
            save_as: Box::new(crate::dialogs::save_as),
            adapters: Arc::new(crate::listen::adapters),
            owners: Arc::new(crate::listen::owners),
            gate: Arc::new(crate::gate::System),
            hwnd: Box::new(crate::host::active_window),
            paths,
            all_bind: Bind::All,
            locale: crate::export::user_locale(),
            watch_addresses: true,
            autostart: Vec::new(),
            tuning: Tuning::default(),
            // The shell can take a moment: never on the window's thread.
            open_url: Box::new(|u| {
                let u = u.to_string();
                std::thread::spawn(move || {
                    let _ = crate::host::open_url(&u);
                });
            }),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

// ---------- the inbox ----------

/// A running server.
enum Srv {
    Tftp(crate::tftp::Server),
    Syslog(crate::syslog::Server),
    Http(crate::http::Server),
}

impl Srv {
    /// Stop it (bounded: `listen::HALT_WAIT`): the threads it left in a file call.
    fn stop(self) -> crate::listen::Left {
        match self {
            Srv::Tftp(s) => s.stop_left(),
            Srv::Syslog(s) => s.stop_left(),
            Srv::Http(s) => s.stop_left(),
        }
    }

    /// Its sockets as bound, read from them: (TCP?, local address).
    fn sockets(&self) -> Vec<(bool, std::net::SocketAddr)> {
        match self {
            Srv::Tftp(t) => vec![(false, t.local)],
            Srv::Http(h) => vec![(true, h.local)],
            Srv::Syslog(s) => s.udp.map(|a| (false, a)).into_iter().chain(s.tcp.map(|a| (true, a))).collect(),
        }
    }
}

/// The firewall's state as read: its status and every rule, or why it could not be read.
type FwRead = Result<(Status, Vec<Rule>), String>;

/// RL7-1: the one source of truth for whether VibeServe is open beyond this PC, shared with the
/// workers that bind. Under one lock: the firewall read the window holds and every socket bound
/// now, by its real local address. A bind is judged and made under it (one beyond this PC that
/// the read does not allow is never made), its sockets enter `open` in the same step, and they
/// leave only once they are closed (`Live`). What the window shows is derived from both:
/// while a socket in `open` is beyond this PC and the newest read does not allow it, the window
/// shows the read it showed before (`prev`), so "unknown" or "this PC only" is never shown while
/// such a socket is bound. RL9-2: once that socket is only a stopped server's, kept by a thread
/// its stop left (`left`), the window shows the newest read and its firewall state says a
/// stopped server is still closing and may still hold a socket on the network (RSA-3: judged on
/// its sockets as bound, not on what the left threads hold), until that thread ends.
struct Net {
    /// The newest read (none yet: `Need::Reading`).
    read: Option<FwRead>,
    /// The read shown before it, shown while a bound socket is beyond what `read` allows.
    prev: Option<FwRead>,
    /// Every server bound now: its sockets (TCP?, local address as bound).
    open: std::collections::BTreeMap<u64, Vec<(bool, std::net::SocketAddr)>>,
    /// The entries in `open` whose server has stopped, waiting for the threads its stop left.
    left: std::collections::BTreeSet<u64>,
    next: u64,
}

struct Shared {
    net: Mutex<Net>,
    /// This exe's path, as the rules name it.
    exe: PathBuf,
    /// The rigs' stand-in for "every address" (`Services::all_bind`, a loopback address that
    /// counts as beyond this PC). None in the app.
    stand_in: Option<std::net::IpAddr>,
}

impl Shared {
    /// An address beyond this PC: anything but loopback (`[::]` included), and the rigs'
    /// stand-in for every address.
    fn beyond(&self, ip: std::net::IpAddr) -> bool {
        !ip.is_loopback() || self.stand_in == Some(ip)
    }

    fn beyond_bind(&self, b: &Bind) -> bool {
        match b {
            Bind::All => true,
            Bind::One(ip, _) => self.beyond(*ip),
        }
    }

    /// `read` lets these (TCP?, port) pairs listen beyond this PC: a Private network, or a
    /// user's rule for them on the active profiles (RIN1-3, RF1-3).
    fn allows(&self, read: Option<&FwRead>, ports: &[(bool, u16)]) -> bool {
        !matches!(need_of(read, &self.exe, ports), Need::Public | Need::Reading | Need::ReadFailed(_))
    }

    /// A socket of these entries (`left`: those of stopped servers; else the others) is beyond
    /// this PC and the newest read does not allow it.
    fn unallowed(&self, net: &Net, left: bool) -> bool {
        net.open.iter().filter(|(id, _)| net.left.contains(id) == left).flat_map(|(_, v)| v).any(|(tcp, a)| self.beyond(a.ip()) && !self.allows(net.read.as_ref(), &[(*tcp, a.port())]))
    }

    /// A server's socket is beyond what the newest read allows: the window shows the read before.
    fn held(&self, net: &Net) -> bool {
        self.unallowed(net, false)
    }

    /// RL9-2: only a thread a stop left may hold such a socket (until it ends; a file call deaf
    /// to the stop may never return). Judged on the stopped server's sockets as bound, not on
    /// what its left threads hold (RSA-3), so the window says "may".
    fn stuck(&self, net: &Net) -> bool {
        self.unallowed(net, true)
    }

    /// The read the window shows.
    fn shown<'a>(&self, net: &'a Net) -> Option<&'a FwRead> {
        if self.held(net) { net.prev.as_ref() } else { net.read.as_ref() }
    }
}

/// A server bound now and its place in `Net::open`. Its sockets leave the set only once they
/// are closed (RL8-1): `close` stops the server, and its entry goes then or, when the stop left
/// threads (each may hold one of its sockets: the listener, a transfer's, a connection's), once
/// the last of them has ended. A drop closes it the same way.
struct Live {
    /// Taken by `close`.
    srv: Option<Srv>,
    reg: Option<Reg>,
}

struct Reg {
    sh: Arc<Shared>,
    id: u64,
    inbox: Arc<Inbox>,
}

impl Drop for Reg {
    fn drop(&mut self) {
        let mut net = lock(&self.sh.net);
        net.open.remove(&self.id);
        net.left.remove(&self.id);
    }
}

impl Reg {
    /// The entry goes once the threads `left` have ended (now, when the stop left none). Then
    /// the window hears of it: a hold on the firewall's state may end.
    fn release(self, left: crate::listen::Left) {
        if left.count() == 0 {
            return;
        }
        lock(&self.sh.net).left.insert(self.id);
        // Not dropped if the thread can't be made: the entry stays for good, never taken out
        // while a left thread may still hold a socket.
        let reg = std::mem::ManuallyDrop::new(self);
        let _ = std::thread::Builder::new().name("left".into()).stack_size(64 * 1024).spawn(move || {
            while !left.ended() {
                std::thread::sleep(Duration::from_millis(50));
            }
            let reg = std::mem::ManuallyDrop::into_inner(reg);
            let inbox = reg.inbox.clone();
            drop(reg);
            inbox.push(Msg::Closed);
        });
    }
}

impl Live {
    fn id(&self) -> Option<u64> {
        self.reg.as_ref().map(|r| r.id)
    }

    /// Stop the server: how many threads the stop left (see `Srv::stop`). Its entry leaves the
    /// set once they have ended (`Reg::release`), never before.
    fn close(&mut self) -> usize {
        let Some(srv) = self.srv.take() else { return 0 };
        let left = srv.stop();
        let n = left.count();
        if let Some(reg) = self.reg.take() {
            reg.release(left);
        }
        n
    }

    /// `close`, `delay` first (tests: a slow stop).
    fn stop(mut self, delay: Duration) -> usize {
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        self.close()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.close();
    }
}

/// What workers and servers tell the window.
enum Msg {
    Entry(Kind, Entry),
    Syslog(Vec<Message>),
    /// `bind`: the bind made, as the card shows it (chosen at bind time, RL6-1, RL7-1).
    Started { kind: Kind, epoch: u64, bind: Bind, res: Result<Live, (String, bool)> },
    /// A server dropped off the UI thread is gone (a hold on the firewall's state may end).
    Closed,
    /// `left`: threads the stop left in a file call (they end on their own).
    Stopped { kind: Kind, epoch: u64, left: usize },
    RootOpened { epoch: u64, res: Result<(Arc<Root>, PathBuf), String> },
    FwRead { epoch: u64, res: Result<(Status, Vec<Rule>), String> },
    FwOpened { epoch: u64, wants: Vec<Want>, res: Result<(Box<dyn GateSession>, Reply), Launch> },
    FwReply { seq: u64, wants: Vec<Want>, res: Result<Reply, String> },
    FwCleaned(Result<Reply, Launch>),
    Adapters(Result<Vec<LocalAddr>, String>),
    AddressesChanged,
    Picked { root: bool, path: Option<PathBuf> },
    SaveTo(Option<(PathBuf, bool)>),
    Saved(Result<(PathBuf, usize), String>),
    File(FileState),
    Pruned(usize),
}

struct Inbox {
    q: Mutex<Vec<Msg>>,
    /// A wake-up is on its way (or the window drained less than 100 ms ago).
    armed: AtomicBool,
}

thread_local! {
    static APP: RefCell<std::rc::Weak<App>> = const { RefCell::new(std::rc::Weak::new()) };
}

impl Inbox {
    fn push(&self, m: Msg) {
        lock(&self.q).push(m);
        if !self.armed.swap(true, Ordering::SeqCst) {
            // No event loop (the tests): they pump themselves.
            let _ = slint::invoke_from_event_loop(|| {
                APP.with(|a| {
                    if let Some(app) = a.borrow().upgrade() {
                        app.drain();
                    }
                })
            });
        }
    }
}

impl Report for Inbox {
    fn entry(&self, kind: Kind, e: Entry) {
        self.push(Msg::Entry(kind, e));
    }
}

/// The syslog receivers' sink: lines to the log file (on the receiver's thread, unfiltered,
/// every one), messages to the window.
struct SyslogSink {
    inbox: Arc<Inbox>,
    file: Arc<Mutex<Option<FileLog>>>,
}

impl crate::syslog::Sink for SyslogSink {
    fn messages(&self, batch: Vec<Message>, raw: Vec<Vec<u8>>) {
        if !raw.is_empty()
            && let Some(f) = lock(&self.file).as_ref()
        {
            for (m, r) in batch.iter().zip(raw.iter()) {
                f.line(m.received, crate::syslog::file_line(m, r));
            }
        }
        self.inbox.push(Msg::Syslog(batch));
    }

    fn keep_raw(&self) -> bool {
        lock(&self.file).is_some()
    }
}

// ---------- the models ----------

/// The syslog rows: read from the store when the list asks (100 000 rows never become 100 000
/// row structs).
struct SyslogModel {
    store: RefCell<SyslogStore>,
    selected: Cell<Option<u64>>,
    notify: ModelNotify,
}

impl Model for SyslogModel {
    type Data = SyslogRow;
    fn row_count(&self) -> usize {
        self.store.borrow().len()
    }
    fn row_data(&self, row: usize) -> Option<SyslogRow> {
        let st = self.store.borrow();
        let (seq, m) = st.row(row)?;
        Some(crate::view::syslog_row(m, self.selected.get() == Some(seq)))
    }
    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }
}

impl SyslogModel {
    /// Any change resets the list: row_added/row_removed made Slint's ListView keep a record per
    /// row ever added (+25 MB at 100 000 messages, measured); a reset keeps only the rows in
    /// sight. The newest rows are at the top, where a reset leaves the view.
    fn changed(&self, _before: usize, c: ViewChange) {
        if c.reset || c.added_front > 0 || c.removed_back > 0 {
            self.notify.reset();
        }
    }
}

/// An activity log's rows, newest first.
struct EntryModel {
    log: RefCell<Log>,
    notify: ModelNotify,
}

impl Model for EntryModel {
    type Data = LogRow;
    fn row_count(&self) -> usize {
        self.log.borrow().len()
    }
    fn row_data(&self, row: usize) -> Option<LogRow> {
        self.log.borrow().get(row).map(crate::view::log_row)
    }
    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }
}

// ---------- state ----------

enum Phase {
    Off,
    /// On, waiting for the root or the firewall (the words say which).
    Waiting(&'static str),
    Starting,
    Running(Live, Bind),
    /// On, but it could not start: the words, and a port to offer instead (80 taken: 8080).
    Failed(String, Option<u16>),
    Stopping,
}

struct Slot {
    on: bool,
    /// The port field's text (maybe half-typed) and the committed port.
    port_text: String,
    port: Option<u16>,
    bind_key: String,
    writes: bool,
    udp: bool,
    tcp: bool,
    epoch: u64,
    phase: Phase,
}

/// Where a server listens while no Private network is active (SEC-Serve-1, RIN1-3): this PC
/// only, so nothing else (a rule left by a crash, Windows' own "allow access" prompt) can let
/// the network in.
pub const PC_ONLY: Bind = Bind::One(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

impl Slot {
    fn running(&self) -> bool {
        matches!(self.phase, Phase::Running(..))
    }

    /// Wanted on the network now (on, and not given up).
    fn live(&self) -> bool {
        self.on && matches!(self.phase, Phase::Waiting(_) | Phase::Starting | Phase::Running(..))
    }
}

struct RootSlot {
    path: PathBuf,
    is_default: bool,
    open: Option<Arc<Root>>,
    opening: bool,
    error: Option<String>,
    epoch: u64,
}

/// The helper's session, shared with the worker that talks to it.
type SharedSession = Arc<Mutex<Option<Box<dyn GateSession>>>>;

#[derive(Default)]
struct Fw {
    /// The reads themselves are in `Net` (RL7-1).
    reading: bool,
    read_epoch: u64,
    session: Option<SharedSession>,
    /// What the helper holds (its last answer).
    held: Vec<Want>,
    /// The newest Set sent, and whether its answer is out.
    sync_seq: u64,
    syncing: bool,
    asking: bool,
    launching: bool,
    declined: bool,
    failed: Option<String>,
    /// The helper ended under us (killed, its 24 h limit).
    lost: bool,
    remove_blocks: bool,
    epoch: u64,
    stale_done: bool,
}

/// What a server needs of the firewall.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Need {
    /// Loopback: nobody else can reach it anyway.
    Nothing,
    Reading,
    ReadFailed(String),
    Off,
    BlockAll,
    /// A rule of the user's already lets it in.
    Covered,
    /// No Private network is active: VibeServe's rule would not apply (SEC-Serve-1).
    Public,
    Rule,
}

struct Syslog {
    model: Rc<SyslogModel>,
    filter_text: String,
    filter_seq: u64,
    severity: u8,
    source: Option<std::net::IpAddr>,
    sources_shown: Vec<Option<std::net::IpAddr>>,
    log_to_file: bool,
    folder: Option<PathBuf>,
    file_state: FileState,
    /// The writer's "behind" count already told in a toast (per writer).
    behind_told: bool,
    dirty: bool,
}

#[derive(Default)]
struct State {
    prefs: Prefs,
    toast_seq: i32,
    toast_paths: HashMap<i32, PathBuf>,
    /// Each toast's timer generation (only the newest timer counts) and its full time in ms.
    toast_time: HashMap<i32, (u64, u64)>,
    adapters: Vec<LocalAddr>,
    adapters_error: Option<String>,
    bind_keys: [Vec<String>; 3],
    last_drain: Option<Instant>,
    closing: bool,
    /// A card's long address list shown whole ("+N more" clicked).
    addrs_open: [bool; 3],
    /// How many `Msg::Closed` the window has had (tests: a closed entry is told, RL9-3).
    closes: usize,
    /// The install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

/// One change to the prefs, applied by the prefs thread onto the newest saved ones.
type PrefsChange = Change<Prefs>;

/// After a change, when the window looks whether the prefs thread met a garbled file.
const PREFS_TELL_MS: u64 = 500;

/// The thread that saves prefs changes, in order (see VibeWare's prefs rules: the store puts
/// every unwritten change onto the file as read right before the write).
fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    prefs_pending: Arc<AtomicUsize>,
    toasts: Rc<VecModel<ToastItem>>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
    me: RefCell<std::rc::Weak<App>>,
    inbox: Arc<Inbox>,
    slots: RefCell<Vec<Slot>>,
    sh: Arc<Shared>,
    root: RefCell<RootSlot>,
    fw: RefCell<Fw>,
    syslog: RefCell<Syslog>,
    file: Arc<Mutex<Option<FileLog>>>,
    /// The last writer let go and maybe still writing out its queue: the next one waits for it,
    /// and so does exit (bounded).
    file_retired: RefCell<Option<std::thread::JoinHandle<()>>>,
    tftp_share: Arc<Share>,
    http_share: Arc<Share>,
    logs: [Rc<EntryModel>; 2],
    /// The repeating tick while a server runs (transfers, counters, the helper's pulse).
    ticker: Timer,
    /// Address changes (dropped at exit).
    watch: RefCell<Option<crate::listen::Watch>>,
    /// Workers still out (tests wait for them).
    in_flight: Arc<AtomicUsize>,
    models: Models,
}

/// The small models the window reads (rebuilt when they change).
struct Models {
    binds: [Rc<VecModel<SharedString>>; 3],
    addrs: [Rc<VecModel<AddrLine>>; 3],
    transfers: Rc<VecModel<TransferRow>>,
    sources: Rc<VecModel<SharedString>>,
    tabs: Rc<VecModel<SharedString>>,
}

impl App {
    /// Wire the controller to a window made by `crate::window`.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let slots = KINDS
            .iter()
            .map(|&k| {
                let sp = prefs.server(k);
                Slot { on: false, port_text: sp.port.to_string(), port: Some(sp.port), bind_key: sp.bind.clone(), writes: false, udp: prefs.syslog_udp, tcp: prefs.syslog_tcp, epoch: 0, phase: Phase::Off }
            })
            .collect();
        let (root_path, is_default) = match &prefs.root {
            Some(r) => (PathBuf::from(r), false),
            None => (svc.paths.default_root.clone(), true),
        };
        let log_folder = prefs.log_folder.as_ref().map(PathBuf::from);
        let log_to_file = prefs.log_to_file;
        let inbox = Arc::new(Inbox { q: Mutex::new(Vec::new()), armed: AtomicBool::new(false) });
        let app = Rc::new(App {
            ui: ui.as_weak(),
            store,
            st: RefCell::new(State { prefs: prefs.clone(), ..State::default() }),
            prefs_tx,
            prefs_pending,
            toasts: Rc::new(VecModel::default()),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
            me: RefCell::new(std::rc::Weak::new()),
            inbox,
            slots: RefCell::new(slots),
            // No read yet: this PC only (RF1-3).
            sh: Arc::new(Shared {
                net: Mutex::new(Net { read: None, prev: None, open: Default::default(), left: Default::default(), next: 0 }),
                exe: svc.gate.exe(),
                stand_in: match &svc.all_bind {
                    Bind::One(ip, _) => Some(*ip),
                    Bind::All => None,
                },
            }),
            root: RefCell::new(RootSlot { path: root_path, is_default, open: None, opening: false, error: None, epoch: 0 }),
            fw: RefCell::new(Fw::default()),
            syslog: RefCell::new(Syslog {
                model: Rc::new(SyslogModel { store: RefCell::new(SyslogStore::new()), selected: Cell::new(None), notify: ModelNotify::default() }),
                filter_text: String::new(),
                filter_seq: 0,
                severity: 7,
                source: None,
                sources_shown: vec![None],
                log_to_file: false,
                folder: log_folder,
                file_state: FileState::Off,
                behind_told: false,
                dirty: true,
            }),
            file: Arc::new(Mutex::new(None)),
            file_retired: RefCell::new(None),
            tftp_share: Share::new(None, false),
            http_share: Share::new(None, false),
            logs: [Rc::new(EntryModel { log: RefCell::new(Log::new(LOG_CAP)), notify: ModelNotify::default() }), Rc::new(EntryModel { log: RefCell::new(Log::new(LOG_CAP)), notify: ModelNotify::default() })],
            ticker: Timer::default(),
            watch: RefCell::new(None),
            in_flight: Arc::new(AtomicUsize::new(0)),
            models: Models {
                binds: [Rc::new(VecModel::default()), Rc::new(VecModel::default()), Rc::new(VecModel::default())],
                addrs: [Rc::new(VecModel::default()), Rc::new(VecModel::default()), Rc::new(VecModel::default())],
                transfers: Rc::new(VecModel::default()),
                sources: Rc::new(VecModel::default()),
                tabs: Rc::new(VecModel::default()),
            },
            svc,
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        APP.with(|a| *a.borrow_mut() = Rc::downgrade(&app));
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        // About's version line. VibeServe has no portable mode: it is always installed.
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        ui.set_about_line(s(format!("version {} · {bits} · installed for you", crate::VERSION)));
        ui.set_syslog_rows(ModelRc::from(app.syslog.borrow().model.clone()));
        ui.set_tftp_log(ModelRc::from(app.logs[0].clone()));
        ui.set_http_log(ModelRc::from(app.logs[1].clone()));
        ui.set_tftp_binds(ModelRc::from(app.models.binds[0].clone()));
        ui.set_syslog_binds(ModelRc::from(app.models.binds[1].clone()));
        ui.set_http_binds(ModelRc::from(app.models.binds[2].clone()));
        ui.set_tftp_addrs(ModelRc::from(app.models.addrs[0].clone()));
        ui.set_syslog_addrs(ModelRc::from(app.models.addrs[1].clone()));
        ui.set_http_addrs(ModelRc::from(app.models.addrs[2].clone()));
        ui.set_transfers(ModelRc::from(app.models.transfers.clone()));
        ui.set_sources(ModelRc::from(app.models.sources.clone()));
        ui.set_tabs(ModelRc::from(app.models.tabs.clone()));
        ui.set_severities(ModelRc::new(VecModel::from(crate::view::severities().into_iter().map(SharedString::from).collect::<Vec<_>>())));
        ui.set_severity(0);
        ui.set_tab(prefs.tab as i32);
        ui.set_root_text(s(crate::text::clean_path(&app.root.borrow().path)));
        app.wire(ui);
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error, None);
        }
        // What can be learned without asking: the adapters, the firewall, old log files.
        app.read_adapters();
        app.read_firewall();
        app.prune_logs();
        if log_to_file {
            app.set_log_to_file(true, false);
        }
        if app.svc.watch_addresses {
            let inbox = app.inbox.clone();
            *app.watch.borrow_mut() = crate::listen::watch(Box::new(move || inbox.push(Msg::AddressesChanged)));
        }
        for k in app.svc.autostart.clone() {
            app.toggle(k, true);
        }
        app.refresh();
        app
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_addrs_toggled, |a, k| {
            let i = k.clamp(0, 2) as usize;
            {
                let mut st = a.st.borrow_mut();
                st.addrs_open[i] = !st.addrs_open[i];
            }
            a.refresh();
        });
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.toast_action(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open_url)(crate::check::SITE));
        on!(on_root_accepted, |a, t| a.commit_root(&t));
        on!(on_root_escaped, |a| a.root_escaped());
        on!(on_root_blurred, |a| a.root_blurred());
        on!(on_pick_root, |a| a.pick(true));
        on!(on_open_root, |a| a.open_root_folder());
        on!(on_firewall_clicked, |a| a.firewall_clicked());
        on!(on_server_toggled, |a, k, v| if let Some(k) = kind_of(k) {
            a.toggle(k, v)
        });
        on!(on_port_edited, |a, k, t| if let Some(k) = kind_of(k) {
            a.port_edited(k, &t)
        });
        on!(on_port_accepted, |a, k, t| if let Some(k) = kind_of(k) {
            a.port_commit(k, &t)
        });
        on!(on_port_escaped, |a, k| kind_of(k).is_some_and(|k| a.port_escaped(k)));
        on!(on_port_blurred, |a, k| if let Some(k) = kind_of(k) {
            a.port_blurred(k)
        });
        on!(on_bind_picked, |a, k, i| if let Some(k) = kind_of(k) {
            a.bind_picked(k, i)
        });
        on!(on_writes_toggled, |a, k, v| if let Some(k) = kind_of(k) {
            a.writes_toggled(k, v)
        });
        on!(on_proto_toggled, |a, tcp, v| a.proto_toggled(tcp, v));
        on!(on_card_action, |a, k| if let Some(k) = kind_of(k) {
            a.card_action(k)
        });
        on!(on_tab_picked, |a, i| a.tab_picked(i));
        on!(on_filter_edited, |a, t| a.filter_edited(&t));
        on!(on_filter_escaped, |a| a.filter_escaped());
        on!(on_severity_picked, |a, i| a.severity_picked(i));
        on!(on_source_picked, |a, i| a.source_picked(i));
        on!(on_pause_toggled, |a| a.pause_toggled());
        on!(on_clear_syslog, |a| a.clear_syslog());
        on!(on_log_to_file_toggled, |a, v| a.set_log_to_file(v, true));
        on!(on_pick_log_folder, |a| a.pick(false));
        on!(on_save_view, |a| a.save_view());
        on!(on_syslog_row_clicked, |a, i| a.select_row(i.max(0) as usize));
        on!(on_syslog_key, |a, d| a.syslog_key(d));
        on!(on_copy_detail, |a| a.copy_detail());
        on!(on_copy_log, |a, k| a.copy_log(k));
        on!(on_clear_log, |a, k| a.clear_log(k));
        on!(on_consent_allow, |a| a.consent_allow());
        on!(on_consent_cancel, |a| a.consent_cancel());
        on!(on_consent_blocks, |a, v| a.consent_blocks(v));
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    fn weak(&self) -> std::rc::Weak<App> {
        self.me.borrow().clone()
    }

    // ---------- workers and the inbox ----------

    /// Run `work` off the UI thread; its message comes back through the inbox.
    fn bg(&self, work: impl FnOnce() -> Msg + Send + 'static) {
        let inbox = self.inbox.clone();
        let n = self.in_flight.clone();
        n.fetch_add(1, Ordering::SeqCst);
        let spawned = std::thread::Builder::new().name("worker".into()).stack_size(512 * 1024).spawn(move || {
            let m = work();
            inbox.push(m);
            n.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Workers still out (tests wait until none are).
    pub fn busy(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// How many "a server's sockets are closed" messages the window has had (tests).
    pub fn closes(&self) -> usize {
        self.st.borrow().closes
    }

    /// Take everything the inbox holds and show it. Tests call it; the event loop calls it
    /// through `Inbox::push`, then at most every 100 ms while messages keep coming.
    pub fn pump(&self) {
        self.drain();
    }

    fn drain(&self) {
        let msgs = std::mem::take(&mut *lock(&self.inbox.q));
        for m in msgs {
            self.handle(m);
        }
        self.tell_behind();
        self.refresh();
        self.st.borrow_mut().last_drain = Some(Instant::now());
        let w = self.weak();
        Timer::single_shot(Duration::from_millis(100), move || {
            let Some(a) = w.upgrade() else { return };
            a.inbox.armed.store(false, Ordering::SeqCst);
            if !lock(&a.inbox.q).is_empty() && !a.inbox.armed.swap(true, Ordering::SeqCst) {
                a.drain();
            }
        });
    }

    fn handle(&self, m: Msg) {
        match m {
            Msg::Entry(k, e) => {
                let i = if k == Kind::Tftp { 0 } else { 1 };
                self.logs[i].log.borrow_mut().push(e);
                self.logs[i].notify.reset();
            }
            Msg::Syslog(batch) => {
                let model = self.syslog.borrow().model.clone();
                let before = model.store.borrow().len();
                let c = model.store.borrow_mut().push(batch);
                model.changed(before, c);
                self.syslog.borrow_mut().dirty = true;
            }
            Msg::Started { kind, epoch, bind, res } => self.started(kind, epoch, bind, res),
            Msg::Closed => self.st.borrow_mut().closes += 1,
            Msg::Stopped { kind, epoch, left } => self.stopped(kind, epoch, left),
            Msg::RootOpened { epoch, res } => self.root_opened(epoch, res),
            Msg::FwRead { epoch, res } => self.fw_read(epoch, res),
            Msg::FwOpened { epoch, wants, res } => self.fw_opened(epoch, wants, res),
            Msg::FwReply { seq, wants, res } => self.fw_reply(seq, wants, res),
            Msg::FwCleaned(res) => self.fw_cleaned(res),
            Msg::Adapters(res) => {
                let mut st = self.st.borrow_mut();
                match res {
                    Ok(a) => {
                        st.adapters = a;
                        st.adapters_error = None;
                    }
                    Err(e) => st.adapters_error = Some(e),
                }
            }
            Msg::AddressesChanged => {
                // Debounced: one read for a burst of changes.
                let w = self.weak();
                Timer::single_shot(Duration::from_secs(2), move || {
                    if let Some(a) = w.upgrade() {
                        a.network_changed();
                    }
                });
            }
            Msg::Picked { root, path } => {
                if let Some(p) = path {
                    if root {
                        self.set_root(p);
                    } else {
                        self.set_log_folder(p);
                    }
                }
            }
            Msg::SaveTo(choice) => self.save_to(choice),
            Msg::Saved(res) => match res {
                Ok((p, n)) => self.toast(&format!("Saved {} rows to {}", crate::text::thousands(n as u64), crate::text::clean_path(&p)), ToastKind::Ok, Some(p)),
                Err(e) => self.toast(&format!("The view was not saved: {e}"), ToastKind::Error, None),
            },
            Msg::File(fs) => self.file_state(fs),
            Msg::Pruned(failed) => {
                if failed > 0 {
                    self.toast(&format!("{failed} syslog files older than 30 days could not be removed from the log folder."), ToastKind::Error, None);
                }
            }
        }
    }

    // ---------- prefs ----------

    /// The prefs as this window has them (its own choices, in memory).
    pub fn prefs(&self) -> Prefs {
        self.st.borrow().prefs.clone()
    }

    /// One change to the prefs: at once in memory, and by the prefs thread onto the newest saved
    /// ones. A file found garbled on the way is told shortly after.
    pub fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.weak();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error, None);
        }
    }

    /// Let the prefs thread hand its last change to the store (at most two seconds), then write
    /// what is unwritten.
    ///
    /// The last write runs on a thread of its own, waited for at most two seconds: a prefs file
    /// on a share that stopped answering never holds the window's thread for good (VibePing
    /// PING-8, review X15CON-4). A prefs thread still busy after its two seconds is not waited
    /// for: at exit the process ends it, and the changes it had not written are lost, unsaid.
    pub fn finish_prefs(&self) {
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.prefs_pending.load(Ordering::SeqCst) > 0 {
            return;
        }
        let store = self.store.clone();
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            store.flush();
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
    }

    /// The window closes: every server stops (transfers end, their temp files go), the helper
    /// removes the firewall rules, the log file is written out, the prefs are saved. Bounded:
    /// the servers, the helper and the log writer get `EXIT_WAIT` together; one stuck in a disk
    /// call (a dead share) is left to the process's end. The log writer is let go only once the
    /// servers have stopped: what they received up to then reaches the file.
    pub fn finish(&self) {
        let deadline = Instant::now() + self.svc.tuning.exit_wait;
        self.st.borrow_mut().closing = true;
        self.ticker.stop();
        let mut running = Vec::new();
        for sl in self.slots.borrow_mut().iter_mut() {
            sl.on = false;
            sl.epoch += 1;
            if let Phase::Running(live, _) = std::mem::replace(&mut sl.phase, Phase::Off) {
                running.push(live);
            }
        }
        // Each server stops on its own thread; together they take as long as the slowest.
        let delay = self.svc.tuning.stop_delay;
        let stops: Vec<_> = running
            .into_iter()
            .map(|live| {
                std::thread::spawn(move || {
                    live.stop(delay);
                })
            })
            .collect();
        let session = self.fw.borrow_mut().session.take();
        let closer = session.map(|s| {
            std::thread::spawn(move || {
                if let Some(sess) = lock(&s).take() {
                    let _ = sess.close();
                }
            })
        });
        // R-SERVE-1: the receivers hand their last batches to the writer until they stop.
        for t in &stops {
            crate::syslog::wait_for(t, deadline);
        }
        let writer = lock(&self.file).take().and_then(FileLog::retire);
        let retired = self.file_retired.borrow_mut().take();
        for t in closer.iter().chain(writer.iter()).chain(retired.iter()) {
            crate::syslog::wait_for(t, deadline);
        }
        *self.watch.borrow_mut() = None;
        self.finish_prefs();
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        // VibeServe has no portable mode: it is always installed, so the uninstaller is checked too.
        let installed = true;
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    // ---------- the servers ----------

    fn slot<R>(&self, k: Kind, f: impl FnOnce(&mut Slot) -> R) -> R {
        f(&mut self.slots.borrow_mut()[idx(k)])
    }

    /// The switch: on asks for the server (it starts once its root and the firewall answer),
    /// off stops it.
    pub fn toggle(&self, k: Kind, on: bool) {
        let stopping = self.slot(k, |sl| {
            sl.on = on;
            matches!(sl.phase, Phase::Stopping)
        });
        if on {
            if !stopping {
                self.slot(k, |sl| sl.phase = Phase::Waiting("Starting…"));
                self.advance(k);
            }
        } else {
            self.stop(k);
        }
        self.refresh();
    }

    fn needs_root(k: Kind) -> bool {
        k != Kind::Syslog
    }

    /// Move a server that is on towards running: port, protocols, root, firewall, then the
    /// bind on a worker.
    fn advance(&self, k: Kind) {
        let (on, waiting, port, udp, tcp) = self.slot(k, |sl| (sl.on, matches!(sl.phase, Phase::Waiting(_)), sl.port, sl.udp, sl.tcp));
        if !on || !waiting || self.st.borrow().closing {
            return;
        }
        let Some(port) = port else {
            self.slot(k, |sl| sl.phase = Phase::Failed("The port must be a number from 1 to 65535.".into(), None));
            return;
        };
        if k == Kind::Syslog && !udp && !tcp {
            self.slot(k, |sl| sl.phase = Phase::Failed("Turn on UDP, TCP or both.".into(), None));
            return;
        }
        if Self::needs_root(k) {
            let (open, opening, error) = {
                let r = self.root.borrow();
                (r.open.is_some(), r.opening, r.error.clone())
            };
            if !open {
                if let Some(e) = error.filter(|_| !opening) {
                    self.slot(k, |sl| sl.phase = Phase::Failed(e, None));
                    return;
                }
                self.slot(k, |sl| sl.phase = Phase::Waiting("Opening the root folder…"));
                self.open_root();
                return;
            }
        }
        match self.fw_gate(k) {
            Gate1::Wait(words) => {
                self.slot(k, |sl| sl.phase = Phase::Waiting(words));
                return;
            }
            Gate1::Go => {}
        }
        self.start_now(k, port);
    }

    fn start_now(&self, k: Kind, port: u16) {
        // The card lists the addresses as they are now.
        self.read_adapters();
        let (epoch, key, udp, tcp) = self.slot(k, |sl| {
            sl.epoch += 1;
            sl.phase = Phase::Starting;
            (sl.epoch, sl.bind_key.clone(), sl.udp, sl.tcp)
        });
        // The bind as the card shows it, and as made (the rigs make "all" a loopback one), when
        // the firewall's state allows more than this PC.
        let chosen = self.chosen(&key);
        let ports = ports_for(k, Some(port), udp, tcp);
        let sh = self.sh.clone();
        let report: Arc<dyn Report> = self.inbox.clone();
        let inbox = self.inbox.clone();
        let owners = self.svc.owners.clone();
        let tuning = self.svc.tuning;
        let share = if k == Kind::Tftp { self.tftp_share.clone() } else { self.http_share.clone() };
        let sink: Arc<dyn crate::syslog::Sink> = Arc::new(SyslogSink { inbox: self.inbox.clone(), file: self.file.clone() });
        self.bg(move || {
            if !tuning.start_delay.is_zero() {
                std::thread::sleep(tuning.start_delay);
            }
            // RL7-1: this worker's own bind and ports are judged against the read held now, and
            // the bind is made and its sockets enter the set, all under one lock: a bind beyond
            // this PC that the read does not allow is never made (it is this PC's instead), and
            // nothing reads the set between the bind and its entry.
            let (shown, bind, res) = {
                let mut net = lock(&sh.net);
                let (shown, bind) = if sh.beyond_bind(&chosen.1) && !sh.allows(net.read.as_ref(), &ports) { (PC_ONLY, PC_ONLY) } else { chosen };
                let res = match k {
                    Kind::Tftp => crate::tftp::start(&bind, port, share, tuning.tftp, report).map(Srv::Tftp).map_err(|e| (e, false)),
                    Kind::Http => crate::http::start(&bind, port, share, tuning.http, report).map(Srv::Http).map_err(|e| (e, true)),
                    Kind::Syslog => crate::syslog::start(&bind, port, udp, tcp, tuning.syslog, sink).map(Srv::Syslog).map_err(|(t, e)| (e, t)),
                };
                let res = res.map(|srv| {
                    let id = net.next;
                    net.next += 1;
                    net.open.insert(id, srv.sockets());
                    Live { srv: Some(srv), reg: Some(Reg { sh: sh.clone(), id, inbox: inbox.clone() }) }
                });
                (shown, bind, res)
            };
            if !tuning.bound_delay.is_zero() {
                std::thread::sleep(tuning.bound_delay);
            }
            let res = res.map_err(|(e, is_tcp)| {
                let proto = if k == Kind::Syslog { if is_tcp { "TCP port" } else { "UDP port" } } else { "Port" };
                (bind_words(&e, proto, port, &bind, owners.as_ref(), is_tcp), k == Kind::Http && port == 80 && matches!(e, BindError::InUse | BindError::Reserved))
            });
            Msg::Started { kind: k, epoch, bind: shown, res }
        });
    }

    /// The bind for a key, as the card shows it and as made (the rigs make "all" a loopback
    /// one): what a server binds when the firewall's state allows more than this PC.
    fn chosen(&self, key: &str) -> (Bind, Bind) {
        if key == "all" {
            (Bind::All, self.svc.all_bind.clone())
        } else {
            let b = Bind::from_key(key).unwrap_or(Bind::All);
            (b.clone(), b)
        }
    }

    fn started(&self, k: Kind, epoch: u64, bind: Bind, res: Result<Live, (String, bool)>) {
        let current = self.slot(k, |sl| sl.epoch == epoch && sl.on);
        match res {
            Ok(live) if !current => {
                // Turned off (or changed) while it started: it goes again, off the UI thread.
                self.bg(move || {
                    drop(live);
                    Msg::Closed
                });
            }
            Ok(live) => {
                self.slot(k, |sl| sl.phase = Phase::Running(live, bind));
                self.ticker_on();
                // RL5-2, RL6-1: a read landed between its bind and now (unknown or Public since,
                // or known again): it stops, then starts again on the bind allowed now, one bind
                // of the port at a time, as `fw_read`'s restarts do. Until a socket beyond this
                // PC is closed, the window shows the read before (`Shared::held`).
                if self.open_beyond(k) != self.may_open(k) {
                    self.restart(k);
                }
            }
            Err(_) if !current => {}
            Err((words, offer)) => {
                self.slot(k, |sl| sl.phase = Phase::Failed(words, offer.then_some(8080)));
            }
        }
        self.sync_rules();
    }

    fn stop(&self, k: Kind) {
        let (srv, epoch) = self.slot(k, |sl| match std::mem::replace(&mut sl.phase, Phase::Off) {
            Phase::Running(live, _) => {
                sl.epoch += 1;
                sl.phase = Phase::Stopping;
                (Some(live), sl.epoch)
            }
            // Already on its way down: its answer carries the epoch it has.
            Phase::Stopping => {
                sl.phase = Phase::Stopping;
                (None, sl.epoch)
            }
            // Starting: the new epoch makes the bind's answer drop its server.
            _ => {
                sl.epoch += 1;
                (None, sl.epoch)
            }
        });
        if let Some(live) = srv {
            // Joining the server's threads takes a moment (transfers end, temp files go).
            let delay = self.svc.tuning.stop_delay;
            self.bg(move || {
                let left = live.stop(delay);
                Msg::Stopped { kind: k, epoch, left }
            });
        }
        self.sync_rules();
    }

    fn stopped(&self, k: Kind, epoch: u64, left: usize) {
        if left > 0 {
            self.toast(&left_toast(k, left), ToastKind::Error, None);
        }
        let again = self.slot(k, |sl| {
            if !matches!(sl.phase, Phase::Stopping) || sl.epoch != epoch {
                return false;
            }
            sl.phase = Phase::Off;
            sl.on
        });
        if again {
            self.slot(k, |sl| sl.phase = Phase::Waiting("Starting…"));
            self.advance(k);
        }
    }

    /// A change that needs a new socket (port, address, protocols): a running server restarts.
    fn restart(&self, k: Kind) {
        if !self.slot(k, |sl| sl.on) {
            return;
        }
        if self.slot(k, |sl| matches!(sl.phase, Phase::Running(..) | Phase::Starting)) {
            self.stop(k); // a running one: `stopped` starts it again (it is still on)
        }
        if self.slot(k, |sl| matches!(sl.phase, Phase::Stopping)) {
            return;
        }
        self.slot(k, |sl| sl.phase = Phase::Waiting("Starting…"));
        self.advance(k);
    }

    fn port_edited(&self, k: Kind, t: &str) {
        self.slot(k, |sl| sl.port_text = t.to_string());
        self.refresh();
    }

    fn port_commit(&self, k: Kind, t: &str) {
        let p = crate::view::parse_port(t);
        let changed = self.slot(k, |sl| {
            sl.port_text = t.trim().to_string();
            let changed = p.is_some() && p != sl.port;
            if p.is_some() {
                sl.port = p;
            }
            changed
        });
        if let Some(port) = p.filter(|_| changed) {
            self.save_prefs(move |pr| pr.server_mut(k).port = port);
            self.restart(k);
        }
        self.refresh();
    }

    fn port_blurred(&self, k: Kind) {
        let t = self.slot(k, |sl| sl.port_text.clone());
        self.port_commit(k, &t);
    }

    /// Escape in a port field: the committed port back; nothing to put back passes it on.
    fn port_escaped(&self, k: Kind) -> bool {
        let used = self.slot(k, |sl| {
            let committed = sl.port.map(|p| p.to_string()).unwrap_or_default();
            if sl.port_text != committed {
                sl.port_text = committed;
                true
            } else {
                false
            }
        });
        if used {
            self.refresh();
        }
        used
    }

    fn bind_picked(&self, k: Kind, i: i32) {
        let key = self.st.borrow().bind_keys[idx(k)].get(i.max(0) as usize).cloned();
        let Some(key) = key else { return };
        let changed = self.slot(k, |sl| {
            let c = sl.bind_key != key;
            sl.bind_key = key.clone();
            c
        });
        if changed {
            let kk = key.clone();
            self.save_prefs(move |p| p.server_mut(k).bind = kk.clone());
            self.restart(k);
        }
        self.refresh();
    }

    fn writes_toggled(&self, k: Kind, v: bool) {
        self.slot(k, |sl| sl.writes = v);
        let share = if k == Kind::Tftp { &self.tftp_share } else { &self.http_share };
        share.writes.store(v, Ordering::SeqCst);
        self.refresh();
    }

    fn proto_toggled(&self, tcp: bool, v: bool) {
        self.slot(Kind::Syslog, |sl| if tcp { sl.tcp = v } else { sl.udp = v });
        let (u, t) = self.slot(Kind::Syslog, |sl| (sl.udp, sl.tcp));
        if u || t {
            self.save_prefs(move |p| {
                p.syslog_udp = u;
                p.syslog_tcp = t;
            });
        }
        self.restart(Kind::Syslog);
        self.refresh();
    }

    /// The card's button: the other port offered (HTTP: 8080 when 80 is taken).
    fn card_action(&self, k: Kind) {
        let alt = self.slot(k, |sl| if let Phase::Failed(_, Some(p)) = sl.phase { Some(p) } else { None });
        if let Some(p) = alt {
            self.port_commit(k, &p.to_string());
        }
    }

    // ---------- the root folder ----------

    fn open_root(&self) {
        let (path, create, epoch) = {
            let mut r = self.root.borrow_mut();
            if r.opening {
                return;
            }
            r.opening = true;
            r.epoch += 1;
            (r.path.clone(), r.is_default, r.epoch)
        };
        // This user's profile and every other one Windows lists (RIN1-1): none of them, and no
        // folder that holds one, is ever the root.
        let mut profiles = vec![self.svc.paths.profile.clone()];
        profiles.extend(self.svc.paths.others.iter().cloned());
        self.bg(move || {
            // A file named as the root means its folder (the one normaliser for input).
            let target = if path.is_file() { path.parent().map(Path::to_path_buf).unwrap_or(path) } else { path };
            let res = Root::open(&target, create, &profiles).map(|r| (Arc::new(r), target));
            Msg::RootOpened { epoch, res }
        });
    }

    fn root_opened(&self, epoch: u64, res: Result<(Arc<Root>, PathBuf), String>) {
        {
            let mut r = self.root.borrow_mut();
            if r.epoch != epoch {
                return;
            }
            r.opening = false;
            match &res {
                Ok((root, _)) => {
                    r.open = Some(root.clone());
                    r.error = None;
                }
                Err(e) => {
                    r.open = None;
                    r.error = Some(e.clone());
                }
            }
        }
        let open = self.root.borrow().open.clone();
        self.tftp_share.set_root(open.clone());
        self.http_share.set_root(open);
        if let Err(e) = &res {
            let busy = KINDS.iter().any(|&k| Self::needs_root(k) && self.slot(k, |sl| sl.live()));
            if busy {
                self.toast(e, ToastKind::Error, None);
            }
        }
        for k in [Kind::Tftp, Kind::Http] {
            self.advance(k);
        }
    }

    /// The root field's text, as committed: quotes and spaces trimmed; empty means the default.
    fn commit_root(&self, t: &str) {
        let t = t.trim().trim_matches('"').trim();
        let path = if t.is_empty() { self.svc.paths.default_root.clone() } else { PathBuf::from(t) };
        // "foo" or "." would be served from wherever the app was started: refused.
        if !path.is_absolute() {
            let now = self.root.borrow().path.clone();
            if let Some(ui) = self.ui() {
                ui.set_root_text(s(crate::text::clean_path(&now)));
            }
            self.toast(&format!("Type a full path, like C:\\Firmware, not \"{}\": the root folder stays as it was.", crate::text::clean_max(t, 200)), ToastKind::Error, None);
            return;
        }
        self.set_root(path);
    }

    fn set_root(&self, path: PathBuf) {
        let is_default = path == self.svc.paths.default_root;
        let changed = {
            let mut r = self.root.borrow_mut();
            let changed = r.path != path;
            if changed {
                r.path = path.clone();
                r.is_default = is_default;
                r.open = None;
                r.error = None;
                r.opening = false;
                r.epoch += 1;
            }
            changed
        };
        if let Some(ui) = self.ui() {
            ui.set_root_text(s(crate::text::clean_path(&path)));
        }
        if !changed {
            return;
        }
        let saved = if is_default { Some(None) } else { path.to_str().map(|p| Some(p.to_string())) };
        match saved {
            Some(v) => self.save_prefs(move |p| p.root = v.clone()),
            None => self.toast("This folder's name cannot be remembered (it is not valid Unicode): it is used now, and the default next time.", ToastKind::Info, None),
        }
        let busy = KINDS.iter().any(|&k| Self::needs_root(k) && self.slot(k, |sl| sl.on));
        if busy {
            // Served from the new root as soon as it is open; until then requests are refused.
            self.tftp_share.set_root(None);
            self.http_share.set_root(None);
            self.open_root();
        }
        self.refresh();
    }

    fn root_escaped(&self) -> bool {
        let Some(ui) = self.ui() else { return false };
        let shown = s(crate::text::clean_path(&self.root.borrow().path));
        if ui.get_root_text() != shown {
            ui.set_root_text(shown);
            return true;
        }
        false
    }

    /// Leaving the field without Enter puts the committed root back (typing is not choosing).
    fn root_blurred(&self) {
        if let Some(ui) = self.ui() {
            ui.set_root_text(s(crate::text::clean_path(&self.root.borrow().path)));
        }
    }

    /// Explorer on the root (as named: nothing is asked of the file system on this thread).
    fn open_root_folder(&self) {
        let p = self.root.borrow().path.clone();
        (self.svc.open_folder)(&p);
    }

    fn pick(&self, root: bool) {
        let start = if root { Some(self.root.borrow().path.clone()) } else { Some(self.log_folder()) };
        let inbox = self.inbox.clone();
        let title = if root { "Root folder for TFTP and HTTP" } else { "Folder for the syslog files" };
        (self.svc.pick_folder)((self.svc.hwnd)(), title, start, Box::new(move |path| inbox.push(Msg::Picked { root, path })));
    }

    // ---------- the firewall ----------

    fn read_firewall(&self) {
        let epoch = {
            let mut f = self.fw.borrow_mut();
            f.reading = true;
            f.read_epoch += 1;
            f.read_epoch
        };
        let gate = self.svc.gate.clone();
        self.bg(move || Msg::FwRead { epoch, res: gate.read() });
    }

    fn fw_read(&self, epoch: u64, res: FwRead) {
        let stale = {
            let mut f = self.fw.borrow_mut();
            if f.read_epoch != epoch {
                return;
            }
            f.reading = false;
            let stale = match &res {
                Ok((_, rules)) if !f.stale_done => rules.iter().filter(|r| crate::firewall::stale(r, &crate::firewall::alive)).count(),
                _ => 0,
            };
            f.stale_done = true;
            stale
        };
        {
            // RL7-1: from here on every bind is judged on this read. While a server's socket is
            // beyond what the read before allowed, the window still shows the one before that
            // (`prev` stays); else the read it showed until now (a stopped server's left
            // thread holds none of it, RL9-2: `Shared::stuck`).
            let mut net = lock(&self.sh.net);
            if !self.sh.held(&net) {
                net.prev = net.read.take();
            }
            net.read = Some(res);
        }
        if stale > 0 {
            // A rule a crashed VibeServe left: removed now, one Windows prompt.
            self.toast(&format!("{} left a firewall rule behind when it closed. Removing it (Windows asks).", if stale == 1 { "An earlier VibeServe" } else { "Earlier VibeServes" }), ToastKind::Info, None);
            let gate = self.svc.gate.clone();
            let hwnd = (self.svc.hwnd)();
            self.bg(move || Msg::FwCleaned(gate.open(hwnd, &Request::clean()).map(|(s, r)| {
                drop(s);
                r
            })));
        }
        // RIN1-3: a server started for this PC only while no Private network was active (or
        // for the network while one was) starts again on the bind the network allows now.
        // RF1-3: a read that failed is no Private network either, so a server on the network
        // goes back to this PC only, and one read that succeeds opens it again.
        // A server still starting is checked the same way once it is up (`started`, RL5-2).
        for k in KINDS {
            if self.slot(k, |sl| sl.running()) && self.open_beyond(k) != self.may_open(k) {
                self.restart(k);
            }
        }
        self.advance_all();
    }

    fn fw_cleaned(&self, res: Result<Reply, Launch>) {
        match res {
            Ok(r) => self.toast(&format!("Removed {} leftover firewall rule{}.", r.stale, if r.stale == 1 { "" } else { "s" }), ToastKind::Ok, None),
            Err(Launch::Declined) => self.toast("The leftover firewall rule stays: it lets only VibeServe in, from your local subnet, and nothing listens while it is closed. It goes when you allow a rule next time.", ToastKind::Info, None),
            Err(Launch::Failed(e)) => self.toast(&format!("The leftover firewall rule could not be removed: {e}"), ToastKind::Error, None),
        }
        self.read_firewall_again();
    }

    fn read_firewall_again(&self) {
        let reading = self.fw.borrow().reading;
        if !reading {
            self.read_firewall();
        }
    }

    /// The (protocol, port) pairs a server listens on.
    fn ports_of(&self, k: Kind) -> Vec<(bool, u16)> {
        self.slot(k, |sl| ports_for(k, sl.port, sl.udp, sl.tcp))
    }

    fn need(&self, k: Kind) -> Need {
        self.need_on(k, false)
    }

    /// What the window shows: `need` on the read it shows (`Shared::shown`).
    fn need_shown(&self, k: Kind) -> Need {
        self.need_on(k, true)
    }

    fn need_on(&self, k: Kind, shown: bool) -> Need {
        let key = self.slot(k, |sl| sl.bind_key.clone());
        if !self.sh.beyond_bind(&self.chosen(&key).1) {
            return Need::Nothing;
        }
        let ports = self.ports_of(k);
        self.read_with(shown, |r| need_of(r, &self.sh.exe, &ports))
    }

    /// `f` on the newest read, or on the one the window shows (RL7-1). It runs under `Net`'s
    /// lock: it must not take it again.
    fn read_with<R>(&self, shown: bool, f: impl FnOnce(Option<&FwRead>) -> R) -> R {
        let net = lock(&self.sh.net);
        f(if shown { self.sh.shown(&net) } else { net.read.as_ref() })
    }

    /// RL7-1: the running server's sockets, as bound, include one beyond this PC (from the
    /// set, never from the settings).
    fn open_beyond(&self, k: Kind) -> bool {
        let Some(id) = self.slot(k, |sl| if let Phase::Running(l, _) = &sl.phase { l.id() } else { None }) else { return false };
        let net = lock(&self.sh.net);
        net.open.get(&id).is_some_and(|v| v.iter().any(|(_, a)| self.sh.beyond(a.ip())))
    }

    /// A bind of this server's settings made now would be beyond this PC: its address is, and
    /// the newest read allows its ports there. Else it is `PC_ONLY` while no Private network is
    /// active (RIN1-3) and while the firewall's state is not read or could not be read (RF1-3):
    /// unknown is not Private, and a firewall that cannot be read is often one whose service is
    /// stopped, which blocks nothing. The worker judges its own bind the same way (`start_now`).
    fn may_open(&self, k: Kind) -> bool {
        let key = self.slot(k, |sl| sl.bind_key.clone());
        let ports = self.ports_of(k);
        self.sh.beyond_bind(&self.chosen(&key).1) && self.read_with(false, |r| self.sh.allows(r, &ports))
    }

    /// The rules the helper should hold now: every live server that needs one.
    fn wants(&self) -> Vec<Want> {
        let mut v = Vec::new();
        for k in KINDS {
            if !self.slot(k, |sl| sl.live()) || self.need(k) != Need::Rule {
                continue;
            }
            let purpose = match k {
                Kind::Tftp => Purpose::Tftp,
                Kind::Syslog => Purpose::Syslog,
                Kind::Http => Purpose::Http,
            };
            for (tcp, port) in self.ports_of(k) {
                if !v.iter().any(|w: &Want| w.tcp == tcp && w.port == port) {
                    v.push(Want { purpose, tcp, port });
                }
            }
        }
        v
    }

    fn session_alive(&self) -> bool {
        let s = self.fw.borrow().session.clone();
        match s {
            None => false,
            Some(s) => match s.try_lock() {
                Ok(g) => g.as_ref().is_some_and(|x| x.alive()),
                Err(_) => true, // busy answering: alive
            },
        }
    }

    fn fw_gate(&self, k: Kind) -> Gate1 {
        match self.need(k) {
            Need::Reading => Gate1::Wait("Checking Windows Firewall…"),
            Need::Nothing | Need::ReadFailed(_) | Need::Off | Need::BlockAll | Need::Covered | Need::Public => Gate1::Go,
            Need::Rule => {
                let (declined, failed, launching, asking, syncing, lost) = {
                    let f = self.fw.borrow();
                    (f.declined, f.failed.is_some(), f.launching, f.asking, f.syncing, f.lost)
                };
                if self.fw.borrow().session.is_some() {
                    if !self.session_alive() {
                        self.helper_gone();
                        return Gate1::Go;
                    }
                    let mine: Vec<(bool, u16)> = self.ports_of(k);
                    let held = self.fw.borrow().held.clone();
                    if mine.iter().all(|(t, p)| held.iter().any(|w| w.tcp == *t && w.port == *p)) {
                        return Gate1::Go;
                    }
                    if !syncing {
                        self.sync_rules_with(self.wants());
                    }
                    return Gate1::Wait("Adding the firewall rule…");
                }
                if declined || failed || lost {
                    return Gate1::Go;
                }
                if launching {
                    return Gate1::Wait("Waiting for Windows' prompt…");
                }
                if !asking {
                    self.open_consent();
                }
                Gate1::Wait("Waiting for your answer…")
            }
        }
    }

    fn advance_all(&self) {
        for k in KINDS {
            self.advance(k);
        }
        self.sync_rules();
        self.refresh();
    }

    fn open_consent(&self) {
        {
            let mut f = self.fw.borrow_mut();
            f.asking = true;
            // Off unless the user ticks it (as in VibePerf): a block rule may be someone's
            // deliberate choice. The dialog still offers it when block rules exist.
            f.remove_blocks = false;
        }
        self.show_consent();
    }

    fn show_consent(&self) {
        let Some(ui) = self.ui() else { return };
        let (asking, remove_blocks) = {
            let f = self.fw.borrow();
            (f.asking, f.remove_blocks)
        };
        let wants = self.wants();
        if asking && wants.is_empty() {
            // The server that asked was turned off meanwhile: the question goes (not a "no").
            self.fw.borrow_mut().asking = false;
        }
        if !asking || wants.is_empty() {
            ui.set_consent_open(false);
            return;
        }
        let what: Vec<String> = wants.iter().map(|w| format!("{} {}", if w.tcp { "TCP" } else { "UDP" }, w.port)).collect();
        let exe = &self.sh.exe;
        let blocks = self.read_with(false, |r| match r {
            Some(Ok((_, rules))) => rules.iter().filter(|r| crate::firewall::blocks_this_exe(r, exe)).count(),
            _ => 0,
        });
        let profiles = self.read_with(false, |r| match r {
            Some(Ok((st, _))) if !st.profiles.is_empty() => format!(" ({} network)", st.profiles),
            _ => String::new(),
        });
        ui.set_consent(ConsentView {
            title: s("Let devices on your network reach VibeServe?"),
            body: s(format!(
                "Windows Firewall{profiles} keeps other devices from reaching VibeServe. One Windows prompt adds a rule that lets in {} from your local subnet, on Private networks only, to this program only. VibeServe removes it when the server stops or the window closes. The servers themselves need no admin rights, even on ports below 1024: only this rule does.",
                if what.is_empty() { "its servers".to_string() } else { what.join(", ") }
            )),
            blocks: if blocks > 0 { s(format!("Also remove Windows' {blocks} block rule{} for VibeServe", if blocks == 1 { "" } else { "s" })) } else { s("") },
            blocks_note: s(if blocks > 0 { "Windows made it when its own prompt for VibeServe was dismissed. A block rule beats any allow rule." } else { "" }),
            remove_blocks,
            allow: s("Allow (Windows asks)"),
            cancel: s("Not now"),
        });
        ui.set_consent_open(true);
    }

    fn consent_blocks(&self, v: bool) {
        self.fw.borrow_mut().remove_blocks = v;
        self.show_consent();
    }

    fn consent_cancel(&self) {
        {
            let mut f = self.fw.borrow_mut();
            f.asking = false;
            f.declined = true;
        }
        if let Some(ui) = self.ui() {
            ui.set_consent_open(false);
        }
        self.advance_all();
    }

    fn consent_allow(&self) {
        let (remove_blocks, epoch) = {
            let mut f = self.fw.borrow_mut();
            f.asking = false;
            f.launching = true;
            f.declined = false;
            f.failed = None;
            f.lost = false;
            f.epoch += 1;
            (f.remove_blocks, f.epoch)
        };
        if let Some(ui) = self.ui() {
            ui.set_consent_open(false);
        }
        let wants = self.wants();
        let gate = self.svc.gate.clone();
        let hwnd = (self.svc.hwnd)();
        let w2 = wants.clone();
        self.bg(move || Msg::FwOpened { epoch, wants: w2.clone(), res: gate.open(hwnd, &Request::set(w2, remove_blocks)) });
        self.refresh();
    }

    fn fw_opened(&self, epoch: u64, wants: Vec<Want>, res: Result<(Box<dyn GateSession>, Reply), Launch>) {
        if self.fw.borrow().epoch != epoch {
            if let Ok((s, _)) = res {
                std::thread::spawn(move || {
                    let _ = s.close();
                });
            }
            return;
        }
        self.fw.borrow_mut().launching = false;
        match res {
            Ok((sess, reply)) => {
                {
                    let mut f = self.fw.borrow_mut();
                    f.session = Some(Arc::new(Mutex::new(Some(sess))));
                    f.held = wants;
                }
                if reply.blocks > 0 {
                    self.toast(&format!("Removed {} Windows block rule{} for VibeServe.", reply.blocks, if reply.blocks == 1 { "" } else { "s" }), ToastKind::Ok, None);
                }
                // The rules changed (ours added, block rules gone): read them again.
                self.read_firewall_again();
            }
            Err(Launch::Declined) => {
                self.fw.borrow_mut().declined = true;
            }
            Err(Launch::Failed(e)) => {
                self.fw.borrow_mut().failed = Some(e.clone());
                self.toast(&format!("The firewall rule was not added: {e}"), ToastKind::Error, None);
            }
        }
        self.advance_all();
    }

    /// Send the helper the rules wanted now, when they differ from what it holds.
    fn sync_rules(&self) {
        if self.fw.borrow().session.is_none() || self.st.borrow().closing {
            return;
        }
        let wants = self.wants();
        let differs = {
            let f = self.fw.borrow();
            let mut a = f.held.clone();
            let mut b = wants.clone();
            a.sort_by_key(|w| (w.tcp, w.port));
            b.sort_by_key(|w| (w.tcp, w.port));
            a != b
        };
        if differs && !self.fw.borrow().syncing {
            self.sync_rules_with(wants);
        }
    }

    fn sync_rules_with(&self, wants: Vec<Want>) {
        let Some(sess) = self.fw.borrow().session.clone() else { return };
        let seq = {
            let mut f = self.fw.borrow_mut();
            f.sync_seq += 1;
            f.syncing = true;
            f.sync_seq
        };
        let w2 = wants.clone();
        self.bg(move || {
            let res = match lock(&sess).as_ref() {
                Some(s) => s.send(&Request::set(w2.clone(), false)),
                None => Err("the helper is gone".into()),
            };
            Msg::FwReply { seq, wants: w2, res }
        });
    }

    fn fw_reply(&self, seq: u64, wants: Vec<Want>, res: Result<Reply, String>) {
        let newest = {
            let mut f = self.fw.borrow_mut();
            let newest = f.sync_seq == seq;
            if newest {
                f.syncing = false;
            }
            newest
        };
        match res {
            Ok(r) if r.ok => {
                if newest {
                    self.fw.borrow_mut().held = wants;
                }
            }
            Ok(r) => {
                self.toast(&format!("Windows Firewall did not take the change: {}", r.error), ToastKind::Error, None);
            }
            Err(_) => self.helper_gone(),
        }
        self.advance_all();
    }

    /// The helper ended under us (killed from outside, or its 24 h limit): its rules are gone.
    fn helper_gone(&self) {
        let had = self.fw.borrow_mut().session.take().is_some();
        if had {
            {
                let mut f = self.fw.borrow_mut();
                f.held.clear();
                f.lost = true;
                f.syncing = false;
            }
            self.toast("The firewall helper ended, and its rule with it: other devices may be blocked again. Click the firewall state to allow again.", ToastKind::Error, None);
        }
    }

    fn firewall_clicked(&self) {
        let read_failed = self.read_with(false, |r| matches!(r, Some(Err(_))));
        if read_failed {
            self.read_firewall();
            return;
        }
        let needed = KINDS.iter().any(|&k| self.slot(k, |sl| sl.live()) && self.need(k) == Need::Rule);
        let (session, launching) = {
            let f = self.fw.borrow();
            (f.session.is_some(), f.launching)
        };
        if needed && !session && !launching {
            self.open_consent();
        }
    }

    // ---------- the syslog view ----------

    fn model(&self) -> Rc<SyslogModel> {
        self.syslog.borrow().model.clone()
    }

    fn apply_filter(&self) {
        let f = {
            let sy = self.syslog.borrow();
            Filter { text: sy.filter_text.trim().to_lowercase(), max_severity: sy.severity, source: sy.source }
        };
        let model = self.model();
        let before = model.store.borrow().len();
        let c = model.store.borrow_mut().set_filter(f);
        model.changed(before, c);
        self.syslog.borrow_mut().dirty = true;
        self.refresh();
    }

    /// Typing in the filter: applied 150 ms after the last key (a 100 000-row scan per key would
    /// lag).
    fn filter_edited(&self, t: &str) {
        let seq = {
            let mut sy = self.syslog.borrow_mut();
            sy.filter_text = t.to_string();
            sy.filter_seq += 1;
            sy.filter_seq
        };
        let w = self.weak();
        Timer::single_shot(Duration::from_millis(150), move || {
            if let Some(a) = w.upgrade()
                && a.syslog.borrow().filter_seq == seq
            {
                a.apply_filter();
            }
        });
    }

    fn filter_escaped(&self) -> bool {
        let had = !self.syslog.borrow().filter_text.is_empty();
        if had {
            self.syslog.borrow_mut().filter_text.clear();
            if let Some(ui) = self.ui() {
                ui.set_filter_text(s(""));
            }
            self.apply_filter();
        }
        had
    }

    fn severity_picked(&self, i: i32) {
        self.syslog.borrow_mut().severity = crate::view::severity_of_index(i.max(0) as usize);
        self.apply_filter();
    }

    fn source_picked(&self, i: i32) {
        let src = self.syslog.borrow().sources_shown.get(i.max(0) as usize).cloned().flatten();
        self.syslog.borrow_mut().source = src;
        self.apply_filter();
    }

    fn pause_toggled(&self) {
        let model = self.model();
        let on = !model.store.borrow().paused();
        let before = model.store.borrow().len();
        let c = model.store.borrow_mut().set_paused(on);
        model.changed(before, c);
        self.syslog.borrow_mut().dirty = true;
        self.refresh();
    }

    fn clear_syslog(&self) {
        let model = self.model();
        let before = model.store.borrow().len();
        let c = model.store.borrow_mut().clear();
        model.selected.set(None);
        model.changed(before, c);
        self.syslog.borrow_mut().dirty = true;
        self.refresh();
    }

    fn select_row(&self, i: usize) {
        let model = self.model();
        let seq = model.store.borrow().row(i).map(|(s, _)| s);
        model.selected.set(seq);
        model.notify.reset();
        self.refresh();
    }

    /// Up/Down/Home/End over the rows (the selection moves, and comes into view).
    fn syslog_key(&self, d: i32) {
        let model = self.model();
        let n = model.store.borrow().len();
        if n == 0 {
            return;
        }
        let cur = model.selected.get().and_then(|s| model.store.borrow().position(s));
        let next = match (d, cur) {
            (-2, _) => 0,
            (2, _) => n - 1,
            (-1, Some(c)) => c.saturating_sub(1),
            (1, Some(c)) => (c + 1).min(n - 1),
            (_, None) => 0,
            _ => return,
        };
        self.select_row(next);
        if let Some(ui) = self.ui() {
            ui.set_syslog_scroll_to(next as i32);
            ui.set_syslog_scroll_seq(ui.get_syslog_scroll_seq() + 1);
        }
    }

    fn copy_detail(&self) -> bool {
        let model = self.model();
        let text = model.selected.get().and_then(|s| model.store.borrow().get(s).map(crate::view::detail_text));
        text.is_some_and(|t| (self.svc.copy)(&t))
    }

    fn copy_log(&self, k: i32) -> bool {
        let i = if k == 0 { 0 } else { 1 };
        let text = crate::activity::as_text(&self.logs[i].log.borrow());
        (self.svc.copy)(&text)
    }

    fn clear_log(&self, k: i32) {
        let i = if k == 0 { 0 } else { 1 };
        self.logs[i].log.borrow_mut().clear();
        self.logs[i].notify.reset();
        self.refresh();
    }

    fn tab_picked(&self, i: i32) {
        let t = i.clamp(0, 2);
        if let Some(ui) = self.ui() {
            ui.set_tab(t);
        }
        self.save_prefs(move |p| p.tab = t as u8);
        self.refresh();
    }

    // ---------- the log file ----------

    fn log_folder(&self) -> PathBuf {
        self.syslog.borrow().folder.clone().unwrap_or_else(|| self.svc.paths.local_data.join("syslog"))
    }

    /// On, off, or a new folder. The writer let go is never waited for here: it writes out its
    /// (bounded) queue on its own, and the next writer waits for it, at most 2 s, on its thread.
    fn set_log_to_file(&self, on: bool, save: bool) {
        self.syslog.borrow_mut().log_to_file = on;
        let old = lock(&self.file).take().and_then(FileLog::retire);
        let before = match old {
            Some(t) => Some(t),
            None => self.file_retired.borrow_mut().take(),
        };
        self.syslog.borrow_mut().behind_told = false;
        if on {
            let folder = self.log_folder();
            if save {
                self.warn_log_folder(&folder);
            }
            let inbox = self.inbox.clone();
            *lock(&self.file) = Some(FileLog::start_after(folder, self.svc.tuning.file, Box::new(move |s| inbox.push(Msg::File(s))), before));
        } else {
            *self.file_retired.borrow_mut() = before;
            self.syslog.borrow_mut().file_state = FileState::Off;
        }
        if save {
            self.save_prefs(move |p| p.log_to_file = on);
        }
        self.refresh();
    }

    /// SEC-Serve-2: a log folder off the fixed local drives (a share, a stick) is said plainly.
    fn warn_log_folder(&self, folder: &Path) {
        if !crate::dialogs::local_fixed(folder) {
            self.toast(&format!("The log folder {} is not on a fixed local drive: syslog messages can carry passwords and configurations, and anyone who can open that folder can read them.", crate::text::clean_path(folder)), ToastKind::Info, None);
        }
    }

    fn set_log_folder(&self, p: PathBuf) {
        self.warn_log_folder(&p);
        let default = p == self.svc.paths.local_data.join("syslog");
        self.syslog.borrow_mut().folder = if default { None } else { Some(p.clone()) };
        let v = if default { Some(None) } else { p.to_str().map(|t| Some(t.to_string())) };
        if let Some(v) = v {
            self.save_prefs(move |pr| pr.log_folder = v.clone());
        }
        if self.syslog.borrow().log_to_file {
            self.set_log_to_file(true, false);
        }
        self.refresh();
    }

    /// The log file fell behind the stream: said once per writer (the status line keeps the
    /// count).
    fn tell_behind(&self) {
        // Lines lost with a failed write are counted too, but that failure has its own toast.
        let fell_behind = lock(&self.file).as_ref().is_some_and(|f| f.fell_behind());
        if !fell_behind || self.syslog.borrow().behind_told {
            return;
        }
        self.syslog.borrow_mut().behind_told = true;
        self.toast("The log file cannot keep up with the messages coming in: lines it could not take are not written (the status line counts them). The window still shows every message.", ToastKind::Error, None);
    }

    fn file_state(&self, fs: FileState) {
        let toast = match &fs {
            FileState::DayFull(p) => Some((format!("Today's syslog file reached 1 GiB: logging to file is paused until tomorrow ({}). The window still shows every message.", crate::text::clean_path(p)), ToastKind::Error)),
            FileState::DiskLow => Some(("Log file paused: disk nearly full (less than 1 GiB free). It goes on by itself when there is room; the window still shows every message.".to_string(), ToastKind::Error)),
            FileState::Failed(e) => Some((format!("The syslog file could not be written: {e}"), ToastKind::Error)),
            _ => None,
        };
        self.syslog.borrow_mut().file_state = fs;
        if let Some((t, k)) = toast {
            self.toast(&t, k, None);
        }
    }

    /// At start, in the app's own syslog folder only: daily files older than 30 days go.
    fn prune_logs(&self) {
        let folder = self.svc.paths.local_data.join("syslog");
        let c = crate::host::local_clock(crate::host::now_filetime());
        let today = crate::syslog::days_from_civil(c.year as i64, c.month as u32, c.day as u32);
        self.bg(move || {
            let (_gone, failed) = crate::syslog::prune(&folder, today);
            Msg::Pruned(failed)
        });
    }

    // ---------- Save view ----------

    fn save_view(&self) {
        let c = crate::host::local_clock(crate::host::now_filetime());
        let name = format!("syslog-view-{}-{:02}{:02}.csv", c.date(), c.hour, c.minute);
        let inbox = self.inbox.clone();
        (self.svc.save_as)((self.svc.hwnd)(), name, Box::new(move |choice| inbox.push(Msg::SaveTo(choice))));
    }

    fn save_to(&self, choice: Option<(PathBuf, bool)>) {
        let Some((path, csv)) = choice else { return };
        let model = self.model();
        // A copy of the rows shown now; 100 000 of them are formatted on the worker.
        let rows: Vec<Message> = model.store.borrow().shown().into_iter().cloned().collect();
        let locale = self.svc.locale;
        self.bg(move || {
            let refs: Vec<&Message> = rows.iter().collect();
            let body = if csv { crate::export::csv(&refs, locale) } else { crate::export::text(&refs) };
            Msg::Saved(crate::prefs::write_atomic(&path, body.as_bytes()).map(|_| (path, rows.len())).map_err(|e| e.to_string()))
        });
    }

    // ---------- adapters ----------

    fn read_adapters(&self) {
        let f = self.svc.adapters.clone();
        self.bg(move || Msg::Adapters(f()));
    }

    // ---------- the tick ----------

    fn ticker_on(&self) {
        if self.ticker.running() {
            return;
        }
        let w = self.weak();
        self.ticker.start(TimerMode::Repeated, Duration::from_millis(500), move || {
            let Some(a) = w.upgrade() else { return };
            let any = a.slots.borrow().iter().any(|s| s.running());
            if !any {
                a.ticker.stop();
            }
            if a.fw.borrow().session.is_some() && !a.session_alive() {
                a.helper_gone();
            }
            a.refresh();
        });
    }

    // ---------- the view ----------

    /// Everything the window shows, from the state as it is now.
    pub fn refresh(&self) {
        let Some(ui) = self.ui() else { return };
        if self.st.borrow().closing {
            return;
        }
        self.show_cards(&ui);
        self.show_syslog(&ui);
        self.show_logs(&ui);
        self.show_firewall(&ui);
        self.show_status(&ui);
        self.show_consent();
    }

    /// "This network is not Private (Public)": the profiles Windows names, Domain included
    /// (RIN1-7).
    fn not_private(&self) -> String {
        self.read_with(true, |r| match r {
            Some(Ok((st, _))) if !st.profiles.is_empty() => format!("This network is not Private ({})", st.profiles),
            _ => "This network is not Private".into(),
        })
    }

    fn fw_note(&self, k: Kind) -> (String, i32) {
        if !self.slot(k, |sl| sl.live()) {
            return (String::new(), 0);
        }
        let (session, settled) = {
            let f = self.fw.borrow();
            (f.session.is_some(), f.declined || f.failed.is_some() || f.lost)
        };
        match self.need_shown(k) {
            Need::BlockAll => ("Windows Firewall blocks all incoming connections on this network: other devices cannot connect (Windows Security, Firewall).".into(), 3),
            Need::ReadFailed(_) => ("Windows Firewall's state could not be read, so it listens on this PC only until it can be: VibeServe shares on Private networks only.".into(), 3),
            Need::Public => (format!("{}, so it listens on this PC only: VibeServe shares on Private networks only.", self.not_private()), 3),
            // Not while the question is open: only once it was answered without a rule.
            Need::Rule if !session && settled => ("Other devices may be blocked by Windows Firewall.".into(), 2),
            _ => (String::new(), 0),
        }
    }

    fn show_cards(&self, ui: &AppWindow) {
        let (adapters, adapters_error, addrs_open) = {
            let st = self.st.borrow();
            (st.adapters.clone(), st.adapters_error.clone(), st.addrs_open)
        };
        for k in KINDS {
            let i = idx(k);
            let (lines, keys, sel) = {
                let key = self.slot(k, |sl| sl.bind_key.clone());
                crate::view::bind_options(&adapters, &key)
            };
            self.st.borrow_mut().bind_keys[i] = keys;
            set_strings(&self.models.binds[i], &lines);
            let (note, note_kind) = self.fw_note(k);
            let (card, addrs) = self.slot(k, |sl| {
                let (state, kind, action, addrs) = match &sl.phase {
                    Phase::Off => (String::new(), 0, String::new(), Vec::new()),
                    Phase::Waiting(w) => (w.to_string(), 0, String::new(), Vec::new()),
                    Phase::Starting => ("Starting…".into(), 0, String::new(), Vec::new()),
                    Phase::Stopping => ("Stopping…".into(), 0, String::new(), Vec::new()),
                    Phase::Failed(w, alt) => (w.clone(), 3, alt.map(|p| format!("Use {p}")).unwrap_or_default(), Vec::new()),
                    Phase::Running(_, bind) => {
                        let port = sl.port.unwrap_or(0);
                        let lines = crate::view::listen_lines(k, bind, port, &adapters);
                        let mut st = crate::view::listening(bind, lines.len());
                        if matches!(bind, Bind::All) && lines.is_empty() {
                            st = if adapters_error.is_some() { "Listening on all addresses (the adapters could not be read)".into() } else { "Listening on all addresses (no network adapter is up)".into() };
                        }
                        (st, 1, String::new(), crate::view::fold_lines(lines, addrs_open[i]))
                    }
                };
                let card = CardView {
                    on: sl.on,
                    title: s(crate::view::title(k)),
                    proto: s(crate::view::proto(k, sl.udp, sl.tcp)),
                    port: s(&sl.port_text),
                    port_invalid: crate::view::parse_port(&sl.port_text).is_none(),
                    bind: sel as i32,
                    writes: sl.writes,
                    udp: sl.udp,
                    tcp: sl.tcp,
                    state: s(state),
                    state_kind: kind,
                    action: s(action),
                    note: s(&note),
                    note_kind,
                };
                (card, addrs)
            });
            set_rows(&self.models.addrs[i], addrs);
            match k {
                Kind::Tftp => ui.set_tftp(card),
                Kind::Syslog => ui.set_syslog(card),
                Kind::Http => ui.set_http(card),
            }
        }
        // TFTP's transfers underway.
        let rows: Vec<TransferRow> = self.slot(Kind::Tftp, |sl| match &sl.phase {
            Phase::Running(Live { srv: Some(Srv::Tftp(t)), .. }, _) => lock(&t.live)
                .iter()
                .map(|l| crate::view::transfer_row(&l.file, &l.peer.to_string(), l.write, l.bytes.load(Ordering::Relaxed), l.total.load(Ordering::Relaxed), l.started.elapsed().as_secs_f64()))
                .collect(),
            _ => Vec::new(),
        });
        set_rows(&self.models.transfers, rows);
    }

    fn show_syslog(&self, ui: &AppWindow) {
        let model = self.model();
        let st = model.store.borrow();
        let (sev, dirty) = {
            let sy = self.syslog.borrow();
            (sy.severity, sy.dirty)
        };
        // The sources picker: rebuilt only when messages or the choice changed.
        let chosen = self.syslog.borrow().source;
        if dirty {
            let (lines, keys) = crate::view::source_lines(st.sources(), chosen, crate::view::MAX_SOURCES);
            set_strings(&self.models.sources, &lines);
            let mut sy = self.syslog.borrow_mut();
            sy.sources_shown = keys;
            sy.dirty = false;
        }
        let sel = self.syslog.borrow().sources_shown.iter().position(|k| *k == chosen).unwrap_or(0);
        ui.set_source(sel as i32);
        ui.set_severity(crate::view::severity_index(sev) as i32);
        ui.set_paused(st.paused());
        ui.set_pause_text(s(if st.paused() { format!("Resume · {} new", crate::text::thousands(st.new_while_paused)) } else { "Pause".into() }));
        let detail = model.selected.get().and_then(|q| st.get(q)).map(crate::view::syslog_detail).unwrap_or(SyslogDetail { shown: false, head: s(""), body: s("") });
        ui.set_detail(detail);
        let running = self.slot(Kind::Syslog, |sl| sl.running());
        let port = self.slot(Kind::Syslog, |sl| sl.port.unwrap_or(514));
        ui.set_syslog_empty(s(if st.held() > 0 {
            "No message matches the filter.".to_string()
        } else if running {
            format!("Listening. Point devices here, port {port} (Cisco: logging host <this PC's address>).")
        } else {
            "Turn on Syslog to receive messages.".into()
        }));
        drop(st);
        let (on, folder, fstate) = {
            let sy = self.syslog.borrow();
            (sy.log_to_file, self.log_folder(), sy.file_state.clone())
        };
        ui.set_log_to_file(on);
        ui.set_log_folder(s(format!("Log folder: {}", crate::text::clean_path(&folder))));
        let (note, kind) = match (&fstate, on) {
            (_, false) => (String::new(), 0),
            (FileState::Writing(p), _) => (p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), 0),
            (FileState::DayFull(_), _) => ("Today's file is full (1 GiB): paused".into(), 2),
            (FileState::DiskLow, _) => ("Paused: disk nearly full".into(), 2),
            (FileState::Failed(e), _) => (format!("Not written: {}", crate::text::clean(e)), 3),
            (FileState::Off, _) => ("Waiting for messages".into(), 0),
        };
        ui.set_log_note(s(note));
        ui.set_log_note_kind(kind);
    }

    fn show_logs(&self, ui: &AppWindow) {
        let model = self.model();
        let (total, held) = {
            let st = model.store.borrow();
            (st.total, st.len())
        };
        let t = self.logs[0].log.borrow().len();
        let h = self.logs[1].log.borrow().len();
        let tabs = [
            if total > 0 { format!("Syslog · {}", crate::text::thousands(held as u64)) } else { "Syslog".to_string() },
            if t > 0 { format!("TFTP log · {}", crate::text::thousands(t as u64)) } else { "TFTP log".into() },
            if h > 0 { format!("HTTP log · {}", crate::text::thousands(h as u64)) } else { "HTTP log".into() },
        ];
        set_strings(&self.models.tabs, &tabs);
        let count = |n: usize, added: u64| {
            if n == 0 {
                String::new()
            } else if (added as usize) > n {
                format!("the last {} of {} requests", crate::text::thousands(n as u64), crate::text::thousands(added))
            } else {
                format!("{} request{}", crate::text::thousands(n as u64), if n == 1 { "" } else { "s" })
            }
        };
        ui.set_tftp_count(s(count(t, self.logs[0].log.borrow().added)));
        ui.set_http_count(s(count(h, self.logs[1].log.borrow().added)));
        let tftp_on = self.slot(Kind::Tftp, |sl| sl.running());
        let http_on = self.slot(Kind::Http, |sl| sl.running());
        ui.set_tftp_empty(s(if tftp_on { "Listening. Every request (who, what, how it ended) shows here." } else { "Turn on TFTP to serve the root folder." }));
        ui.set_http_empty(s(if http_on { "Listening. Every request shows here." } else { "Turn on HTTP to serve the root folder." }));
    }

    fn show_firewall(&self, ui: &AppWindow) {
        let any_live = KINDS.iter().any(|&k| self.slot(k, |sl| sl.live()));
        let needed = KINDS.iter().any(|&k| self.slot(k, |sl| sl.live()) && self.need_shown(k) == Need::Rule);
        let covered = KINDS.iter().any(|&k| self.slot(k, |sl| sl.live()) && self.need_shown(k) == Need::Covered);
        let not_private = self.not_private();
        // The status the window shows (RL7-1: never "unknown" while a socket beyond this PC is
        // bound), copied out of `Net`'s lock.
        let shown: Option<Result<Status, String>> = self.read_with(true, |r| r.map(|x| x.as_ref().map(|(st, _)| st.clone()).map_err(String::clone)));
        let stuck = self.sh.stuck(&lock(&self.sh.net));
        // What a click does (`firewall_clicked`): a failed newest read is read again.
        let read_failed = self.read_with(false, |r| matches!(r, Some(Err(_))));
        let f = self.fw.borrow();
        let held = f.held.len();
        let v = match &shown {
            // RL9-2: never "unknown" or "not shared" while a stopped server's thread may still
            // hold a socket on the network, and never the state from before its stop either.
            // RSA-3: judged on the stopped server's sockets as bound, not on what its left
            // threads hold, so the tip says only what is known. RSA-2: a click still reads the
            // firewall again while the newest read failed (a read that succeeds can end this).
            _ if stuck => FirewallView { text: s("Firewall: a server is still closing"), kind: 2, tip: s(closing_tip(read_failed)), action: read_failed },
            None => FirewallView { text: s("Firewall: checking…"), kind: 0, tip: s("Reading Windows Firewall's state (no admin needed)."), action: false },
            Some(Err(e)) => FirewallView { text: s("Firewall: unknown"), kind: 2, tip: s(format!("Windows Firewall's state could not be read ({}), so the servers listen on this PC only until it can be. Click to try again.", crate::text::clean(e))), action: true },
            // SEC-Serve-1: no Private network, no sharing (unless a rule of the user's lets it
            // in): the servers listen on this PC only, whatever the firewall's state (RIN1-3).
            Some(Ok(st)) if st.active & crate::firewall::PRIVATE == 0 && !covered => FirewallView {
                text: s(if st.profiles.is_empty() || st.profiles.contains(',') { "No Private network: not shared".to_string() } else { format!("{} network: not shared", st.profiles) }),
                kind: 2,
                tip: s(format!("{not_private}. VibeServe shares on Private networks only, so here the servers listen on this PC only and other devices cannot connect. To share, set this network to Private in Windows Settings.")),
                action: false,
            },
            Some(Ok(st)) if !st.enabled => FirewallView { text: s("Firewall off"), kind: 0, tip: s(format!("Windows Firewall is off for this network ({}): other devices can connect.", st.profiles)), action: false },
            Some(Ok(st)) if st.block_all => FirewallView {
                text: s("Firewall blocks all incoming"),
                kind: 3,
                tip: s(format!("\"Block all incoming connections\" is on for this network ({}): no rule can let other devices in. Servers still answer this PC.", st.profiles)),
                action: false,
            },
            Some(Ok(_)) if f.session.is_some() && held > 0 => FirewallView { text: s("Firewall rule active"), kind: 1, tip: s(format!("VibeServe's rule lets in {held} port{} from your local subnet, on Private networks only, for this program only. It goes when the servers stop.", if held == 1 { "" } else { "s" })), action: false },
            Some(Ok(_)) if f.session.is_some() => FirewallView { text: s("Firewall: allowed"), kind: 0, tip: s("The helper is ready: a server you turn on gets its rule without another prompt."), action: false },
            Some(Ok(_)) if f.launching => FirewallView { text: s("Firewall: waiting for Windows…"), kind: 0, tip: s("Windows asks whether VibeServe may change the firewall."), action: false },
            Some(Ok(_)) if needed && f.lost => FirewallView { text: s("Firewall rule gone"), kind: 3, tip: s("The firewall helper ended, and its rule with it. Click to allow again."), action: true },
            Some(Ok(_)) if needed && (f.declined || f.failed.is_some()) => FirewallView {
                text: s("Firewall may block devices"),
                kind: 2,
                tip: s(f.failed.as_ref().map(|e| format!("The rule was not added ({}). Click to try again.", crate::text::clean(e))).unwrap_or_else(|| "No rule was added: other devices may be blocked. Click to allow (Windows asks).".into())),
                action: true,
            },
            Some(Ok(_)) if any_live && !needed => FirewallView { text: s("Firewall: no rule needed"), kind: 0, tip: s("The servers on now listen on this PC only, or a rule of yours already lets them in."), action: false },
            Some(Ok(st)) => FirewallView { text: s("Firewall on"), kind: 0, tip: s(format!("Windows Firewall is on ({}). Turning on a server offers a rule (one Windows prompt); sharing works on Private networks only.", st.profiles)), action: false },
        };
        drop(f);
        ui.set_firewall(v);
    }

    fn show_status(&self, ui: &AppWindow) {
        let mut parts = Vec::new();
        let mut warn = false;
        for k in KINDS {
            let (on, phase_words, udp, tcp) = self.slot(k, |sl| {
                let w = match &sl.phase {
                    Phase::Running(..) => "on",
                    Phase::Failed(..) => "failed",
                    Phase::Off => "off",
                    Phase::Stopping => "stopping",
                    _ => "starting",
                };
                (sl.on, w, sl.udp, sl.tcp)
            });
            let name = match k {
                Kind::Tftp => "TFTP",
                Kind::Syslog => "syslog",
                Kind::Http => "HTTP",
            };
            let words = if !on && phase_words != "stopping" { "off" } else { phase_words };
            warn |= words == "failed";
            if k == Kind::Syslog && words == "on" {
                let p: Vec<&str> = [(udp, "UDP"), (tcp, "TCP")].iter().filter(|(b, _)| *b).map(|(_, n)| *n).collect();
                parts.push(format!("{name} on ({})", p.join(", ")));
            } else {
                parts.push(format!("{name} {words}"));
            }
        }
        let root = {
            let r = self.root.borrow();
            match &r.error {
                Some(_) => {
                    warn = true;
                    format!("root {} (not open)", crate::text::clean_path(&r.path))
                }
                None => format!("root {}", crate::text::clean_path(&r.path)),
            }
        };
        parts.push(root);
        let fw = {
            let f = self.fw.borrow();
            if f.session.is_some() && !f.held.is_empty() { "firewall rule active".to_string() } else { String::new() }
        };
        if !fw.is_empty() {
            parts.push(fw);
        }
        ui.set_status_left(s(parts.join(" · ")));
        ui.set_status_warn(warn);
        // Right: transfers, messages, what was dropped.
        let mut right = Vec::new();
        let transfers = self.models.transfers.row_count();
        if transfers > 0 {
            right.push(format!("{transfers} transfer{}", if transfers == 1 { "" } else { "s" }));
        }
        let (total, over_memory) = {
            let m = self.model();
            let st = m.store.borrow();
            (st.total, st.over_memory)
        };
        if total > 0 {
            right.push(format!("{} message{}", crate::text::thousands(total), if total == 1 { "" } else { "s" }));
        }
        if over_memory > 0 {
            right.push(format!("{} older out of memory: 64 MiB cap", crate::text::thousands(over_memory)));
        }
        let (dropped, refused, broken) = self.slot(Kind::Syslog, |sl| match &sl.phase {
            Phase::Running(Live { srv: Some(Srv::Syslog(sy)), .. }, _) => (sy.rate.dropped.load(Ordering::Relaxed), sy.stats.refused.load(Ordering::Relaxed), sy.stats.broken.load(Ordering::Relaxed)),
            _ => (0, 0, 0),
        });
        if dropped > 0 {
            right.push(format!("{} dropped: rate", crate::text::thousands(dropped)));
        }
        if refused > 0 {
            right.push(format!("{} TCP refused: 64 open", crate::text::thousands(refused)));
        }
        if broken > 0 {
            right.push(format!("{} TCP framing errors", crate::text::thousands(broken)));
        }
        let (behind, fell_behind) = lock(&self.file).as_ref().map(|f| (f.behind(), f.fell_behind())).unwrap_or((0, false));
        if behind > 0 {
            right.push(format!("{} not written to the log file{}", crate::text::thousands(behind), if fell_behind { ": it fell behind" } else { "" }));
        }
        match &self.syslog.borrow().file_state {
            FileState::DayFull(_) if self.syslog.borrow().log_to_file => right.push("log file paused: today's file is full".into()),
            FileState::DiskLow if self.syslog.borrow().log_to_file => right.push("log file paused: disk nearly full".into()),
            FileState::Failed(_) if self.syslog.borrow().log_to_file => right.push("log file not written".into()),
            _ => {}
        }
        ui.set_status_right(s(right.join(" · ")));
    }

    // ---------- toasts ----------

    /// A toast, bottom right: errors stay 10 s, the rest 5 s. With `reveal` it offers "Show"
    /// (that file selected in Explorer). The text is cleaned (it may hold outside text).
    pub fn toast(&self, text: &str, kind: ToastKind, reveal: Option<PathBuf>) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            if let Some(p) = reveal.clone() {
                st.toast_paths.insert(id, p);
            }
            id
        };
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(crate::text::clean_max(text, 600)), kind, action: if reveal.is_some() { s("Show") } else { s("") } });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    fn dialog_open(&self) -> bool {
        self.ui().is_some_and(|ui| ui.get_about_open() || ui.get_consent_open())
    }

    /// A toast's timer, `ms` from now. Only its newest timer counts, and while a dialog is open
    /// it waits: the toast is in sight but out of reach there.
    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.weak();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            if current && !a.dialog_open() {
                a.drop_toast(id);
            }
        });
    }

    /// A dialog closed: every toast gets its full time again.
    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        self.st.borrow_mut().toast_time.remove(&id);
        self.st.borrow_mut().toast_paths.remove(&id);
    }

    fn toast_action(&self, id: i32) {
        let p = self.st.borrow().toast_paths.get(&id).cloned();
        if let Some(p) = p {
            (self.svc.reveal)(&p);
        }
        self.drop_toast(id);
    }

    // ---------- for tests ----------

    /// What the helper holds now (tests).
    pub fn rules_held(&self) -> Vec<Want> {
        self.fw.borrow().held.clone()
    }

    /// A server's address as bound (tests connect to it).
    pub fn local_addr(&self, k: Kind) -> Option<Vec<std::net::SocketAddr>> {
        self.slot(k, |sl| match &sl.phase {
            Phase::Running(l, _) => l.srv.as_ref().map(|s| s.sockets().into_iter().map(|(_, a)| a).collect()),
            _ => None,
        })
    }

    pub fn running(&self, k: Kind) -> bool {
        self.slot(k, |sl| sl.running())
    }

    /// The addresses changed (debounced; tests call it directly): the adapters are read again,
    /// and the firewall's state, since another network may be another profile (RIN1-3).
    pub fn network_changed(&self) {
        self.read_adapters();
        self.read_firewall_again();
    }

    /// Where a running server listens, as its card says (tests).
    pub fn bound(&self, k: Kind) -> Option<Bind> {
        self.slot(k, |sl| match &sl.phase {
            Phase::Running(_, b) => Some(b.clone()),
            _ => None,
        })
    }

    /// The root's final path as open now (tests).
    pub fn root_open(&self) -> Option<PathBuf> {
        self.root.borrow().open.as_ref().and_then(|r| r.final_path().ok()).map(|u| crate::host::path_from_wide(&u))
    }
}

/// What the firewall says to a server about to start.
enum Gate1 {
    Go,
    Wait(&'static str),
}

/// The (TCP?, port) pairs a server of `k` listens on.
fn ports_for(k: Kind, port: Option<u16>, udp: bool, tcp: bool) -> Vec<(bool, u16)> {
    let Some(p) = port else { return Vec::new() };
    match k {
        Kind::Tftp => vec![(false, p)],
        Kind::Http => vec![(true, p)],
        Kind::Syslog => [(false, udp), (true, tcp)].into_iter().filter(|(_, on)| *on).map(|(t, _)| (t, p)).collect(),
    }
}

/// What a server beyond this PC on `ports` needs of the firewall, on `read`.
fn need_of(read: Option<&FwRead>, exe: &Path, ports: &[(bool, u16)]) -> Need {
    match read {
        None => Need::Reading,
        Some(Err(e)) => Need::ReadFailed(e.clone()),
        Some(Ok((st, rules))) => {
            // SEC-Serve-1: VibeServe shares on Private networks only, so there a rule of the
            // user's for Private is enough; with no Private network no rule would apply.
            let private = st.active & crate::firewall::PRIVATE != 0;
            let profiles = if private { crate::firewall::PRIVATE } else { st.active };
            let covered = st.enabled && !st.block_all && !ports.is_empty() && ports.iter().all(|(tcp, p)| crate::firewall::allowed_already(rules, exe, *p, if *tcp { 6 } else { 17 }, profiles));
            if !private && !covered {
                // RIN1-3: then the servers listen on this PC only (`PC_ONLY`), whatever the
                // firewall's state, a rule left by a crash or Windows' own prompt.
                Need::Public
            } else if !st.enabled {
                Need::Off
            } else if st.block_all {
                Need::BlockAll
            } else if covered {
                Need::Covered
            } else {
                Need::Rule
            }
        }
    }
}

/// Why a server could not listen, in words, with the port's owner when it is in use.
fn bind_words(e: &BindError, proto: &str, port: u16, bind: &Bind, owners: &(dyn Fn(bool, u16) -> Option<Vec<PortOwner>> + Send + Sync), tcp: bool) -> String {
    match e {
        BindError::InUse | BindError::Reserved => match owners(tcp, port) {
            Some(o) if !o.is_empty() => {
                let first = o[0].words(tcp, port);
                let more = if o.len() > 1 { format!(" and {} more", o.len() - 1) } else { String::new() };
                format!("{proto} {port} in use by {first}{more}.")
            }
            Some(_) if *e == BindError::Reserved => format!("{proto} {port} is reserved by Windows (an excluded port range, often Hyper-V's)."),
            Some(_) => format!("{proto} {port} is in use."),
            None => format!("{proto} {port} is in use (its owner could not be read)."),
        },
        BindError::NoAddress => format!("{} is not on this PC now.", bind.key()),
        BindError::Other(w) => format!("Could not listen on {proto} {port}: {}", crate::text::clean(w)),
    }
}

/// What a thread a stop left most likely waits on (RSD-1): a file call deaf to the stop, and for
/// HTTP also a download blocked in a send to a client that stopped reading (`shutdown` does not
/// wake that send; its write timeout, the idle time, ends it).
fn left_cause(k: Kind) -> &'static str {
    match k {
        Kind::Http => "a file Windows holds or on a client that stopped reading",
        Kind::Tftp | Kind::Syslog => "a file Windows holds",
    }
}

/// The toast for a stop that left `left` threads of `k`'s server (RSD-1): what they most likely
/// wait on, and no promise that they end, since a file call may never return (DECISIONS).
pub fn left_toast(k: Kind, left: usize) -> String {
    let (name, what) = match k {
        Kind::Tftp => ("TFTP", "transfer"),
        Kind::Syslog => ("Syslog", "connection"),
        Kind::Http => ("HTTP", "request"),
    };
    let (n, they) = if left == 1 { (format!("1 {what} has"), "It ends") } else { (format!("{left} {what}s have"), "They end") };
    format!("{name} stopped, but {n} not ended yet, most likely waiting on {}. {they} once that lets go, which may take a while.", left_cause(k))
}

/// The tip of "Firewall: a server is still closing" (RSA-3, RSD-1): claims no more than is known,
/// whichever server it is, and offers the click only while the newest read failed (RSA-2).
pub fn closing_tip(read_failed: bool) -> String {
    format!(
        "A server that stopped has a thread that has not ended yet, most likely waiting on {}. Until it ends, it may still hold a socket other devices can reach. It ends once that lets go, which may take a while, and the firewall's state shows again then.{}",
        left_cause(Kind::Http),
        if read_failed { " Click to read the firewall's state again." } else { "" }
    )
}

fn set_strings(m: &VecModel<SharedString>, v: &[String]) {
    let same = m.row_count() == v.len() && m.iter().zip(v.iter()).all(|(a, b)| a.as_str() == b);
    if !same {
        m.set_vec(v.iter().map(SharedString::from).collect::<Vec<_>>());
    }
}

fn set_rows<T: Clone + PartialEq + 'static>(m: &VecModel<T>, v: Vec<T>) {
    let same = m.row_count() == v.len() && m.iter().zip(v.iter()).all(|(a, b)| a == *b);
    if !same {
        m.set_vec(v);
    }
}
