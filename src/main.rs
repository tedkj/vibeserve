// VibeServe: one process, no browser engine, the software renderer.
#![windows_subsystem = "windows"]

use slint::ComponentHandle;

/// The real release-list fetcher (WinHTTP), the exe's alone: it is in no test build, not the
/// lib's, not the integration tests', not this exe's own unit tests', so no test can go online
/// (review RAB-2; tests/pe.rs checks this line).
#[cfg(not(test))]
mod net;

/// The window's Win32 handle, for `host::fit_to_work_area`.
fn hwnd_of(w: &slint::winit_030::winit::window::Window) -> Option<isize> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match w.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

fn main() -> Result<(), slint::PlatformError> {
    // First of all: DLLs loaded at run time come from System32 only, never from the (user-
    // writable) folder this exe sits in. It also runs elevated, as the firewall helper.
    // The static imports are covered by the link flag /DEPENDENTLOADFLAG:0x800 (build.rs).
    // SAFETY: a process-wide setting with a valid flag; nothing has been loaded by name yet.
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    // No Windows "No Disk" box: a file call on an empty card reader or drive gets its error back
    // instead of a modal box (review fix-popup, RX1). tests/pe.rs checks this block comes next.
    // SAFETY: a process-wide setting with a valid flag, the bits already set kept.
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_FAILCRITICALERRORS, SetErrorMode};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    }
    // The command line: nothing (the window), files dropped on the exe (the window, below), or the
    // elevated firewall helper's one exact argument set (`--firewall <id> <pid>`, no window;
    // `helper::run` refuses a malformed one with exit 2), which comes first. Anything else ends
    // the process before any window or file (exit code 2). args_os: an
    // argument that is not valid Unicode (a dropped file's name with a lone surrogate) must not
    // panic (panic = abort ends the app).
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.get(1).and_then(|a| a.to_str()) == Some(vibeserve::helper::ARG) {
        std::process::exit(vibeserve::helper::run(&args));
    }
    // Files dropped on the exe or its shortcut: the window, and a toast that they were left alone
    // (launch.rs). Any other argument, an option above all, exits 2 as before.
    let dropped = match vibeserve::launch::start(args.get(1..).unwrap_or_default()) {
        vibeserve::launch::Start::Window => None,
        vibeserve::launch::Start::Dropped(note) => Some(note),
        vibeserve::launch::Start::Refused => std::process::exit(2),
    };
    #[allow(unused_mut)]
    let mut paths = vibeserve::host::paths();
    // Live checks and measurements only: the app's folders (and the default root) in a place of
    // the developer's choosing, so nothing touches the real profile. Never in a shipped build.
    #[cfg(feature = "dev-hooks")]
    if let Some(home) = std::env::var_os("VIBESERVE_DEV_HOME").map(std::path::PathBuf::from) {
        paths = vibeserve::host::Paths { config: home.join("config"), local_data: home.join("local"), default_root: home.join("root"), profile: home.clone(), others: Vec::new() };
    }
    // The probe hands back the value it was asked about, and `main` goes on with that one only: the
    // old binding is gone (`dev_probe`, review RRF-2).
    #[cfg(feature = "dev-hooks")]
    let paths = dev_probe(paths);
    let prefs = vibeserve::prefs::Store::new(paths.config.join("prefs.json"));
    let ui = vibeserve::window(prefs.clone())?;
    // The one place that names the real release-list fetcher (tests/pe.rs checks it): every test
    // hands the controller a fake, so no test goes online. This exe's unit-test build has no
    // `net` and never runs `main`: it gets a stand-in that fetches nothing.
    #[cfg(not(test))]
    let fetch = std::sync::Arc::new(net::fetch_release_list);
    #[cfg(test)]
    let fetch = std::sync::Arc::new(|_: &str| vibeserve::check::Fetched::Failed("a test build has no fetcher".into()));
    #[allow(unused_mut)]
    let mut svc = vibeserve::controller::Services::system(paths, fetch);
    // Measurements: servers on at start ("tftp,syslog,http"), as the dev's prefs place them.
    #[cfg(feature = "dev-hooks")]
    if let Ok(list) = std::env::var("VIBESERVE_DEV_START") {
        use vibeserve::activity::Kind;
        svc.autostart = list
            .split(',')
            .filter_map(|k| match k.trim() {
                "tftp" => Some(Kind::Tftp),
                "syslog" => Some(Kind::Syslog),
                "http" => Some(Kind::Http),
                _ => None,
            })
            .collect();
    }
    let app = vibeserve::controller::App::attach(&ui, prefs, svc);
    if let Some(note) = dropped {
        app.toast(&note, vibeserve::ToastKind::Info, None);
    }
    // The window opens at its preferred size; on a small or highly scaled screen that runs past
    // the taskbar, so the first window event once it is on screen fits it into the monitor's work
    // area (X15A11Y-3), once.
    let fitted = std::cell::Cell::new(false);
    {
        use slint::winit_030::{EventResult, WinitWindowAccessor};
        use vibeserve::host;
        ui.window().on_winit_window_event(move |window, _| {
            if !fitted.get() && window.with_winit_window(hwnd_of).flatten().and_then(host::fit_to_work_area).is_some() {
                fitted.set(true);
            }
            EventResult::Propagate
        });
    }
    let ran = ui.run();
    app.finish(); // servers stopped, temp files gone, firewall rules removed, prefs written
    ran
}

/// Live checks only (review RRE-5, RRF-2): with VIBESERVE_DEV_PROBE set, `main` writes the
/// app's data folders, one a line on stdout, and ends (exit 0) right after the dev home, before
/// any of them is used and before any window. Else it hands back the value it was given,
/// unchanged, and `main` goes on with it (`let paths = dev_probe(paths);`), so the folders the
/// probe names are the ones `main` uses. tests/pe.rs asks this before it starts the exe for real
/// (`run_exe`): every folder must be inside the scratch dev home it gave, so an override that is
/// gone, compiled out or too late fails there, by what the exe does.
#[cfg(feature = "dev-hooks")]
fn dev_probe(paths: vibeserve::host::Paths) -> vibeserve::host::Paths {
    use std::io::Write;
    if std::env::var_os("VIBESERVE_DEV_PROBE").is_some() {
        let mut out = std::io::stdout().lock();
        for f in [&paths.config, &paths.local_data, &paths.default_root, &paths.profile].into_iter().chain(&paths.others) {
            let _ = writeln!(out, "{}", f.display());
        }
        let _ = out.flush();
        std::process::exit(0);
    }
    paths
}
