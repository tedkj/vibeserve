//! Windows' own folder picker (the Common Item Dialog, through its COM vtable: windows-sys
//! carries no COM interfaces) and Save As. Each runs on a thread of its own, owned by the app's
//! window: the dialog is modal to it while the app's event loop keeps running, and nothing
//! re-enters the UI thread's handlers. (The picker is VibeCopy's.)

use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

type Raw = *mut core::ffi::c_void;

#[repr(C)]
struct FileDialogVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(Raw) -> u32,
    show: unsafe extern "system" fn(Raw, HWND) -> HRESULT,
    set_file_types: usize,
    set_file_type_index: usize,
    get_file_type_index: usize,
    advise: usize,
    unadvise: usize,
    set_options: unsafe extern "system" fn(Raw, u32) -> HRESULT,
    get_options: unsafe extern "system" fn(Raw, *mut u32) -> HRESULT,
    set_default_folder: usize,
    set_folder: unsafe extern "system" fn(Raw, Raw) -> HRESULT,
    get_folder: usize,
    get_current_selection: usize,
    set_file_name: usize,
    get_file_name: usize,
    set_title: unsafe extern "system" fn(Raw, PCWSTR) -> HRESULT,
    set_ok_button_label: unsafe extern "system" fn(Raw, PCWSTR) -> HRESULT,
    set_file_name_label: usize,
    get_result: unsafe extern "system" fn(Raw, *mut Raw) -> HRESULT,
}

#[repr(C)]
struct ShellItemVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(Raw) -> u32,
    bind_to_handler: usize,
    get_parent: usize,
    get_display_name: unsafe extern "system" fn(Raw, i32, *mut PWSTR) -> HRESULT,
}

const IID_IFILEDIALOG: GUID = GUID::from_u128(0x42f85136_db7e_439c_85f1_e4075d135fc8);
const IID_ISHELLITEM: GUID = GUID::from_u128(0x43826d1e_e718_42ee_bc55_a1e261c37bfe);
const FOS_NOCHANGEDIR: u32 = 0x8;
const FOS_PICKFOLDERS: u32 = 0x20;
const FOS_FORCEFILESYSTEM: u32 = 0x40;
const FOS_PATHMUSTEXIST: u32 = 0x800;

unsafe fn vtbl<T>(p: Raw) -> &'static T {
    unsafe { &**(p as *mut *const T) }
}

fn item_for(path: &Path) -> Option<Raw> {
    use windows_sys::Win32::UI::Shell::SHCreateItemFromParsingName;
    let w = crate::host::wide_path(path);
    let mut item: Raw = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; the item comes back ours to release.
    let hr = unsafe { SHCreateItemFromParsingName(w.as_ptr(), std::ptr::null_mut(), &IID_ISHELLITEM, &mut item) };
    if hr >= 0 && !item.is_null() { Some(item) } else { None }
}

fn run(owner: HWND, title: &str, start: Option<&Path>) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize};
    use windows_sys::Win32::UI::Shell::{FileOpenDialog, SIGDN_FILESYSPATH};
    // SAFETY: COM on this thread; every interface released; the strings outlive their calls.
    unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
        let mut dlg: Raw = std::ptr::null_mut();
        let mut out = None;
        if CoCreateInstance(&FileOpenDialog, std::ptr::null_mut(), CLSCTX_INPROC_SERVER, &IID_IFILEDIALOG, &mut dlg) >= 0 && !dlg.is_null() {
            let v = vtbl::<FileDialogVtbl>(dlg);
            let mut opts = 0u32;
            (v.get_options)(dlg, &mut opts);
            (v.set_options)(dlg, opts | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR | FOS_PATHMUSTEXIST | FOS_PICKFOLDERS);
            let t = crate::host::wide(title);
            (v.set_title)(dlg, t.as_ptr());
            let ok = crate::host::wide("Choose");
            (v.set_ok_button_label)(dlg, ok.as_ptr());
            // A start folder only on a fixed local drive: on a share that does not answer the
            // picker takes ~20 s to appear (C46, VibeSpace SPE-4).
            if let Some(dir) = start.filter(|s| local_fixed(s)).and_then(|s| s.ancestors().find(|a| a.is_dir())).and_then(item_for) {
                (v.set_folder)(dlg, dir);
                (vtbl::<ShellItemVtbl>(dir).release)(dir);
            }
            if (v.show)(dlg, owner) >= 0 {
                let mut item: Raw = std::ptr::null_mut();
                if (v.get_result)(dlg, &mut item) >= 0 && !item.is_null() {
                    let iv = vtbl::<ShellItemVtbl>(item);
                    let mut p: PWSTR = std::ptr::null_mut();
                    if (iv.get_display_name)(item, SIGDN_FILESYSPATH, &mut p) >= 0 && !p.is_null() {
                        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
                        out = Some(PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(p, len))));
                        CoTaskMemFree(p as *const _);
                    }
                    (iv.release)(item);
                }
            }
            (v.release)(dlg);
        }
        CoUninitialize();
        out
    }
}

/// A path on a fixed local drive (`C:\...`, also in its `\\?\` form). Asks the drive type
/// only, which reads nothing from the drive.
pub fn local_fixed(path: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_FIXED: u32 = 3;
    let s = path.as_os_str().to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = s.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return false;
    }
    let root = crate::host::wide(&format!("{}:\\", b[0] as char));
    // SAFETY: a NUL-terminated root path.
    unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_FIXED }
}

/// A folder picker over `owner`; `done` hears the choice (None: cancelled), on the dialog's
/// thread. The start folder is looked at there too, and only on a fixed local drive.
pub fn pick_folder(owner: isize, title: &str, start: Option<PathBuf>, done: Box<dyn FnOnce(Option<PathBuf>) + Send>) {
    let title = title.to_string();
    std::thread::spawn(move || done(run(owner as HWND, &title, start.as_deref())));
}

/// What Save As answers: the path and whether it is CSV (None: cancelled).
pub type SaveAnswer = Box<dyn FnOnce(Option<(PathBuf, bool)>) + Send>;

/// Save As for a saved view, on its own thread: the path as Windows has it (never round-tripped
/// through a lossy string) and whether CSV was chosen (by the type picked, or the extension).
pub fn save_as(owner: isize, default_name: String, done: SaveAnswer) {
    std::thread::spawn(move || {
        use windows_sys::Win32::UI::Controls::Dialogs::{GetSaveFileNameW, OFN_EXPLORER, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW};
        // Pairs of display name and pattern, each NUL-terminated, the list ended by another NUL.
        let filter: Vec<u16> = "CSV, opens in Excel (*.csv)\0*.csv\0Text (*.txt)\0*.txt\0\0".encode_utf16().collect();
        let mut file = vec![0u16; 1024];
        for (i, c) in default_name.encode_utf16().take(1000).enumerate() {
            file[i] = c;
        }
        let ext = crate::host::wide("csv");
        let title = crate::host::wide("Save view");
        // SAFETY: zeroed is valid for OPENFILENAMEW; every pointer set below points at a live
        // buffer of the size given, and the call returns before any of them go away.
        let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.hwndOwner = owner as HWND;
        ofn.lpstrFilter = filter.as_ptr();
        ofn.nFilterIndex = 1;
        ofn.lpstrFile = file.as_mut_ptr();
        ofn.nMaxFile = file.len() as u32;
        ofn.lpstrDefExt = ext.as_ptr();
        ofn.lpstrTitle = title.as_ptr();
        ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if unsafe { GetSaveFileNameW(&mut ofn) } == 0 {
            return done(None);
        }
        let len = file.iter().position(|&c| c == 0).unwrap_or(file.len());
        let path = crate::host::path_from_wide(&file[..len]);
        let txt = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt"));
        done(Some((path, !txt)));
    });
}
