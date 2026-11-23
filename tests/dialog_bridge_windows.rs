#![cfg(target_os = "windows")]

use spiffy_search::dialog::{self, DialogContext, DialogKind};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows::Win32::UI::Shell::{
    FileOpenDialog, FileSaveDialog, IFileOpenDialog, IFileSaveDialog, IShellItem,
    SHCreateItemFromParsingName, FOS_ALLOWMULTISELECT, FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetForegroundWindow, GetWindowThreadProcessId, PostMessageW, SetForegroundWindow,
    WM_CLOSE,
};

static DIALOG_FIXTURE_LOCK: Mutex<()> = Mutex::new(());
static TEST_LOG_INIT: Once = Once::new();

#[derive(Clone, Copy)]
enum FixtureKind {
    Open,
    Save,
    Folder,
    MultiOpen,
    LegacyOpen,
}

impl FixtureKind {
    fn title(self) -> &'static str {
        match self {
            Self::Open => "Spiffy Dialog Fixture Open",
            Self::Save => "Spiffy Dialog Fixture Save",
            Self::Folder => "Spiffy Dialog Fixture Folder",
            Self::MultiOpen => "Spiffy Dialog Fixture Multi Open",
            Self::LegacyOpen => "Spiffy Dialog Fixture Legacy Open",
        }
    }
}

#[test]
#[ignore = "requires an interactive Windows desktop"]
fn modern_open_dialog_navigates_and_prepares_one_file_without_confirming() {
    let temp = fixture_tree();
    let target_file = temp.path().join("Destination").join("hero clip.txt");
    with_dialog(FixtureKind::Open, temp.path().join("Start"), |context| {
        assert_eq!(context.kind, DialogKind::Open);
        let receipt =
            dialog::prepare_files(&context.dialog_id, &[target_file]).unwrap_or_else(|error| {
                let after = dialog::inspect_active()
                    .ok()
                    .and_then(|inspection| inspection.context)
                    .map(|context| (context.current_folder, context.filename_present));
                panic!("prepare failed: {error}; active dialog state: {after:?}")
            });
        assert_eq!(receipt.target_count, 1);
        assert!(!receipt.confirmation_invoked);
        assert!(!receipt.filename_preserved);
    });
}

#[test]
#[ignore = "requires an interactive Windows desktop"]
fn modern_save_dialog_navigates_and_preserves_typed_filename() {
    let temp = fixture_tree();
    let destination = temp.path().join("Destination");
    with_dialog(FixtureKind::Save, temp.path().join("Start"), |context| {
        assert_eq!(context.kind, DialogKind::Save);
        let receipt = dialog::navigate_folder(&context.dialog_id, &destination).unwrap();
        assert!(receipt.filename_preserved);
        assert!(!receipt.confirmation_invoked);
    });
}

#[test]
#[ignore = "requires an interactive Windows desktop"]
fn modern_folder_dialog_navigates_without_invoking_selection() {
    let temp = fixture_tree();
    let destination = temp.path().join("Destination");
    with_dialog(FixtureKind::Folder, temp.path().join("Start"), |context| {
        assert_eq!(context.kind, DialogKind::Folder);
        let receipt = dialog::navigate_folder(&context.dialog_id, &destination).unwrap();
        assert!(!receipt.confirmation_invoked);
    });
}

#[test]
#[ignore = "requires an interactive Windows desktop"]
fn modern_multi_open_dialog_prepares_same_parent_files() {
    let temp = fixture_tree();
    let destination = temp.path().join("Destination");
    let files = [
        destination.join("hero clip.txt"),
        destination.join("second clip.txt"),
    ];
    with_dialog(
        FixtureKind::MultiOpen,
        temp.path().join("Start"),
        |context| {
            assert_eq!(context.kind, DialogKind::Open);
            let receipt = dialog::prepare_files(&context.dialog_id, &files).unwrap();
            assert_eq!(receipt.target_count, 2);
            assert!(!receipt.confirmation_invoked);
        },
    );
}

#[test]
#[ignore = "requires an interactive Windows desktop"]
fn legacy_get_open_file_name_navigates_and_prepares_without_confirming() {
    let temp = fixture_tree();
    let target_file = temp.path().join("Destination").join("hero clip.txt");
    with_dialog(
        FixtureKind::LegacyOpen,
        temp.path().join("Start"),
        |context| {
            assert_eq!(context.kind, DialogKind::Open);
            let receipt = dialog::prepare_files(&context.dialog_id, &[target_file]).unwrap();
            assert_eq!(receipt.target_count, 1);
            assert!(!receipt.confirmation_invoked);
        },
    );
}

fn fixture_tree() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("Start")).unwrap();
    std::fs::create_dir(temp.path().join("Destination")).unwrap();
    std::fs::write(
        temp.path().join("Destination").join("hero clip.txt"),
        "fixture",
    )
    .unwrap();
    std::fs::write(
        temp.path().join("Destination").join("second clip.txt"),
        "fixture two",
    )
    .unwrap();
    temp
}

fn with_dialog(action: FixtureKind, initial_folder: PathBuf, verify: impl FnOnce(&DialogContext)) {
    TEST_LOG_INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
    let _serial = DIALOG_FIXTURE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let title = action.title().to_string();
    let thread_title = title.clone();
    let handle = thread::spawn(move || show_fixture(action, &thread_title, &initial_folder));
    let context = match wait_for_fixture(&title) {
        Ok(context) => context,
        Err(error) => {
            close_fixture_dialog(&title);
            handle.join().unwrap();
            panic!("{error}");
        }
    };
    let result = panic::catch_unwind(AssertUnwindSafe(|| verify(&context)));
    close_dialog_id(&context.dialog_id);
    handle.join().unwrap();
    if let Err(payload) = result {
        panic::resume_unwind(payload);
    }
}

fn show_fixture(kind: FixtureKind, title: &str, initial_folder: &Path) {
    let status = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    assert!(
        status.is_ok(),
        "fixture COM initialization failed: {status}"
    );
    {
        let title = wide_null(title);
        match kind {
            FixtureKind::Save => {
                let folder = shell_item(initial_folder);
                let dialog: IFileSaveDialog =
                    unsafe { CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER) }
                        .unwrap();
                unsafe {
                    dialog.SetTitle(PCWSTR(title.as_ptr())).unwrap();
                    dialog.SetFolder(&folder).unwrap();
                    dialog
                        .SetFileName(PCWSTR(wide_null("preserve-name.txt").as_ptr()))
                        .unwrap();
                    let _ = dialog.Show(None);
                }
            }
            FixtureKind::Open | FixtureKind::Folder | FixtureKind::MultiOpen => {
                let folder = shell_item(initial_folder);
                let dialog: IFileOpenDialog =
                    unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
                        .unwrap();
                unsafe {
                    dialog.SetTitle(PCWSTR(title.as_ptr())).unwrap();
                    dialog.SetFolder(&folder).unwrap();
                    let mut options = dialog.GetOptions().unwrap() | FOS_FORCEFILESYSTEM;
                    if matches!(kind, FixtureKind::Folder) {
                        options |= FOS_PICKFOLDERS;
                    }
                    if matches!(kind, FixtureKind::MultiOpen) {
                        options |= FOS_ALLOWMULTISELECT;
                    }
                    dialog.SetOptions(options).unwrap();
                    let _ = dialog.Show(None);
                }
            }
            FixtureKind::LegacyOpen => show_legacy_fixture(&title, initial_folder),
        }
    }
    unsafe { CoUninitialize() };
}

fn show_legacy_fixture(title: &[u16], initial_folder: &Path) {
    let initial_folder = wide_null(&initial_folder.to_string_lossy());
    let mut filename = vec![0_u16; 32_768];
    let mut options = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        lpstrFile: PWSTR(filename.as_mut_ptr()),
        nMaxFile: filename.len() as u32,
        lpstrInitialDir: PCWSTR(initial_folder.as_ptr()),
        lpstrTitle: PCWSTR(title.as_ptr()),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    let _ = unsafe { GetOpenFileNameW(&mut options) };
}

fn shell_item(path: &Path) -> IShellItem {
    let path = wide_null(&path.to_string_lossy());
    unsafe { SHCreateItemFromParsingName(PCWSTR(path.as_ptr()), None) }.unwrap()
}

fn wait_for_fixture(title: &str) -> Result<DialogContext, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found_window = false;
    while Instant::now() < deadline {
        if let Some(hwnd) = find_fixture_window(title) {
            found_window = true;
            let _ = unsafe { SetForegroundWindow(hwnd) };
            if unsafe { GetForegroundWindow() } == hwnd {
                match dialog::inspect_active() {
                    Ok(inspection) => {
                        if let Some(context) =
                            inspection.context.filter(|context| context.title == title)
                        {
                            return Ok(context);
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    if found_window {
        Err(format!(
            "fixture dialog '{title}' opened but could not be foregrounded and inspected"
        ))
    } else {
        Err(format!("fixture dialog '{title}' did not open"))
    }
}

fn close_dialog_id(dialog_id: &str) {
    let hwnd = dialog_id
        .rsplit(':')
        .next()
        .and_then(|value| usize::from_str_radix(value, 16).ok())
        .map(|value| HWND(value as *mut _));
    if let Some(hwnd) = hwnd {
        let _ = unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) };
    }
}

fn close_fixture_dialog(title: &str) {
    if let Some(hwnd) = find_fixture_window(title) {
        let _ = unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) };
    }
}

fn find_fixture_window(title: &str) -> Option<HWND> {
    let class = wide_null("#32770");
    let title = wide_null(title);
    let hwnd = unsafe { FindWindowW(PCWSTR(class.as_ptr()), PCWSTR(title.as_ptr())).ok()? };
    let mut process_id = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    (process_id == std::process::id()).then_some(hwnd)
}

fn wide_null(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}
