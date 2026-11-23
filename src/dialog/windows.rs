use super::*;
use crate::model::normalize_path;
use ::windows::core::{Interface, BSTR, PWSTR};
use ::windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, RECT, RPC_E_CHANGED_MODE, WPARAM};
use ::windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use ::windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use ::windows::Win32::System::Variant::{
    VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_I4,
};
use ::windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationCondition, IUIAutomationElement,
    IUIAutomationElementArray, IUIAutomationValuePattern, TreeScope_Descendants,
    UIA_ComboBoxControlTypeId, UIA_ControlTypePropertyId, UIA_EditControlTypeId,
    UIA_ToolBarControlTypeId, UIA_ValuePatternId, UIA_CONTROLTYPE_ID,
};
use ::windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    VIRTUAL_KEY, VK_LCONTROL, VK_RETURN,
};
use ::windows::Win32::UI::Shell::{IShellWindows, IWebBrowserApp, ShellWindows};
use ::windows::Win32::UI::WindowsAndMessaging::{
    GetClassNameW, GetDlgItem, GetForegroundWindow, GetWindowRect, GetWindowTextLengthW,
    GetWindowTextW, GetWindowThreadProcessId, IsWindow, SendMessageW, SetForegroundWindow,
    WM_NEXTDLGCTL,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::mem::{size_of, ManuallyDrop};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

const STANDARD_DIALOG_CLASS: &str = "#32770";
const IDOK: i32 = 1;
const EDT1: usize = 0x0480;
const WM_USER: u32 = 0x0400;
const CDM_FIRST: u32 = WM_USER + 100;
const CDM_GETSPEC: u32 = CDM_FIRST;
const CDM_GETFOLDERPATH: u32 = CDM_FIRST + 2;
const CDM_SETCONTROLTEXT: u32 = CDM_FIRST + 4;
const ACTION_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROL_READY_TIMEOUT: Duration = Duration::from_millis(750);

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn enter() -> DialogBridgeResult<Self> {
        let status = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if status.is_ok() {
            Ok(Self { uninitialize: true })
        } else if status == RPC_E_CHANGED_MODE {
            Ok(Self {
                uninitialize: false,
            })
        } else {
            Err(DialogBridgeError::Platform(format!(
                "COM initialization failed: {status}"
            )))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe { CoUninitialize() };
        }
    }
}

pub(super) fn inspect_active() -> DialogBridgeResult<DialogInspection> {
    let hwnd = unsafe { GetForegroundWindow() };
    inspect_window(hwnd)
}

fn inspect_window(hwnd: HWND) -> DialogBridgeResult<DialogInspection> {
    if hwnd.0.is_null() || !unsafe { IsWindow(Some(hwnd)).as_bool() } {
        return Ok(DialogInspection::unsupported(
            "no_foreground_window",
            "No foreground window is available",
        ));
    }
    if window_class(hwnd) != STANDARD_DIALOG_CLASS {
        return Ok(DialogInspection::unsupported(
            "not_a_standard_file_dialog",
            "The foreground window is not a supported standard Windows file dialog",
        ));
    }
    let ok_label = unsafe { GetDlgItem(Some(hwnd), IDOK) }
        .ok()
        .map(window_text)
        .unwrap_or_default();
    if ok_label.trim().is_empty() {
        return Ok(DialogInspection::unsupported(
            "dialog_confirmation_missing",
            "The foreground #32770 window does not expose a standard confirmation control",
        ));
    }

    let mut process_id = 0_u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    let title = window_text(hwnd);
    let uia = uia_dialog_snapshot(hwnd);
    let filename = uia
        .filename
        .or_else(|| common_dialog_text(hwnd, CDM_GETSPEC));
    let current_folder = common_dialog_current_folder(hwnd).or(uia.current_folder);
    let kind = classify_dialog(&ok_label, filename.is_some());
    let mut bounds = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut bounds) }.map_err(|error| {
        DialogBridgeError::Platform(format!("could not read dialog bounds: {error}"))
    })?;
    let width = bounds.right.saturating_sub(bounds.left).max(0) as u32;
    let height = bounds.bottom.saturating_sub(bounds.top).max(0) as u32;
    let adapter_id = if uia.filename_available {
        "windows_standard_uia"
    } else {
        "windows_standard_common_dialog"
    };
    let mut capabilities = vec![
        DialogCapability::NavigateFolder,
        DialogCapability::AnchorOverlay,
    ];
    if current_folder.is_some() {
        capabilities.push(DialogCapability::ReadCurrentFolder);
    }
    if matches!(kind, DialogKind::Open) && filename.is_some() {
        capabilities.push(DialogCapability::PrepareFile);
        capabilities.push(DialogCapability::PrepareMultipleFiles);
    }
    if kind == DialogKind::Save && filename.is_some() {
        capabilities.push(DialogCapability::PreserveSaveFilename);
    }

    Ok(DialogInspection {
        supported: true,
        code: "standard_dialog".to_string(),
        message: "Supported standard Windows file dialog".to_string(),
        context: Some(DialogContext {
            dialog_id: dialog_id(hwnd, process_id),
            platform: "windows".to_string(),
            adapter_id: adapter_id.to_string(),
            kind,
            process_id,
            application_id: process_image_name(process_id)
                .unwrap_or_else(|| format!("pid:{process_id}")),
            title,
            bounds: DialogBounds {
                x: bounds.left,
                y: bounds.top,
                width,
                height,
            },
            current_folder: current_folder.map(|path| path.to_string_lossy().to_string()),
            filename_present: filename.is_some_and(|value| !value.trim().is_empty()),
            capabilities,
        }),
    })
}

pub(super) fn navigate_folder(
    expected_dialog_id: &str,
    target: &Path,
) -> DialogBridgeResult<DialogActionReceipt> {
    let started = Instant::now();
    let (mut hwnd, mut context) = active_expected_context(expected_dialog_id)?;
    if context.kind == DialogKind::Save
        && !context
            .capabilities
            .contains(&DialogCapability::PreserveSaveFilename)
    {
        (hwnd, context) =
            wait_for_capability(expected_dialog_id, DialogCapability::PreserveSaveFilename)?;
    }
    if context.kind == DialogKind::Save
        && !context
            .capabilities
            .contains(&DialogCapability::PreserveSaveFilename)
    {
        return Err(DialogBridgeError::Platform(
            "save filename control did not become available before navigation".to_string(),
        ));
    }
    let original_filename = dialog_filename(hwnd);
    let shell_target = shell_path(target);

    activate_expected(hwnd, expected_dialog_id)?;
    send_address_navigation(&shell_target)?;
    wait_for_folder(hwnd, expected_dialog_id, target)?;

    let mut filename_preserved = false;
    if context.kind == DialogKind::Save {
        let original = original_filename.ok_or_else(|| {
            DialogBridgeError::Platform(
                "save dialog filename control became unavailable".to_string(),
            )
        })?;
        set_dialog_filename(hwnd, &original)?;
        filename_preserved = dialog_filename(hwnd).as_deref() == Some(original.as_str());
        if !filename_preserved {
            return Err(DialogBridgeError::Platform(
                "save filename could not be restored after navigation".to_string(),
            ));
        }
    }
    ensure_expected_foreground(hwnd, expected_dialog_id)?;
    let resulting_folder = dialog_current_folder(hwnd)
        .map(|path| path.to_string_lossy().to_string())
        .or_else(|| Some(target.to_string_lossy().to_string()));
    tracing::info!(
        action = "navigate_folder",
        adapter = %context.adapter_id,
        filename_preserved,
        elapsed_millis = started.elapsed().as_millis() as u64,
        "file-dialog bridge action completed"
    );
    Ok(DialogActionReceipt {
        dialog_id: expected_dialog_id.to_string(),
        adapter_id: context.adapter_id,
        action: DialogActionKind::NavigateFolder,
        target_count: 1,
        resulting_folder,
        filename_preserved,
        confirmation_invoked: false,
        elapsed_millis: started.elapsed().as_millis() as u64,
    })
}

pub(super) fn prepare_files(
    expected_dialog_id: &str,
    files: &[PathBuf],
) -> DialogBridgeResult<DialogActionReceipt> {
    let started = Instant::now();
    let (hwnd, context) = wait_for_capability(expected_dialog_id, DialogCapability::PrepareFile)?;
    if context.kind != DialogKind::Open
        || !context
            .capabilities
            .contains(&DialogCapability::PrepareFile)
    {
        return Err(DialogBridgeError::InvalidTarget(
            "the active dialog does not support preparing Open files".to_string(),
        ));
    }
    let parent = files[0].parent().ok_or_else(|| {
        DialogBridgeError::InvalidTarget("prepared file has no parent folder".to_string())
    })?;
    activate_expected(hwnd, expected_dialog_id)?;
    send_address_navigation(&shell_path(parent))?;
    wait_for_folder(hwnd, expected_dialog_id, parent)?;

    let prepared = files
        .iter()
        .map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
                .ok_or_else(|| {
                    DialogBridgeError::InvalidTarget("prepared file has no filename".to_string())
                })
        })
        .collect::<DialogBridgeResult<Vec<_>>>()?;
    let value = if prepared.len() == 1 {
        prepared[0].clone()
    } else {
        prepared
            .iter()
            .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" ")
    };
    set_dialog_filename(hwnd, &value)?;
    let actual = dialog_filename(hwnd).unwrap_or_default();
    if actual != value {
        return Err(DialogBridgeError::Platform(
            "the dialog did not retain the prepared filename selection".to_string(),
        ));
    }
    ensure_expected_foreground(hwnd, expected_dialog_id)?;
    tracing::info!(
        action = "prepare_files",
        adapter = %context.adapter_id,
        target_count = files.len(),
        elapsed_millis = started.elapsed().as_millis() as u64,
        "file-dialog bridge action completed"
    );
    Ok(DialogActionReceipt {
        dialog_id: expected_dialog_id.to_string(),
        adapter_id: context.adapter_id,
        action: DialogActionKind::PrepareFiles,
        target_count: files.len(),
        resulting_folder: dialog_current_folder(hwnd)
            .map(|path| path.to_string_lossy().to_string())
            .or_else(|| Some(parent.to_string_lossy().to_string())),
        filename_preserved: false,
        confirmation_invoked: false,
        elapsed_millis: started.elapsed().as_millis() as u64,
    })
}

pub(super) fn list_open_folders() -> DialogBridgeResult<Vec<OpenFolder>> {
    let _apartment = ComApartment::enter()?;
    let shell_windows: IShellWindows = unsafe { CoCreateInstance(&ShellWindows, None, CLSCTX_ALL) }
        .map_err(|error| {
            DialogBridgeError::Platform(format!("could not open Explorer window registry: {error}"))
        })?;
    let count = unsafe { shell_windows.Count() }.map_err(|error| {
        DialogBridgeError::Platform(format!("could not count Explorer windows: {error}"))
    })?;
    let foreground = unsafe { GetForegroundWindow() };
    let mut folders = BTreeMap::<String, OpenFolder>::new();
    for index in 0..count {
        let variant = variant_i32(index);
        let Ok(dispatch) = (unsafe { shell_windows.Item(&variant) }) else {
            continue;
        };
        let Ok(browser) = dispatch.cast::<IWebBrowserApp>() else {
            continue;
        };
        let Ok(full_name) = (unsafe { browser.FullName() }) else {
            continue;
        };
        if !full_name
            .to_string()
            .to_ascii_lowercase()
            .ends_with("explorer.exe")
        {
            continue;
        }
        let Ok(location_url) = (unsafe { browser.LocationURL() }) else {
            continue;
        };
        let Ok(url) = Url::parse(&location_url.to_string()) else {
            continue;
        };
        let Ok(path) = url.to_file_path() else {
            continue;
        };
        if !path.is_dir() {
            continue;
        }
        let Ok(raw_hwnd) = (unsafe { browser.HWND() }) else {
            continue;
        };
        let hwnd = HWND(raw_hwnd.0 as *mut _);
        let key = normalize_path(&path);
        let item = OpenFolder {
            window_id: format!("windows-explorer:{:x}", hwnd.0 as usize),
            application_id: "explorer.exe".to_string(),
            source: OpenFolderSource::Explorer,
            path: path.to_string_lossy().to_string(),
            active: hwnd == foreground,
        };
        folders
            .entry(key)
            .and_modify(|existing| existing.active |= item.active)
            .or_insert(item);
    }
    Ok(folders.into_values().collect())
}

pub(super) fn doctor(_request_permission: bool) -> DialogBridgeResult<DialogBridgeDoctor> {
    let inspection = inspect_active()?;
    let folders = list_open_folders()?;
    Ok(DialogBridgeDoctor {
        platform: "windows".to_string(),
        adapter_available: true,
        accessibility_required: false,
        accessibility_granted: uia_available(),
        active_dialog_supported: inspection.supported,
        active_dialog_code: inspection.code,
        open_folder_count: folders.len(),
    })
}

pub(super) fn built_in_profiles() -> Vec<DialogAdapterProfile> {
    vec![DialogAdapterProfile {
        id: "windows.standard_common_dialog".to_string(),
        platform: "windows".to_string(),
        application_identity: "*".to_string(),
        dialog_role: "#32770 with IDOK confirmation".to_string(),
        window_title_rule: None,
        path_control_locator: "CDM_GETFOLDERPATH; filtered UIA address; Unicode address-bar action"
            .to_string(),
        filename_control_locator: Some(
            "filtered UIA filename ComboBox/Edit; common-dialog edt1 fallback".to_string(),
        ),
        confirmation_control_locator: Some("Win32 IDOK (inspection only)".to_string()),
        supported_modes: vec![DialogKind::Open, DialogKind::Save, DialogKind::Folder],
    }]
}

fn active_expected_context(expected_dialog_id: &str) -> DialogBridgeResult<(HWND, DialogContext)> {
    let hwnd = unsafe { GetForegroundWindow() };
    let inspection = inspect_window(hwnd)?;
    let context = inspection.context.ok_or(DialogBridgeError::NoDialog)?;
    if context.dialog_id != expected_dialog_id {
        return Err(DialogBridgeError::DialogChanged);
    }
    Ok((hwnd, context))
}

fn wait_for_capability(
    expected_dialog_id: &str,
    capability: DialogCapability,
) -> DialogBridgeResult<(HWND, DialogContext)> {
    let deadline = Instant::now() + CONTROL_READY_TIMEOUT;
    loop {
        let current = active_expected_context(expected_dialog_id)?;
        if current.1.capabilities.contains(&capability) || Instant::now() >= deadline {
            return Ok(current);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn activate_expected(hwnd: HWND, expected_dialog_id: &str) -> DialogBridgeResult<()> {
    if unsafe { GetForegroundWindow() } != hwnd {
        let _ = unsafe { SetForegroundWindow(hwnd) };
    }
    ensure_expected_foreground(hwnd, expected_dialog_id)
}

fn ensure_expected_foreground(hwnd: HWND, expected_dialog_id: &str) -> DialogBridgeResult<()> {
    let foreground = unsafe { GetForegroundWindow() };
    if foreground != hwnd || window_class(hwnd) != STANDARD_DIALOG_CLASS {
        return Err(DialogBridgeError::DialogChanged);
    }
    let confirmation_present = unsafe { GetDlgItem(Some(hwnd), IDOK) }
        .ok()
        .is_some_and(|control| !window_text(control).trim().is_empty());
    let mut process_id = 0_u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    if !confirmation_present || dialog_id(hwnd, process_id) != expected_dialog_id {
        return Err(DialogBridgeError::DialogChanged);
    }
    Ok(())
}

fn classify_dialog(ok_label: &str, has_filename: bool) -> DialogKind {
    let label = ok_label.replace('&', "").trim().to_ascii_lowercase();
    if label.contains("save") {
        DialogKind::Save
    } else if label.contains("folder")
        || (!has_filename && (label.contains("select") || label.contains("choose")))
    {
        DialogKind::Folder
    } else if label.contains("open")
        || label.contains("upload")
        || label.contains("attach")
        || label.contains("import")
        || label.contains("choose")
        || label.contains("select")
    {
        DialogKind::Open
    } else {
        DialogKind::Unknown
    }
}

fn dialog_id(hwnd: HWND, process_id: u32) -> String {
    format!("windows:{process_id}:{:x}", hwnd.0 as usize)
}

fn window_class(hwnd: HWND) -> String {
    let mut buffer = [0_u16; 256];
    let length = unsafe { GetClassNameW(hwnd, &mut buffer) }.max(0) as usize;
    String::from_utf16_lossy(&buffer[..length])
}

fn window_text(hwnd: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(hwnd) }.max(0) as usize;
    if length == 0 {
        return String::new();
    }
    let mut buffer = vec![0_u16; length + 1];
    let copied = unsafe { GetWindowTextW(hwnd, &mut buffer) }.max(0) as usize;
    String::from_utf16_lossy(&buffer[..copied])
}

fn process_image_name(process_id: u32) -> Option<String> {
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }.ok()?;
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    };
    let _ = unsafe { CloseHandle(process) };
    result.ok()?;
    Path::new(&String::from_utf16_lossy(&buffer[..length as usize]))
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
}

fn dialog_filename(hwnd: HWND) -> Option<String> {
    uia_dialog_snapshot(hwnd)
        .filename
        .or_else(|| common_dialog_text(hwnd, CDM_GETSPEC))
}

fn dialog_current_folder(hwnd: HWND) -> Option<PathBuf> {
    common_dialog_current_folder(hwnd).or_else(|| uia_dialog_snapshot(hwnd).current_folder)
}

fn common_dialog_current_folder(hwnd: HWND) -> Option<PathBuf> {
    common_dialog_text(hwnd, CDM_GETFOLDERPATH)
        .and_then(|value| {
            let value = value.strip_prefix("Address: ").unwrap_or(&value).trim();
            (!value.is_empty()).then(|| PathBuf::from(value))
        })
        .filter(|path| path.is_dir())
}

fn common_dialog_text(hwnd: HWND, message: u32) -> Option<String> {
    let mut buffer = vec![0_u16; 32_768];
    let result = unsafe {
        SendMessageW(
            hwnd,
            message,
            Some(WPARAM(buffer.len())),
            Some(LPARAM(buffer.as_mut_ptr() as isize)),
        )
    };
    if result.0 <= 0 {
        return None;
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

fn set_dialog_filename(hwnd: HWND, value: &str) -> DialogBridgeResult<()> {
    if set_uia_filename(hwnd, value) {
        return Ok(());
    }
    let wide = wide_null(value);
    unsafe {
        SendMessageW(
            hwnd,
            CDM_SETCONTROLTEXT,
            Some(WPARAM(EDT1)),
            Some(LPARAM(wide.as_ptr() as isize)),
        );
    }
    let edit = unsafe { GetDlgItem(Some(hwnd), EDT1 as i32) }.map_err(|error| {
        DialogBridgeError::Platform(format!("filename control is unavailable: {error}"))
    })?;
    unsafe {
        SendMessageW(
            hwnd,
            WM_NEXTDLGCTL,
            Some(WPARAM(edit.0 as usize)),
            Some(LPARAM(1)),
        );
    }
    if common_dialog_text(hwnd, CDM_GETSPEC).as_deref() == Some(value) {
        Ok(())
    } else {
        Err(DialogBridgeError::Platform(
            "filename control rejected the requested value".to_string(),
        ))
    }
}

fn uia_available() -> bool {
    let Ok(_apartment) = ComApartment::enter() else {
        return false;
    };
    let automation =
        unsafe { CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER) };
    let available = automation.is_ok();
    drop(automation);
    available
}

fn set_uia_filename(hwnd: HWND, value: &str) -> bool {
    let Ok(_apartment) = ComApartment::enter() else {
        return false;
    };
    let Ok(automation) = (unsafe {
        CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
    }) else {
        return false;
    };
    let Some(element) = uia_filename_element(&automation, hwnd) else {
        return false;
    };
    let Ok(pattern) =
        (unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) })
    else {
        return false;
    };
    if unsafe { pattern.CurrentIsReadOnly() }
        .map(|value| value.as_bool())
        .unwrap_or(true)
    {
        return false;
    }
    let encoded = BSTR::from(value);
    unsafe { pattern.SetValue(&encoded) }.is_ok() && unsafe { element.SetFocus() }.is_ok()
}

#[derive(Default)]
struct UiaDialogSnapshot {
    filename_available: bool,
    filename: Option<String>,
    current_folder: Option<PathBuf>,
}

fn uia_dialog_snapshot(hwnd: HWND) -> UiaDialogSnapshot {
    let Ok(_apartment) = ComApartment::enter() else {
        return UiaDialogSnapshot::default();
    };
    let Ok(automation) = (unsafe {
        CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
    }) else {
        return UiaDialogSnapshot::default();
    };
    let Some(elements) = uia_controls(
        &automation,
        hwnd,
        &[
            UIA_EditControlTypeId,
            UIA_ComboBoxControlTypeId,
            UIA_ToolBarControlTypeId,
        ],
    ) else {
        return UiaDialogSnapshot::default();
    };
    let count = unsafe { elements.Length() }
        .unwrap_or_default()
        .clamp(0, 4096);
    let mut current_folder = None;
    let mut explicit_edit = None;
    let mut explicit_combo = None;
    let mut fallback_edit = None;
    let mut fallback_combo = None;
    for index in 0..count {
        let Ok(element) = (unsafe { elements.GetElement(index) }) else {
            continue;
        };
        let id = unsafe { element.CurrentAutomationId() }
            .map(|value| value.to_string().to_ascii_lowercase())
            .unwrap_or_default();
        let name = unsafe { element.CurrentName() }
            .map(|value| value.to_string())
            .unwrap_or_default();
        let id_lower = id.to_ascii_lowercase();
        let name_lower = name.to_ascii_lowercase();
        let address_element =
            id.contains("address") || id == "41477" || name_lower.starts_with("address:");
        let value_pattern =
            unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
                .ok();
        let value = value_pattern
            .as_ref()
            .and_then(|pattern| unsafe { pattern.CurrentValue() }.ok())
            .map(|value| value.to_string());
        if current_folder.is_none() && address_element {
            current_folder =
                address_text_path(&name).or_else(|| value.as_deref().and_then(address_text_path));
        }
        let control_type = unsafe { element.CurrentControlType() }.ok();
        if control_type != Some(UIA_EditControlTypeId)
            && control_type != Some(UIA_ComboBoxControlTypeId)
        {
            continue;
        }
        let writable = value_pattern
            .as_ref()
            .and_then(|pattern| unsafe { pattern.CurrentIsReadOnly() }.ok())
            .is_some_and(|read_only| !read_only.as_bool());
        if !writable {
            continue;
        }
        let filename_identity = id_lower.contains("filename")
            || matches!(id_lower.as_str(), "1001" | "1148")
            || name_lower.contains("file name")
            || name_lower.contains("save as");
        let search_control = id_lower.contains("search") || name_lower.contains("search");
        tracing::debug!(
            automation_id = %id_lower,
            control_type = control_type.map(|value| value.0),
            address_control = address_element,
            filename_control = filename_identity,
            search_control,
            value_available = value.is_some(),
            "evaluated writable file-dialog control"
        );
        let candidate = value.unwrap_or_default();
        if filename_identity {
            if control_type == Some(UIA_EditControlTypeId) {
                explicit_edit = Some(candidate);
            } else if explicit_combo.is_none() {
                explicit_combo = Some(candidate);
            }
        } else if !address_element && !search_control {
            if control_type == Some(UIA_EditControlTypeId) && fallback_edit.is_none() {
                fallback_edit = Some(candidate);
            } else if control_type == Some(UIA_ComboBoxControlTypeId) && fallback_combo.is_none() {
                fallback_combo = Some(candidate);
            }
        }
    }
    let filename = explicit_edit
        .or(explicit_combo)
        .or(fallback_edit)
        .or(fallback_combo);
    UiaDialogSnapshot {
        filename_available: filename.is_some(),
        filename,
        current_folder,
    }
}

fn address_text_path(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    let value = value
        .get(..value.len().min(16))
        .filter(|prefix| prefix.to_ascii_lowercase().starts_with("address:"))
        .and_then(|_| value.split_once(':').map(|(_, path)| path.trim()))
        .unwrap_or(value);
    let path = PathBuf::from(value);
    (path.is_absolute() && path.is_dir()).then_some(path)
}

fn uia_filename_element(automation: &IUIAutomation, hwnd: HWND) -> Option<IUIAutomationElement> {
    let elements = uia_controls(
        automation,
        hwnd,
        &[UIA_EditControlTypeId, UIA_ComboBoxControlTypeId],
    )?;
    let count = unsafe { elements.Length() }.ok()?.clamp(0, 4096);
    let mut explicit_edit = None;
    let mut explicit_combo = None;
    let mut fallback_edit = None;
    let mut fallback_combo = None;
    for index in 0..count {
        let Ok(element) = (unsafe { elements.GetElement(index) }) else {
            continue;
        };
        let control_type = unsafe { element.CurrentControlType() }.ok();
        if control_type != Some(UIA_EditControlTypeId)
            && control_type != Some(UIA_ComboBoxControlTypeId)
        {
            continue;
        }
        let id = unsafe { element.CurrentAutomationId() }
            .map(|value| value.to_string().to_ascii_lowercase())
            .unwrap_or_default();
        let name = unsafe { element.CurrentName() }
            .map(|value| value.to_string().to_ascii_lowercase())
            .unwrap_or_default();
        let writable =
            unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
                .ok()
                .and_then(|pattern| unsafe { pattern.CurrentIsReadOnly() }.ok())
                .is_some_and(|read_only| !read_only.as_bool());
        if !writable {
            continue;
        }
        if id.contains("filename")
            || matches!(id.as_str(), "1001" | "1148")
            || name.contains("file name")
            || name.contains("save as")
        {
            if control_type == Some(UIA_EditControlTypeId) {
                explicit_edit = Some(element);
            } else if explicit_combo.is_none() {
                explicit_combo = Some(element);
            }
        } else if !name.contains("address")
            && !id.contains("address")
            && !name.contains("search")
            && !id.contains("search")
        {
            if control_type == Some(UIA_EditControlTypeId) && fallback_edit.is_none() {
                fallback_edit = Some(element);
            } else if control_type == Some(UIA_ComboBoxControlTypeId) && fallback_combo.is_none() {
                fallback_combo = Some(element);
            }
        }
    }
    explicit_edit
        .or(explicit_combo)
        .or(fallback_edit)
        .or(fallback_combo)
}

fn uia_controls(
    automation: &IUIAutomation,
    hwnd: HWND,
    control_types: &[UIA_CONTROLTYPE_ID],
) -> Option<IUIAutomationElementArray> {
    let root = unsafe { automation.ElementFromHandle(hwnd) }.ok()?;
    let mut conditions = control_types
        .iter()
        .filter_map(|control_type| {
            let value = variant_i32(control_type.0);
            unsafe { automation.CreatePropertyCondition(UIA_ControlTypePropertyId, &value) }
                .ok()
                .map(Some)
        })
        .collect::<Vec<Option<IUIAutomationCondition>>>();
    let condition = if conditions.len() == 1 {
        conditions.pop().flatten()?
    } else if conditions.len() > 1 {
        unsafe { automation.CreateOrConditionFromNativeArray(&conditions) }.ok()?
    } else {
        return None;
    };
    unsafe { root.FindAll(TreeScope_Descendants, &condition) }.ok()
}

fn send_address_navigation(path: &str) -> DialogBridgeResult<()> {
    let inputs = [
        key_input(VK_LCONTROL, false),
        key_input(VIRTUAL_KEY(b'L' as u16), false),
        key_input(VIRTUAL_KEY(b'L' as u16), true),
        key_input(VK_LCONTROL, true),
    ];
    send_inputs(&inputs)?;
    thread::sleep(Duration::from_millis(50));
    send_unicode(path)?;
    send_inputs(&[key_input(VK_RETURN, false), key_input(VK_RETURN, true)])?;
    Ok(())
}

fn key_input(key: VIRTUAL_KEY, key_up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key,
                dwFlags: if key_up {
                    KEYEVENTF_KEYUP
                } else {
                    Default::default()
                },
                ..Default::default()
            },
        },
    }
}

fn send_unicode(value: &str) -> DialogBridgeResult<()> {
    let mut inputs = Vec::with_capacity(value.encode_utf16().count() * 2);
    for unit in value.encode_utf16() {
        inputs.push(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wScan: unit,
                    dwFlags: KEYEVENTF_UNICODE,
                    ..Default::default()
                },
            },
        });
        inputs.push(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wScan: unit,
                    dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    ..Default::default()
                },
            },
        });
    }
    send_inputs(&inputs)
}

fn send_inputs(inputs: &[INPUT]) -> DialogBridgeResult<()> {
    if inputs.is_empty() {
        return Ok(());
    }
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    if sent as usize == inputs.len() {
        Ok(())
    } else {
        Err(DialogBridgeError::Platform(format!(
            "Windows accepted {sent} of {} explicit input events",
            inputs.len()
        )))
    }
}

fn wait_for_folder(hwnd: HWND, expected_dialog_id: &str, target: &Path) -> DialogBridgeResult<()> {
    let target_key = normalize_path(target);
    let deadline = Instant::now() + ACTION_TIMEOUT;
    while Instant::now() < deadline {
        ensure_expected_foreground(hwnd, expected_dialog_id)?;
        if dialog_current_folder(hwnd)
            .as_ref()
            .is_some_and(|folder| normalize_path(folder) == target_key)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(DialogBridgeError::Platform(
        "dialog navigation did not reach the requested folder before timeout".to_string(),
    ))
}

fn shell_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{stripped}")
    } else if let Some(stripped) = value.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        value.to_string()
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn variant_i32(value: i32) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VARENUM(VT_I4.0),
                Anonymous: VARIANT_0_0_0 { lVal: value },
                ..Default::default()
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_standard_confirmation_labels_conservatively() {
        assert_eq!(classify_dialog("&Open", true), DialogKind::Open);
        assert_eq!(classify_dialog("&Save", true), DialogKind::Save);
        assert_eq!(classify_dialog("Select Folder", false), DialogKind::Folder);
        assert_eq!(classify_dialog("Proceed", true), DialogKind::Unknown);
    }

    #[test]
    fn strips_windows_verbatim_prefixes_for_shell_navigation() {
        assert_eq!(
            shell_path(Path::new(r"\\?\C:\Media\Hero")),
            r"C:\Media\Hero"
        );
        assert_eq!(
            shell_path(Path::new(r"\\?\UNC\server\share\Hero")),
            r"\\server\share\Hero"
        );
    }

    #[test]
    fn built_in_profile_is_narrow_and_never_invokes_confirmation() {
        let profiles = built_in_profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].dialog_role, "#32770 with IDOK confirmation");
        assert!(profiles[0]
            .confirmation_control_locator
            .as_deref()
            .is_some_and(|locator| locator.contains("inspection only")));
    }
}
