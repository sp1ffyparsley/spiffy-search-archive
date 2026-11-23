use super::*;
use objc2_app_kit::NSWorkspace;
use std::collections::BTreeMap;
use std::ffi::{c_char, c_void};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFArrayRef = *const c_void;
type CFDictionaryRef = *const c_void;
type AXUIElementRef = *const c_void;
type AXValueRef = *const c_void;
type AXObserverRef = *const c_void;
type CGEventRef = *const c_void;
type CFRunLoopRef = *const c_void;
type CFRunLoopSourceRef = *const c_void;
type AXError = i32;

const K_AX_ERROR_SUCCESS: AXError = 0;
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_AX_VALUE_CGPOINT_TYPE: i32 = 1;
const K_AX_VALUE_CGSIZE_TYPE: i32 = 2;
const K_CG_HID_EVENT_TAP: u32 = 0;
const K_CG_EVENT_FLAG_MASK_SHIFT: u64 = 0x0002_0000;
const K_CG_EVENT_FLAG_MASK_COMMAND: u64 = 0x0010_0000;
const KEY_A: u16 = 0;
const KEY_G: u16 = 5;
const KEY_RETURN: u16 = 36;
const ACTION_SETTLE: Duration = Duration::from_millis(250);
const ACTION_TIMEOUT: Duration = Duration::from_secs(3);
const OBSERVER_WAIT_SLICE: Duration = Duration::from_millis(50);
const MAX_AX_NODES: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CGSize {
    width: f64,
    height: f64,
}

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
    fn AXUIElementCreateApplication(pid: i32) -> AXUIElementRef;
    fn AXUIElementCopyAttributeValue(
        element: AXUIElementRef,
        attribute: CFStringRef,
        value: *mut CFTypeRef,
    ) -> AXError;
    fn AXUIElementSetAttributeValue(
        element: AXUIElementRef,
        attribute: CFStringRef,
        value: CFTypeRef,
    ) -> AXError;
    fn AXObserverCreate(
        application: i32,
        callback: unsafe extern "C" fn(AXObserverRef, AXUIElementRef, CFStringRef, *mut c_void),
        observer: *mut AXObserverRef,
    ) -> AXError;
    fn AXObserverAddNotification(
        observer: AXObserverRef,
        element: AXUIElementRef,
        notification: CFStringRef,
        context: *mut c_void,
    ) -> AXError;
    fn AXObserverRemoveNotification(
        observer: AXObserverRef,
        element: AXUIElementRef,
        notification: CFStringRef,
    ) -> AXError;
    fn AXObserverGetRunLoopSource(observer: AXObserverRef) -> CFRunLoopSourceRef;
    fn AXValueGetType(value: AXValueRef) -> i32;
    fn AXValueGetValue(value: AXValueRef, value_type: i32, output: *mut c_void) -> bool;
    fn CGEventCreateKeyboardEvent(
        source: *const c_void,
        virtual_key: u16,
        key_down: bool,
    ) -> CGEventRef;
    fn CGEventSetFlags(event: CGEventRef, flags: u64);
    fn CGEventKeyboardSetUnicodeString(event: CGEventRef, length: usize, text: *const u16);
    fn CGEventPost(tap: u32, event: CGEventRef);

    static kAXFocusedWindowAttribute: CFStringRef;
    static kAXWindowsAttribute: CFStringRef;
    static kAXSheetsAttribute: CFStringRef;
    static kAXRoleAttribute: CFStringRef;
    static kAXTitleAttribute: CFStringRef;
    static kAXDescriptionAttribute: CFStringRef;
    static kAXIdentifierAttribute: CFStringRef;
    static kAXValueAttribute: CFStringRef;
    static kAXPositionAttribute: CFStringRef;
    static kAXSizeAttribute: CFStringRef;
    static kAXChildrenAttribute: CFStringRef;
    static kAXDocumentAttribute: CFStringRef;
    static kAXFocusedAttribute: CFStringRef;
    static kAXTrustedCheckOptionPrompt: CFStringRef;
    static kAXFocusedWindowChangedNotification: CFStringRef;
    static kAXFocusedUIElementChangedNotification: CFStringRef;
    static kAXSheetCreatedNotification: CFStringRef;
    static kAXUIElementDestroyedNotification: CFStringRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRetain(value: CFTypeRef) -> CFTypeRef;
    fn CFRelease(value: CFTypeRef);
    fn CFGetTypeID(value: CFTypeRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(value: CFStringRef) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> bool;
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        value: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetCount(array: CFArrayRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, index: isize) -> *const c_void;
    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(run_loop: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRemoveSource(run_loop: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRunInMode(
        mode: CFStringRef,
        seconds: f64,
        return_after_source_handled: bool,
    ) -> i32;
    static kCFBooleanTrue: CFTypeRef;
    static kCFRunLoopDefaultMode: CFStringRef;
}

struct OwnedCf(CFTypeRef);

impl OwnedCf {
    fn new(value: CFTypeRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }

    fn retained(value: CFTypeRef) -> Option<Self> {
        if value.is_null() {
            None
        } else {
            Some(Self(unsafe { CFRetain(value) }))
        }
    }

    fn as_type(&self) -> CFTypeRef {
        self.0
    }

    fn as_ax(&self) -> AXUIElementRef {
        self.0
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

struct AxSubscription {
    element: OwnedCf,
    notification: CFStringRef,
}

struct AxTransitionObserver {
    observer: OwnedCf,
    run_loop: CFRunLoopRef,
    source: CFRunLoopSourceRef,
    signalled: Box<AtomicBool>,
    subscriptions: Vec<AxSubscription>,
}

impl AxTransitionObserver {
    fn new(pid: i32, panel: AXUIElementRef) -> Option<Self> {
        let mut observer = ptr::null();
        if unsafe { AXObserverCreate(pid, ax_transition_callback, &mut observer) }
            != K_AX_ERROR_SUCCESS
        {
            return None;
        }
        let observer = OwnedCf::new(observer)?;
        let source = unsafe { AXObserverGetRunLoopSource(observer.as_type()) };
        let run_loop = unsafe { CFRunLoopGetCurrent() };
        if source.is_null() || run_loop.is_null() {
            return None;
        }
        unsafe { CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode) };
        let mut result = Self {
            observer,
            run_loop,
            source,
            signalled: Box::new(AtomicBool::new(false)),
            subscriptions: Vec::new(),
        };
        if let Some(application) = OwnedCf::new(unsafe { AXUIElementCreateApplication(pid) }) {
            result.subscribe(application.as_ax(), unsafe {
                kAXFocusedWindowChangedNotification
            });
            result.subscribe(application.as_ax(), unsafe {
                kAXFocusedUIElementChangedNotification
            });
            result.subscribe(application.as_ax(), unsafe { kAXSheetCreatedNotification });
        }
        result.subscribe(panel, unsafe { kAXUIElementDestroyedNotification });
        Some(result)
    }

    fn subscribe(&mut self, element: AXUIElementRef, notification: CFStringRef) {
        let Some(element) = OwnedCf::retained(element) else {
            return;
        };
        let context = self.signalled.as_ref() as *const AtomicBool as *mut c_void;
        if unsafe {
            AXObserverAddNotification(
                self.observer.as_type(),
                element.as_ax(),
                notification,
                context,
            )
        } == K_AX_ERROR_SUCCESS
        {
            self.subscriptions.push(AxSubscription {
                element,
                notification,
            });
        }
    }

    fn wait_slice(&self, duration: Duration) {
        if !self.signalled.swap(false, Ordering::AcqRel) {
            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, duration.as_secs_f64(), true) };
        }
    }
}

impl Drop for AxTransitionObserver {
    fn drop(&mut self) {
        unsafe {
            CFRunLoopRemoveSource(self.run_loop, self.source, kCFRunLoopDefaultMode);
        }
        for subscription in &self.subscriptions {
            unsafe {
                AXObserverRemoveNotification(
                    self.observer.as_type(),
                    subscription.element.as_ax(),
                    subscription.notification,
                )
            };
        }
    }
}

unsafe extern "C" fn ax_transition_callback(
    _observer: AXObserverRef,
    _element: AXUIElementRef,
    _notification: CFStringRef,
    context: *mut c_void,
) {
    if let Some(signalled) = unsafe { (context as *const AtomicBool).as_ref() } {
        signalled.store(true, Ordering::Release);
    }
}

struct FrontApplication {
    pid: i32,
    application_id: String,
}

pub(super) fn inspect_active() -> DialogBridgeResult<DialogInspection> {
    if !unsafe { AXIsProcessTrusted() } {
        return Ok(DialogInspection::unsupported(
            "accessibility_required",
            "Accessibility permission is required only for the macOS file-dialog bridge",
        ));
    }
    let app = front_application().ok_or_else(|| {
        DialogBridgeError::Platform("NSWorkspace has no frontmost application".to_string())
    })?;
    let app_element =
        OwnedCf::new(unsafe { AXUIElementCreateApplication(app.pid) }).ok_or_else(|| {
            DialogBridgeError::Platform("could not create app AX element".to_string())
        })?;
    let Some(window) = copy_attribute(app_element.as_ax(), unsafe { kAXFocusedWindowAttribute })
    else {
        return Ok(DialogInspection::unsupported(
            "no_focused_window",
            "The frontmost macOS application has no focused window",
        ));
    };
    let panel = first_sheet(window.as_ax()).unwrap_or(window);
    inspect_panel(panel.as_ax(), &app)
}

fn inspect_panel(
    panel: AXUIElementRef,
    app: &FrontApplication,
) -> DialogBridgeResult<DialogInspection> {
    let role = string_attribute(panel, unsafe { kAXRoleAttribute }).unwrap_or_default();
    if !matches!(role.as_str(), "AXWindow" | "AXSheet" | "AXDialog") {
        return Ok(DialogInspection::unsupported(
            "not_a_standard_file_panel",
            "The focused AX element is not a supported Open/Save panel",
        ));
    }
    let title = string_attribute(panel, unsafe { kAXTitleAttribute }).unwrap_or_default();
    let nodes = collect_nodes(panel);
    let button_labels = nodes
        .iter()
        .filter(|node| node.role == "AXButton")
        .flat_map(|node| [node.title.as_str(), node.description.as_str()])
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let filename = filename_node(&nodes).and_then(|node| node.value.clone());
    let kind = classify_panel(&button_labels, filename.is_some());
    if kind == DialogKind::Unknown {
        return Ok(DialogInspection::unsupported(
            "unrecognized_standard_file_panel",
            "The focused panel does not expose a recognized Open, Save, or Choose action",
        ));
    }
    let (position, size) = panel_geometry(panel);
    let dialog_id = panel_id(app.pid, &app.application_id, &title, position, size);
    let mut capabilities = vec![
        DialogCapability::NavigateFolder,
        DialogCapability::AnchorOverlay,
    ];
    if kind == DialogKind::Open {
        capabilities.push(DialogCapability::PrepareFile);
    }
    if kind == DialogKind::Save && filename.is_some() {
        capabilities.push(DialogCapability::PreserveSaveFilename);
    }
    Ok(DialogInspection {
        supported: true,
        code: "standard_panel".to_string(),
        message: "Supported standard macOS file panel".to_string(),
        context: Some(DialogContext {
            dialog_id,
            platform: "macos".to_string(),
            adapter_id: "macos_standard_ax".to_string(),
            kind,
            process_id: app.pid.max(0) as u32,
            application_id: app.application_id.clone(),
            title,
            bounds: DialogBounds {
                x: position.x.round() as i32,
                y: position.y.round() as i32,
                width: size.width.max(0.0).round() as u32,
                height: size.height.max(0.0).round() as u32,
            },
            current_folder: None,
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
    let (panel, context) = expected_panel(expected_dialog_id)?;
    let nodes = collect_nodes(panel.as_ax());
    let original_filename = filename_node(&nodes).and_then(|node| node.value.clone());
    let observer = AxTransitionObserver::new(context.process_id as i32, panel.as_ax());
    go_to_path(target)?;
    let (current_panel, current_context) =
        wait_for_expected_panel(expected_dialog_id, observer.as_ref())?;
    let mut filename_preserved = false;
    if context.kind == DialogKind::Save {
        let original = original_filename.ok_or_else(|| {
            DialogBridgeError::Platform("save panel filename field became unavailable".to_string())
        })?;
        set_filename_value(current_panel.as_ax(), &original)?;
        filename_preserved =
            filename_value(current_panel.as_ax()).as_deref() == Some(original.as_str());
        if !filename_preserved {
            return Err(DialogBridgeError::Platform(
                "save filename could not be restored after folder navigation".to_string(),
            ));
        }
    }
    tracing::info!(
        action = "navigate_folder",
        adapter = %current_context.adapter_id,
        filename_preserved,
        elapsed_millis = started.elapsed().as_millis() as u64,
        "file-dialog bridge action completed"
    );
    Ok(DialogActionReceipt {
        dialog_id: expected_dialog_id.to_string(),
        adapter_id: current_context.adapter_id,
        action: DialogActionKind::NavigateFolder,
        target_count: 1,
        resulting_folder: Some(target.to_string_lossy().to_string()),
        filename_preserved,
        confirmation_invoked: false,
        elapsed_millis: started.elapsed().as_millis() as u64,
    })
}

pub(super) fn prepare_files(
    expected_dialog_id: &str,
    files: &[PathBuf],
) -> DialogBridgeResult<DialogActionReceipt> {
    if files.len() != 1 {
        return Err(DialogBridgeError::InvalidTarget(
            "macOS AX preparation currently requires exactly one file".to_string(),
        ));
    }
    let started = Instant::now();
    let (panel, context) = expected_panel(expected_dialog_id)?;
    if context.kind != DialogKind::Open {
        return Err(DialogBridgeError::InvalidTarget(
            "the active macOS panel is not an Open panel".to_string(),
        ));
    }
    let observer = AxTransitionObserver::new(context.process_id as i32, panel.as_ax());
    go_to_path(&files[0])?;
    let (_panel, current) = wait_for_expected_panel(expected_dialog_id, observer.as_ref())?;
    tracing::info!(
        action = "prepare_files",
        adapter = %current.adapter_id,
        target_count = 1,
        elapsed_millis = started.elapsed().as_millis() as u64,
        "file-dialog bridge action completed"
    );
    Ok(DialogActionReceipt {
        dialog_id: expected_dialog_id.to_string(),
        adapter_id: current.adapter_id,
        action: DialogActionKind::PrepareFiles,
        target_count: 1,
        resulting_folder: files[0]
            .parent()
            .map(|path| path.to_string_lossy().to_string()),
        filename_preserved: false,
        confirmation_invoked: false,
        elapsed_millis: started.elapsed().as_millis() as u64,
    })
}

pub(super) fn list_open_folders() -> DialogBridgeResult<Vec<OpenFolder>> {
    if !unsafe { AXIsProcessTrusted() } {
        return Err(DialogBridgeError::AccessibilityRequired);
    }
    let workspace = NSWorkspace::sharedWorkspace();
    let Some(finder) = workspace.runningApplications().iter().find(|app| {
        app.bundleIdentifier()
            .as_deref()
            .is_some_and(|id| id.to_string() == "com.apple.finder")
    }) else {
        return Ok(Vec::new());
    };
    let pid = finder.processIdentifier();
    if pid <= 0 {
        return Ok(Vec::new());
    }
    let app_element =
        OwnedCf::new(unsafe { AXUIElementCreateApplication(pid) }).ok_or_else(|| {
            DialogBridgeError::Platform("could not create Finder AX element".to_string())
        })?;
    let Some(windows) = copy_attribute(app_element.as_ax(), unsafe { kAXWindowsAttribute }) else {
        return Ok(Vec::new());
    };
    let focused = copy_attribute(app_element.as_ax(), unsafe { kAXFocusedWindowAttribute });
    let focused_id = focused
        .as_ref()
        .map(|window| finder_window_id(pid, window.as_ax()));
    let mut result = BTreeMap::new();
    for window in array_values(windows.as_type()) {
        let document = string_attribute(window, unsafe { kAXDocumentAttribute });
        let Some(path) = document
            .as_deref()
            .and_then(|value| Url::parse(value).ok())
            .and_then(|url| url.to_file_path().ok())
            .filter(|path| path.is_dir())
        else {
            continue;
        };
        let window_id = finder_window_id(pid, window);
        let item = OpenFolder {
            window_id: window_id.clone(),
            application_id: "com.apple.finder".to_string(),
            source: OpenFolderSource::Finder,
            path: path.to_string_lossy().to_string(),
            active: focused_id.as_deref() == Some(window_id.as_str()),
        };
        result.insert(path.to_string_lossy().to_string(), item);
    }
    Ok(result.into_values().collect())
}

pub(super) fn doctor(request_permission: bool) -> DialogBridgeResult<DialogBridgeDoctor> {
    let trusted = if request_permission {
        request_accessibility_permission()
    } else {
        unsafe { AXIsProcessTrusted() }
    };
    let inspection = inspect_active()?;
    let open_folder_count = if trusted {
        list_open_folders()?.len()
    } else {
        0
    };
    Ok(DialogBridgeDoctor {
        platform: "macos".to_string(),
        adapter_available: true,
        accessibility_required: true,
        accessibility_granted: trusted,
        active_dialog_supported: inspection.supported,
        active_dialog_code: inspection.code,
        open_folder_count,
    })
}

pub(super) fn built_in_profiles() -> Vec<DialogAdapterProfile> {
    vec![DialogAdapterProfile {
        id: "macos.standard_file_panel".to_string(),
        platform: "macos".to_string(),
        application_identity: "*".to_string(),
        dialog_role: "AXWindow/AXSheet with Open, Save, or Choose action".to_string(),
        window_title_rule: None,
        path_control_locator: "AX panel; system Go to Folder action; AXObserver-assisted settle"
            .to_string(),
        filename_control_locator: Some("writable AXTextField with Save As identity".to_string()),
        confirmation_control_locator: Some("AXButton (inspection only)".to_string()),
        supported_modes: vec![DialogKind::Open, DialogKind::Save, DialogKind::Folder],
    }]
}

fn expected_panel(expected_dialog_id: &str) -> DialogBridgeResult<(OwnedCf, DialogContext)> {
    let app = front_application().ok_or(DialogBridgeError::DialogChanged)?;
    let app_element = OwnedCf::new(unsafe { AXUIElementCreateApplication(app.pid) })
        .ok_or(DialogBridgeError::DialogChanged)?;
    let window = copy_attribute(app_element.as_ax(), unsafe { kAXFocusedWindowAttribute })
        .ok_or(DialogBridgeError::DialogChanged)?;
    let panel = first_sheet(window.as_ax()).unwrap_or(window);
    let inspection = inspect_panel(panel.as_ax(), &app)?;
    let context = inspection.context.ok_or(DialogBridgeError::NoDialog)?;
    if context.dialog_id != expected_dialog_id {
        return Err(DialogBridgeError::DialogChanged);
    }
    Ok((panel, context))
}

fn wait_for_expected_panel(
    expected_dialog_id: &str,
    observer: Option<&AxTransitionObserver>,
) -> DialogBridgeResult<(OwnedCf, DialogContext)> {
    let started = Instant::now();
    let deadline = started + ACTION_TIMEOUT;
    loop {
        if started.elapsed() >= ACTION_SETTLE {
            match expected_panel(expected_dialog_id) {
                Ok(panel) => return Ok(panel),
                Err(DialogBridgeError::DialogChanged | DialogBridgeError::NoDialog) => {}
                Err(error) => return Err(error),
            }
        }
        if Instant::now() >= deadline {
            return Err(DialogBridgeError::Platform(
                "macOS file panel did not settle after navigation before timeout".to_string(),
            ));
        }
        if let Some(observer) = observer {
            observer.wait_slice(OBSERVER_WAIT_SLICE);
        } else {
            thread::sleep(OBSERVER_WAIT_SLICE);
        }
    }
}

fn front_application() -> Option<FrontApplication> {
    let application = NSWorkspace::sharedWorkspace().frontmostApplication()?;
    let pid = application.processIdentifier();
    if pid <= 0 {
        return None;
    }
    let application_id = application
        .bundleIdentifier()
        .map(|value| value.to_string())
        .or_else(|| application.localizedName().map(|value| value.to_string()))
        .unwrap_or_else(|| format!("pid:{pid}"));
    Some(FrontApplication {
        pid,
        application_id,
    })
}

fn first_sheet(window: AXUIElementRef) -> Option<OwnedCf> {
    let sheets = copy_attribute(window, unsafe { kAXSheetsAttribute })?;
    array_values(sheets.as_type())
        .into_iter()
        .next()
        .and_then(OwnedCf::retained)
}

struct AxNode {
    element: OwnedCf,
    role: String,
    title: String,
    description: String,
    identifier: String,
    value: Option<String>,
}

fn collect_nodes(root: AXUIElementRef) -> Vec<AxNode> {
    let Some(root) = OwnedCf::retained(root) else {
        return Vec::new();
    };
    let mut pending = vec![root];
    let mut nodes = Vec::new();
    while let Some(element) = pending.pop() {
        if nodes.len() >= MAX_AX_NODES {
            break;
        }
        if let Some(children) = copy_attribute(element.as_ax(), unsafe { kAXChildrenAttribute }) {
            for child in array_values(children.as_type()).into_iter().rev() {
                if let Some(child) = OwnedCf::retained(child) {
                    pending.push(child);
                }
            }
        }
        nodes.push(AxNode {
            role: string_attribute(element.as_ax(), unsafe { kAXRoleAttribute })
                .unwrap_or_default(),
            title: string_attribute(element.as_ax(), unsafe { kAXTitleAttribute })
                .unwrap_or_default(),
            description: string_attribute(element.as_ax(), unsafe { kAXDescriptionAttribute })
                .unwrap_or_default(),
            identifier: string_attribute(element.as_ax(), unsafe { kAXIdentifierAttribute })
                .unwrap_or_default(),
            value: string_attribute(element.as_ax(), unsafe { kAXValueAttribute }),
            element,
        });
    }
    nodes
}

fn filename_node(nodes: &[AxNode]) -> Option<&AxNode> {
    nodes.iter().find(|node| {
        if node.role != "AXTextField" {
            return false;
        }
        let identity =
            format!("{} {} {}", node.title, node.description, node.identifier).to_ascii_lowercase();
        !identity.contains("search")
            && (identity.contains("save as")
                || identity.contains("filename")
                || identity.contains("file name"))
    })
}

fn filename_value(panel: AXUIElementRef) -> Option<String> {
    let nodes = collect_nodes(panel);
    filename_node(&nodes).and_then(|node| node.value.clone())
}

fn set_filename_value(panel: AXUIElementRef, value: &str) -> DialogBridgeResult<()> {
    let nodes = collect_nodes(panel);
    let node = filename_node(&nodes).ok_or_else(|| {
        DialogBridgeError::Platform("save filename AXTextField is unavailable".to_string())
    })?;
    let encoded = cf_string(value)?;
    let result = unsafe {
        AXUIElementSetAttributeValue(node.element.as_ax(), kAXValueAttribute, encoded.as_type())
    };
    if result != K_AX_ERROR_SUCCESS {
        return Err(DialogBridgeError::Platform(format!(
            "AX filename update failed with code {result}"
        )));
    }
    let focus = unsafe {
        AXUIElementSetAttributeValue(node.element.as_ax(), kAXFocusedAttribute, kCFBooleanTrue)
    };
    if focus != K_AX_ERROR_SUCCESS {
        return Err(DialogBridgeError::Platform(format!(
            "AX filename focus failed with code {focus}"
        )));
    }
    Ok(())
}

fn classify_panel(labels: &[&str], has_filename: bool) -> DialogKind {
    let labels = labels
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if labels.iter().any(|value| value == "save") {
        DialogKind::Save
    } else if labels
        .iter()
        .any(|value| value.contains("choose") || value.contains("select"))
        && !has_filename
    {
        DialogKind::Folder
    } else if labels.iter().any(|value| {
        value == "open"
            || value.contains("upload")
            || value.contains("attach")
            || value.contains("import")
    }) {
        DialogKind::Open
    } else {
        DialogKind::Unknown
    }
}

fn panel_geometry(panel: AXUIElementRef) -> (CGPoint, CGSize) {
    let mut point = CGPoint::default();
    let mut size = CGSize::default();
    if let Some(value) = copy_attribute(panel, unsafe { kAXPositionAttribute }) {
        if unsafe { AXValueGetType(value.as_type()) } == K_AX_VALUE_CGPOINT_TYPE {
            unsafe {
                AXValueGetValue(
                    value.as_type(),
                    K_AX_VALUE_CGPOINT_TYPE,
                    (&mut point as *mut CGPoint).cast(),
                )
            };
        }
    }
    if let Some(value) = copy_attribute(panel, unsafe { kAXSizeAttribute }) {
        if unsafe { AXValueGetType(value.as_type()) } == K_AX_VALUE_CGSIZE_TYPE {
            unsafe {
                AXValueGetValue(
                    value.as_type(),
                    K_AX_VALUE_CGSIZE_TYPE,
                    (&mut size as *mut CGSize).cast(),
                )
            };
        }
    }
    (point, size)
}

fn panel_id(
    pid: i32,
    application_id: &str,
    title: &str,
    position: CGPoint,
    size: CGSize,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [application_id.as_bytes(), title.as_bytes()] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    for value in [position.x, position.y, size.width, size.height] {
        hasher.update(&value.to_bits().to_le_bytes());
    }
    let digest = hasher.finalize();
    let short = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or_default());
    format!("macos:{pid}:{short:016x}")
}

fn finder_window_id(pid: i32, window: AXUIElementRef) -> String {
    let title = string_attribute(window, unsafe { kAXTitleAttribute }).unwrap_or_default();
    let (position, size) = panel_geometry(window);
    panel_id(pid, "com.apple.finder", &title, position, size).replace("macos:", "macos-finder:")
}

fn copy_attribute(element: AXUIElementRef, attribute: CFStringRef) -> Option<OwnedCf> {
    let mut value = ptr::null();
    let result = unsafe { AXUIElementCopyAttributeValue(element, attribute, &mut value) };
    (result == K_AX_ERROR_SUCCESS)
        .then(|| OwnedCf::new(value))
        .flatten()
}

fn string_attribute(element: AXUIElementRef, attribute: CFStringRef) -> Option<String> {
    let value = copy_attribute(element, attribute)?;
    cf_string_to_rust(value.as_type())
}

fn cf_string_to_rust(value: CFTypeRef) -> Option<String> {
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return None;
    }
    let length = unsafe { CFStringGetLength(value) };
    let capacity = unsafe { CFStringGetMaximumSizeForEncoding(length, K_CF_STRING_ENCODING_UTF8) }
        .saturating_add(1);
    if capacity <= 0 {
        return Some(String::new());
    }
    let mut buffer = vec![0_u8; capacity as usize];
    if !unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast(),
            capacity,
            K_CF_STRING_ENCODING_UTF8,
        )
    } {
        return None;
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).ok()
}

fn array_values(value: CFTypeRef) -> Vec<CFTypeRef> {
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFArrayGetTypeID() } {
        return Vec::new();
    }
    let count = unsafe { CFArrayGetCount(value) }.clamp(0, MAX_AX_NODES as isize);
    (0..count)
        .map(|index| unsafe { CFArrayGetValueAtIndex(value, index) })
        .filter(|value| !value.is_null())
        .collect()
}

fn cf_string(value: &str) -> DialogBridgeResult<OwnedCf> {
    let mut encoded = value.as_bytes().to_vec();
    if encoded.contains(&0) {
        return Err(DialogBridgeError::InvalidTarget(
            "AX string contains a NUL byte".to_string(),
        ));
    }
    encoded.push(0);
    OwnedCf::new(unsafe {
        CFStringCreateWithCString(
            ptr::null(),
            encoded.as_ptr().cast(),
            K_CF_STRING_ENCODING_UTF8,
        )
    })
    .ok_or_else(|| DialogBridgeError::Platform("could not create AX string".to_string()))
}

fn go_to_path(path: &Path) -> DialogBridgeResult<()> {
    let value = path.to_string_lossy();
    post_key(
        KEY_G,
        true,
        K_CG_EVENT_FLAG_MASK_COMMAND | K_CG_EVENT_FLAG_MASK_SHIFT,
    )?;
    post_key(
        KEY_G,
        false,
        K_CG_EVENT_FLAG_MASK_COMMAND | K_CG_EVENT_FLAG_MASK_SHIFT,
    )?;
    thread::sleep(Duration::from_millis(120));
    post_key(KEY_A, true, K_CG_EVENT_FLAG_MASK_COMMAND)?;
    post_key(KEY_A, false, K_CG_EVENT_FLAG_MASK_COMMAND)?;
    post_unicode(&value)?;
    post_key(KEY_RETURN, true, 0)?;
    post_key(KEY_RETURN, false, 0)?;
    Ok(())
}

fn post_key(key: u16, down: bool, flags: u64) -> DialogBridgeResult<()> {
    let event = OwnedCf::new(unsafe { CGEventCreateKeyboardEvent(ptr::null(), key, down) })
        .ok_or_else(|| DialogBridgeError::Platform("could not create CGEvent".to_string()))?;
    if flags != 0 {
        unsafe { CGEventSetFlags(event.as_type(), flags) };
    }
    unsafe { CGEventPost(K_CG_HID_EVENT_TAP, event.as_type()) };
    Ok(())
}

fn post_unicode(value: &str) -> DialogBridgeResult<()> {
    let encoded = value.encode_utf16().collect::<Vec<_>>();
    for chunk in encoded.chunks(20) {
        let down = OwnedCf::new(unsafe { CGEventCreateKeyboardEvent(ptr::null(), 0, true) })
            .ok_or_else(|| {
                DialogBridgeError::Platform("could not create text CGEvent".to_string())
            })?;
        unsafe {
            CGEventKeyboardSetUnicodeString(down.as_type(), chunk.len(), chunk.as_ptr());
            CGEventPost(K_CG_HID_EVENT_TAP, down.as_type());
        }
        let up = OwnedCf::new(unsafe { CGEventCreateKeyboardEvent(ptr::null(), 0, false) })
            .ok_or_else(|| {
                DialogBridgeError::Platform("could not create text CGEvent".to_string())
            })?;
        unsafe {
            CGEventKeyboardSetUnicodeString(up.as_type(), chunk.len(), chunk.as_ptr());
            CGEventPost(K_CG_HID_EVENT_TAP, up.as_type());
        }
    }
    Ok(())
}

fn request_accessibility_permission() -> bool {
    let keys = [unsafe { kAXTrustedCheckOptionPrompt }];
    let values = [unsafe { kCFBooleanTrue }];
    let options = OwnedCf::new(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            ptr::null(),
            ptr::null(),
        )
    });
    options
        .as_ref()
        .is_some_and(|options| unsafe { AXIsProcessTrustedWithOptions(options.as_type()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_labels_are_classified_without_title_heuristics() {
        assert_eq!(classify_panel(&["Save", "Cancel"], true), DialogKind::Save);
        assert_eq!(classify_panel(&["Open", "Cancel"], false), DialogKind::Open);
        assert_eq!(
            classify_panel(&["Choose", "Cancel"], false),
            DialogKind::Folder
        );
        assert_eq!(classify_panel(&["Continue"], true), DialogKind::Unknown);
    }
}
