use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

const MAX_DIALOG_ID_BYTES: usize = 256;
const MAX_PREPARED_FILES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialogKind {
    Open,
    Save,
    Folder,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialogCapability {
    NavigateFolder,
    PrepareFile,
    PrepareMultipleFiles,
    PreserveSaveFilename,
    ReadCurrentFolder,
    AnchorOverlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogBounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogContext {
    pub dialog_id: String,
    pub platform: String,
    pub adapter_id: String,
    pub kind: DialogKind,
    pub process_id: u32,
    pub application_id: String,
    pub title: String,
    pub bounds: DialogBounds,
    pub current_folder: Option<String>,
    pub filename_present: bool,
    pub capabilities: Vec<DialogCapability>,
}

impl fmt::Debug for DialogContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DialogContext")
            .field("dialog_id", &self.dialog_id)
            .field("platform", &self.platform)
            .field("adapter_id", &self.adapter_id)
            .field("kind", &self.kind)
            .field("process_id", &self.process_id)
            .field("application_id", &self.application_id)
            .field("title", &"[redacted]")
            .field(
                "current_folder",
                &self.current_folder.as_ref().map(|_| "[redacted]"),
            )
            .field("filename_present", &self.filename_present)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogInspection {
    pub supported: bool,
    pub code: String,
    pub message: String,
    pub context: Option<DialogContext>,
}

impl DialogInspection {
    fn unsupported(code: &str, message: &str) -> Self {
        Self {
            supported: false,
            code: code.to_string(),
            message: message.to_string(),
            context: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DialogActionKind {
    NavigateFolder,
    PrepareFiles,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogActionReceipt {
    pub dialog_id: String,
    pub adapter_id: String,
    pub action: DialogActionKind,
    pub target_count: usize,
    pub resulting_folder: Option<String>,
    pub filename_preserved: bool,
    pub confirmation_invoked: bool,
    pub elapsed_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenFolderSource {
    Explorer,
    Finder,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFolder {
    pub window_id: String,
    pub application_id: String,
    pub source: OpenFolderSource,
    pub path: String,
    pub active: bool,
}

impl fmt::Debug for OpenFolder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFolder")
            .field("window_id", &self.window_id)
            .field("application_id", &self.application_id)
            .field("source", &self.source)
            .field("path", &"[redacted]")
            .field("active", &self.active)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogBridgeDoctor {
    pub platform: String,
    pub adapter_available: bool,
    pub accessibility_required: bool,
    pub accessibility_granted: bool,
    pub active_dialog_supported: bool,
    pub active_dialog_code: String,
    pub open_folder_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialogAdapterProfile {
    pub id: String,
    pub platform: String,
    pub application_identity: String,
    pub dialog_role: String,
    pub window_title_rule: Option<String>,
    pub path_control_locator: String,
    pub filename_control_locator: Option<String>,
    pub confirmation_control_locator: Option<String>,
    pub supported_modes: Vec<DialogKind>,
}

#[derive(Debug, thiserror::Error)]
pub enum DialogBridgeError {
    #[error("no supported foreground file dialog is active")]
    NoDialog,
    #[error("the foreground dialog changed before the action could run")]
    DialogChanged,
    #[error("invalid dialog target: {0}")]
    InvalidTarget(String),
    #[error("Accessibility permission is required for the macOS file-dialog bridge")]
    AccessibilityRequired,
    #[error("file-dialog adapter is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("file-dialog platform operation failed: {0}")]
    Platform(String),
}

impl DialogBridgeError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoDialog => "no_supported_dialog",
            Self::DialogChanged => "dialog_changed",
            Self::InvalidTarget(_) => "invalid_target",
            Self::AccessibilityRequired => "accessibility_required",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Platform(_) => "platform_error",
        }
    }
}

pub type DialogBridgeResult<T> = Result<T, DialogBridgeError>;

pub fn inspect_active() -> DialogBridgeResult<DialogInspection> {
    imp::inspect_active()
}

pub fn navigate_folder(
    expected_dialog_id: &str,
    target: &Path,
) -> DialogBridgeResult<DialogActionReceipt> {
    validate_dialog_id(expected_dialog_id)?;
    let target = canonical_directory(target)?;
    imp::navigate_folder(expected_dialog_id, &target)
}

pub fn prepare_files(
    expected_dialog_id: &str,
    files: &[PathBuf],
) -> DialogBridgeResult<DialogActionReceipt> {
    validate_dialog_id(expected_dialog_id)?;
    if files.is_empty() || files.len() > MAX_PREPARED_FILES {
        return Err(DialogBridgeError::InvalidTarget(format!(
            "file count must be between 1 and {MAX_PREPARED_FILES}"
        )));
    }
    let canonical = files
        .iter()
        .map(|path| canonical_file(path))
        .collect::<DialogBridgeResult<Vec<_>>>()?;
    let parent = canonical[0].parent().ok_or_else(|| {
        DialogBridgeError::InvalidTarget("prepared file has no parent folder".to_string())
    })?;
    if canonical
        .iter()
        .any(|path| path.parent().is_none_or(|candidate| candidate != parent))
    {
        return Err(DialogBridgeError::InvalidTarget(
            "all prepared files must share one parent folder".to_string(),
        ));
    }
    imp::prepare_files(expected_dialog_id, &canonical)
}

pub fn list_open_folders() -> DialogBridgeResult<Vec<OpenFolder>> {
    imp::list_open_folders()
}

pub fn doctor(request_permission: bool) -> DialogBridgeResult<DialogBridgeDoctor> {
    imp::doctor(request_permission)
}

pub fn built_in_profiles() -> Vec<DialogAdapterProfile> {
    imp::built_in_profiles()
}

fn validate_dialog_id(dialog_id: &str) -> DialogBridgeResult<()> {
    if dialog_id.is_empty()
        || dialog_id.len() > MAX_DIALOG_ID_BYTES
        || dialog_id.contains(['\0', '\r', '\n'])
    {
        return Err(DialogBridgeError::InvalidTarget(
            "dialog identifier is malformed".to_string(),
        ));
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> DialogBridgeResult<PathBuf> {
    let canonical = path.canonicalize().map_err(|error| {
        DialogBridgeError::InvalidTarget(format!("folder cannot be resolved: {error}"))
    })?;
    if !canonical.is_dir() {
        return Err(DialogBridgeError::InvalidTarget(
            "folder target is not a directory".to_string(),
        ));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path) -> DialogBridgeResult<PathBuf> {
    let canonical = path.canonicalize().map_err(|error| {
        DialogBridgeError::InvalidTarget(format!("file cannot be resolved: {error}"))
    })?;
    if !canonical.is_file() {
        return Err(DialogBridgeError::InvalidTarget(
            "file target is not a normal file".to_string(),
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use unsupported as imp;
#[cfg(target_os = "windows")]
use windows as imp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_debug_redacts_title_and_paths() {
        let context = DialogContext {
            dialog_id: "windows:1:2".to_string(),
            platform: "windows".to_string(),
            adapter_id: "standard".to_string(),
            kind: DialogKind::Save,
            process_id: 1,
            application_id: "fixture.exe".to_string(),
            title: "Secret Project".to_string(),
            bounds: DialogBounds {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            current_folder: Some("C:/Private".to_string()),
            filename_present: true,
            capabilities: vec![DialogCapability::NavigateFolder],
        };
        let debug = format!("{context:?}");
        assert!(!debug.contains("Secret Project"));
        assert!(!debug.contains("C:/Private"));
    }

    #[test]
    fn target_validation_is_bounded_and_same_parent() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.txt");
        let other = temp.path().join("other");
        std::fs::write(&first, "first").unwrap();
        std::fs::create_dir(&other).unwrap();
        let second = other.join("second.txt");
        std::fs::write(&second, "second").unwrap();

        assert!(canonical_directory(temp.path()).is_ok());
        assert!(canonical_file(&first).is_ok());
        assert!(validate_dialog_id("").is_err());

        let canonical = [
            canonical_file(&first).unwrap(),
            canonical_file(&second).unwrap(),
        ];
        assert_ne!(canonical[0].parent(), canonical[1].parent());
    }
}
