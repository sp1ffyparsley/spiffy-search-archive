use super::*;
use std::path::{Path, PathBuf};

pub(super) fn inspect_active() -> DialogBridgeResult<DialogInspection> {
    Ok(DialogInspection::unsupported(
        "unsupported_platform",
        "The file-dialog bridge supports Windows and macOS only",
    ))
}

pub(super) fn navigate_folder(
    _expected_dialog_id: &str,
    _target: &Path,
) -> DialogBridgeResult<DialogActionReceipt> {
    Err(DialogBridgeError::UnsupportedPlatform)
}

pub(super) fn prepare_files(
    _expected_dialog_id: &str,
    _files: &[PathBuf],
) -> DialogBridgeResult<DialogActionReceipt> {
    Err(DialogBridgeError::UnsupportedPlatform)
}

pub(super) fn list_open_folders() -> DialogBridgeResult<Vec<OpenFolder>> {
    Err(DialogBridgeError::UnsupportedPlatform)
}

pub(super) fn doctor(_request_permission: bool) -> DialogBridgeResult<DialogBridgeDoctor> {
    Ok(DialogBridgeDoctor {
        platform: "unsupported".to_string(),
        adapter_available: false,
        accessibility_required: false,
        accessibility_granted: false,
        active_dialog_supported: false,
        active_dialog_code: "unsupported_platform".to_string(),
        open_folder_count: 0,
    })
}

pub(super) fn built_in_profiles() -> Vec<DialogAdapterProfile> {
    Vec::new()
}
