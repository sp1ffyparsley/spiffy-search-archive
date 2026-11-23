use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{
    canonical_or_original, extension_category, normalize_path, path_tokens, FileCategory,
    FileRecord, ItemKind,
};
use chrono::{DateTime, Utc};
use spiffy_shared::StableFileIdentity;
use std::fs::Metadata;
use std::path::Path;
use std::time::SystemTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PlatformFlags {
    hidden: bool,
    system: bool,
    package: bool,
    application: bool,
    cloud_placeholder: bool,
    offline: bool,
}

pub fn file_record(path: &Path, root_id: Uuid, device_id: Uuid) -> SearchResult<FileRecord> {
    file_record_at(path, root_id, device_id, Utc::now())
}

pub fn file_record_at(
    path: &Path,
    root_id: Uuid,
    device_id: Uuid,
    last_seen: DateTime<Utc>,
) -> SearchResult<FileRecord> {
    let metadata = path.metadata().map_err(|error| io_error(path, error))?;
    let canonical = canonical_or_original(path);
    let display_path = canonical.to_string_lossy().to_string();
    let filename = canonical
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| display_path.clone());
    if filename.contains('\0') || display_path.contains('\0') {
        return Err(SearchError::State(format!(
            "filesystem path contains an unsupported NUL character: {}",
            path.display()
        )));
    }
    let extension = canonical
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let filename_stem = canonical
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| filename.clone());
    let folder = metadata.is_dir();
    let file = metadata.is_file();
    let flags = platform_flags(&canonical, &metadata, folder, &extension);
    let item_kind = if flags.application {
        ItemKind::Application
    } else if folder {
        ItemKind::Folder
    } else {
        ItemKind::File
    };
    let category = if folder || flags.application {
        FileCategory::Other
    } else {
        extension_category(&extension)
    };
    let stable_file_id = StableFileIdentity::from_path(&canonical).ok();
    let stable_key = FileRecord::stable_key_for(&canonical, stable_file_id.as_ref());
    let parent = canonical.parent().unwrap_or(&canonical);

    Ok(FileRecord {
        stable_key,
        stable_file_id,
        root_id,
        device_id,
        canonical_path: display_path.clone(),
        display_path,
        normalized_path: normalize_path(&canonical),
        filename,
        filename_stem,
        extension,
        parent_path: parent.to_string_lossy().to_string(),
        parent_tokens: path_tokens(parent),
        item_kind,
        category,
        content_type: category_name(category).to_string(),
        mime_type: if folder {
            "inode/directory".to_string()
        } else {
            mime_guess::from_path(&canonical)
                .first_raw()
                .unwrap_or("application/octet-stream")
                .to_string()
        },
        size: if file { metadata.len() } else { 0 },
        created_time: metadata.created().ok().map(system_time_to_utc),
        modified_time: metadata.modified().ok().map(system_time_to_utc),
        last_seen_time: last_seen,
        hidden: flags.hidden,
        system: flags.system,
        package: flags.package,
        application: flags.application,
        folder,
        file,
        cloud_placeholder: flags.cloud_placeholder,
        offline: flags.offline,
        missing: false,
        tombstone: false,
        source_provider: "private_index".to_string(),
        remote_device: None,
        content_index_state: "disabled".to_string(),
        preview_state: "unknown".to_string(),
        tags: Vec::new(),
    })
}

pub fn set_background_priority() -> SearchResult<()> {
    set_background_priority_platform()
}

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unsupported"
    }
}

fn system_time_to_utc(value: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(value)
}

fn category_name(category: FileCategory) -> &'static str {
    match category {
        FileCategory::Document => "document",
        FileCategory::Image => "image",
        FileCategory::Video => "video",
        FileCategory::Audio => "audio",
        FileCategory::Archive => "archive",
        FileCategory::Code => "code",
        FileCategory::Other => "other",
    }
}

#[cfg(target_os = "windows")]
fn platform_flags(
    _path: &Path,
    metadata: &Metadata,
    _folder: bool,
    extension: &str,
) -> PlatformFlags {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_UNPINNED: u32 = 0x0010_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

    let attributes = metadata.file_attributes();
    PlatformFlags {
        hidden: attributes & FILE_ATTRIBUTE_HIDDEN != 0,
        system: attributes & FILE_ATTRIBUTE_SYSTEM != 0,
        package: matches!(extension, "appx" | "msix" | "appxbundle" | "msixbundle"),
        application: matches!(extension, "exe" | "com" | "lnk" | "appref-ms"),
        cloud_placeholder: attributes
            & (FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_UNPINNED
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
            != 0,
        offline: attributes & FILE_ATTRIBUTE_OFFLINE != 0,
    }
}

#[cfg(target_os = "macos")]
fn platform_flags(
    path: &Path,
    metadata: &Metadata,
    folder: bool,
    extension: &str,
) -> PlatformFlags {
    use std::os::macos::fs::MetadataExt;

    let dot_hidden = path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('.'));
    let package = folder && matches!(extension, "app" | "bundle" | "framework" | "plugin");
    PlatformFlags {
        hidden: dot_hidden || metadata.st_flags() & libc::UF_HIDDEN != 0,
        system: false,
        package,
        application: folder && extension == "app",
        cloud_placeholder: false,
        offline: false,
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn platform_flags(
    path: &Path,
    _metadata: &Metadata,
    _folder: bool,
    _extension: &str,
) -> PlatformFlags {
    PlatformFlags {
        hidden: path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.')),
        ..PlatformFlags::default()
    }
}

#[cfg(target_os = "windows")]
fn set_background_priority_platform() -> SearchResult<()> {
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS,
    };

    unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) }.map_err(|error| {
        SearchError::State(format!(
            "could not set Windows background priority: {error}"
        ))
    })
}

#[cfg(target_os = "macos")]
fn set_background_priority_platform() -> SearchResult<()> {
    let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_error(
            "current process priority",
            std::io::Error::last_os_error(),
        ))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn set_background_priority_platform() -> SearchResult<()> {
    Err(SearchError::State(
        "Spiffy Search supports resident indexing only on Windows and macOS".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn local_files_and_folders_produce_stable_search_records() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("Project Sources");
        fs::create_dir(&folder).unwrap();
        let file = folder.join("Hero Clip.MOV");
        fs::write(&file, b"media").unwrap();
        let root_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let first = file_record(&file, root_id, device_id).unwrap();
        let second = file_record(&file, root_id, device_id).unwrap();
        assert_eq!(first.stable_key, second.stable_key);
        assert_eq!(first.extension, "mov");
        assert_eq!(first.category, FileCategory::Video);
        assert_eq!(first.size, 5);
        assert!(first.parent_tokens.contains("Project"));
        let folder_record = file_record(&folder, root_id, device_id).unwrap();
        assert_eq!(folder_record.item_kind, ItemKind::Folder);
        assert_eq!(folder_record.mime_type, "inode/directory");
    }
}
