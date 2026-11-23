use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use spiffy_shared::StableFileIdentity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    File,
    Folder,
    Application,
    Window,
    Content,
    Clipboard,
    Browser,
    Shelf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    Document,
    Image,
    Video,
    Audio,
    Archive,
    Code,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    pub stable_key: String,
    pub stable_file_id: Option<StableFileIdentity>,
    pub root_id: Uuid,
    pub device_id: Uuid,
    pub canonical_path: String,
    pub display_path: String,
    pub normalized_path: String,
    pub filename: String,
    pub filename_stem: String,
    pub extension: String,
    pub parent_path: String,
    pub parent_tokens: String,
    pub item_kind: ItemKind,
    pub category: FileCategory,
    pub content_type: String,
    pub mime_type: String,
    pub size: u64,
    pub created_time: Option<DateTime<Utc>>,
    pub modified_time: Option<DateTime<Utc>>,
    pub last_seen_time: DateTime<Utc>,
    pub hidden: bool,
    pub system: bool,
    pub package: bool,
    pub application: bool,
    pub folder: bool,
    pub file: bool,
    pub cloud_placeholder: bool,
    pub offline: bool,
    pub missing: bool,
    pub tombstone: bool,
    pub source_provider: String,
    pub remote_device: Option<String>,
    pub content_index_state: String,
    pub preview_state: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    pub record: FileRecord,
    pub score: f64,
    pub match_indices: Vec<u32>,
    pub diagnostics: RankingDiagnostics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_match: Option<ContentMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentMatch {
    pub snippet: String,
    pub highlights: Vec<ContentHighlight>,
    pub source_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentHighlight {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RankingDiagnostics {
    pub signals: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemOverlay {
    pub favorite: bool,
    pub pinned: bool,
    pub aliases: Vec<String>,
    pub usage_count: u64,
    pub last_opened: Option<DateTime<Utc>>,
    pub last_selected: Option<DateTime<Utc>>,
    pub custom_priority: i16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemMetadata {
    pub record: FileRecord,
    pub overlay: ItemOverlay,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FavoriteItem {
    pub stable_key: String,
    pub display_name: String,
    pub last_known_path: String,
    pub overlay: ItemOverlay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewText {
    pub stable_key: String,
    pub text: String,
    pub truncated: bool,
}

impl FileRecord {
    pub fn stable_key_for(path: &Path, identity: Option<&StableFileIdentity>) -> String {
        match identity {
            Some(identity) => format!("{}:{}", identity.volume_id, identity.file_id),
            None => {
                let normalized = normalize_path(path);
                format!("path:{}", blake3::hash(normalized.as_bytes()).to_hex())
            }
        }
    }
}

pub fn normalize_path(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    {
        let value = if let Some(rest) = value.strip_prefix("//?/UNC/") {
            format!("//{rest}")
        } else if let Some(rest) = value.strip_prefix("//?/") {
            rest.to_string()
        } else {
            value
        };
        value.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        value
    }
}

pub fn path_tokens(path: &Path) -> String {
    path.components()
        .filter_map(|component| component.as_os_str().to_str())
        .flat_map(|component| component.split([' ', '-', '_', '.']))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn extension_category(extension: &str) -> FileCategory {
    match extension.to_ascii_lowercase().as_str() {
        "txt" | "md" | "rtf" | "pdf" | "doc" | "docx" | "ppt" | "pptx" | "xls" | "xlsx" | "odt"
        | "ods" | "odp" | "epub" | "csv" | "srt" | "vtt" => FileCategory::Document,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "tif" | "tiff" | "bmp" | "svg" | "heic"
        | "avif" => FileCategory::Image,
        "mp4" | "mov" | "mkv" | "avi" | "webm" | "m4v" | "flv" | "wmv" | "prproj" | "aep" => {
            FileCategory::Video
        }
        "wav" | "mp3" | "flac" | "aac" | "m4a" | "ogg" | "opus" | "aiff" => FileCategory::Audio,
        "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" => FileCategory::Archive,
        "rs" | "py" | "js" | "ts" | "tsx" | "jsx" | "html" | "css" | "json" | "xml" | "toml"
        | "yaml" | "yml" | "c" | "cpp" | "h" | "hpp" | "cs" | "java" | "swift" | "kt" | "go"
        | "rb" | "php" | "sh" | "ps1" | "ahk" => FileCategory::Code,
        _ => FileCategory::Other,
    }
}

pub fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_and_keys_are_deterministic() {
        assert_eq!(extension_category("PRPROJ"), FileCategory::Video);
        assert_eq!(extension_category("rs"), FileCategory::Code);
        let path = Path::new("Some Folder").join("Clip.mov");
        assert_eq!(
            FileRecord::stable_key_for(&path, None),
            FileRecord::stable_key_for(&path, None)
        );
        assert!(path_tokens(&path).contains("Some"));
        #[cfg(windows)]
        {
            assert_eq!(
                normalize_path(Path::new(r"\\?\C:\Media\Clip.mov")),
                "c:/media/clip.mov"
            );
            assert_eq!(
                normalize_path(Path::new(r"\\?\UNC\server\share\Clip.mov")),
                "//server/share/clip.mov"
            );
        }
    }
}
