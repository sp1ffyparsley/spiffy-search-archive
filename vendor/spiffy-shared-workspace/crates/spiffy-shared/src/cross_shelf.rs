use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DeviceIdentity, ProtocolVersion};

pub const CROSS_SHELF_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 5);
pub const CROSS_SEARCH_PROTOCOL_MINOR: u16 = 1;
pub const FOLLOW_ME_SHELF_PROTOCOL_MINOR: u16 = 4;
pub const REMOTE_CLIPBOARD_SNAPSHOT_PROTOCOL_MINOR: u16 = 5;
pub const FOLLOW_ME_TRANSFER_KIND_METADATA: &str = "spiffy.follow_me.kind";
pub const FOLLOW_ME_FOLDER_TAR_V1: &str = "folder_tar_v1";
pub const DEFAULT_TRANSFER_CHUNK_BYTES: u32 = 512 * 1024;
pub const MAX_FOLLOW_ME_ITEMS: usize = 500;
pub const MAX_FOLLOW_ME_CONTENT_BYTES: usize = 32 * 1024;
pub const MAX_FOLLOW_ME_FOLDER_ENTRIES: usize = 100_000;
pub const MAX_FOLLOW_ME_FOLDER_DEPTH: usize = 128;
pub const MAX_FOLLOW_ME_FOLDER_PATH_BYTES: usize = 4_096;

const FOLLOW_ME_PAYLOAD_SCHEMA: &str = "1";

pub fn normalize_follow_me_folder_path(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err("Follow Me folder path must be relative".to_string());
        };
        let component = component.to_str().ok_or_else(|| {
            "Follow Me folder path is not representable as cross-platform UTF-8".to_string()
        })?;
        if component.is_empty()
            || component.len() > 255
            || component.trim() != component
            || component.ends_with(['.', ' '])
            || component
                .chars()
                .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
        {
            return Err("Follow Me folder path contains a non-portable component".to_string());
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err("Follow Me folder path uses a Windows-reserved name".to_string());
        }
        components.push(component);
    }
    if components.is_empty() || components.len() > MAX_FOLLOW_ME_FOLDER_DEPTH {
        return Err("Follow Me folder path is empty or too deeply nested".to_string());
    }
    let encoded = components.join("/");
    if encoded.len() > MAX_FOLLOW_ME_FOLDER_PATH_BYTES {
        return Err(format!(
            "Follow Me folder path exceeds {MAX_FOLLOW_ME_FOLDER_PATH_BYTES} bytes"
        ));
    }
    Ok(encoded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    PendingConfirmation,
    Trusted,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMode {
    PairedDisconnected,
    ConnectedManual,
    LiveClipboardTimed,
    FollowMeShelf,
    Paused,
    Revoked,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    Windows,
    Macos,
    Linux,
    #[default]
    #[serde(other)]
    Unknown,
}

impl DevicePlatform {
    #[cfg(target_os = "windows")]
    pub const fn current() -> Self {
        Self::Windows
    }

    #[cfg(target_os = "macos")]
    pub const fn current() -> Self {
        Self::Macos
    }

    #[cfg(target_os = "linux")]
    pub const fn current() -> Self {
        Self::Linux
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    pub const fn current() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardMode {
    ManualSend,
    TimedMirror,
    ShelfOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardKind {
    PlainText,
    RichText,
    Html,
    Url,
    ImagePng,
    FileList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardItemContract {
    pub id: Uuid,
    pub origin_device_id: Uuid,
    pub kind: ClipboardKind,
    pub encoded_content: String,
    pub content_type: Option<String>,
    pub content_hash: String,
    pub sequence: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub byte_len: u64,
    pub private_once: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClipboardSnapshotItem {
    pub kind: ClipboardKind,
    pub encoded_content: Option<String>,
    pub content_type: Option<String>,
    pub content_hash: Option<String>,
    pub byte_len: u64,
    pub file_count: Option<u32>,
}

impl fmt::Debug for RemoteClipboardSnapshotItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteClipboardSnapshotItem")
            .field("kind", &self.kind)
            .field(
                "encoded_content",
                &self.encoded_content.as_ref().map(|_| "[redacted]"),
            )
            .field("content_type", &self.content_type)
            .field(
                "content_hash",
                &self.content_hash.as_ref().map(|_| "[redacted]"),
            )
            .field("byte_len", &self.byte_len)
            .field("file_count", &self.file_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClipboardSnapshot {
    pub device: DeviceIdentity,
    #[serde(default)]
    pub platform: DevicePlatform,
    pub captured_at: DateTime<Utc>,
    pub item: Option<RemoteClipboardSnapshotItem>,
}

impl fmt::Debug for RemoteClipboardSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteClipboardSnapshot")
            .field("device", &self.device)
            .field("platform", &self.platform)
            .field("captured_at", &self.captured_at)
            .field("item", &self.item)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferThumbnailContract {
    pub content_type: String,
    pub encoded_content: String,
    pub content_hash: String,
    pub byte_len: u64,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOfferContract {
    pub transfer_id: Uuid,
    pub source_item_id: Uuid,
    pub origin_device_id: Uuid,
    pub filename: String,
    pub byte_len: u64,
    pub blake3: String,
    pub chunk_bytes: u32,
    pub modified_at: Option<DateTime<Utc>>,
    pub content_type: Option<String>,
    pub metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<TransferThumbnailContract>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDecision {
    Pending,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferResumeContract {
    pub transfer_id: Uuid,
    pub decision: TransferDecision,
    pub next_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferChunkContract {
    pub transfer_id: Uuid,
    pub offset: u64,
    pub encoded_bytes: String,
    pub chunk_blake3: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShelfEventOperation {
    Add,
    Remove,
    Rename,
    Reorder,
    ChangeColor,
    SetExpiration,
    PinLocal,
    ClearEverywhere,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedShelfEventContract {
    pub event_id: Uuid,
    pub shelf_id: Uuid,
    pub entity_id: Uuid,
    pub origin: DeviceIdentity,
    pub sequence: u64,
    pub created_at: DateTime<Utc>,
    pub operation: ShelfEventOperation,
    pub payload: BTreeMap<String, String>,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShelfEntityKind {
    Shelf,
    Item,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mutation", rename_all = "snake_case")]
pub enum ShelfMutationContract {
    AddShelf {
        name: String,
        color: String,
    },
    AddItem {
        kind: crate::ShelfItemKind,
        display_name: String,
        content: Option<String>,
        source_url: Option<String>,
        mime_type: Option<String>,
        size: Option<u64>,
        content_hash: Option<String>,
        position: u32,
    },
    Remove {
        entity_kind: ShelfEntityKind,
    },
    Rename {
        entity_kind: ShelfEntityKind,
        name: String,
    },
    Reorder {
        ordered_item_ids: Vec<Uuid>,
    },
    ChangeColor {
        color: String,
    },
    SetExpiration {
        entity_kind: ShelfEntityKind,
        expires_at: Option<DateTime<Utc>>,
    },
    ClearShelf,
    ClearClipboardHistory,
}

impl ShelfMutationContract {
    pub const fn operation(&self) -> ShelfEventOperation {
        match self {
            Self::AddShelf { .. } | Self::AddItem { .. } => ShelfEventOperation::Add,
            Self::Remove { .. } => ShelfEventOperation::Remove,
            Self::Rename { .. } => ShelfEventOperation::Rename,
            Self::Reorder { .. } => ShelfEventOperation::Reorder,
            Self::ChangeColor { .. } => ShelfEventOperation::ChangeColor,
            Self::SetExpiration { .. } => ShelfEventOperation::SetExpiration,
            Self::ClearShelf | Self::ClearClipboardHistory => ShelfEventOperation::ClearEverywhere,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::AddShelf { name, color } => {
                validate_follow_me_name(name)?;
                validate_follow_me_color(color)
            }
            Self::AddItem {
                kind,
                display_name,
                content,
                source_url,
                mime_type,
                content_hash,
                ..
            } => {
                if *kind == crate::ShelfItemKind::FileList {
                    return Err("Follow Me sends each file-list item separately".to_string());
                }
                validate_follow_me_name(display_name)?;
                if content
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_FOLLOW_ME_CONTENT_BYTES)
                {
                    return Err(format!(
                        "Follow Me inline content exceeds {MAX_FOLLOW_ME_CONTENT_BYTES} bytes"
                    ));
                }
                validate_optional_text(source_url.as_deref(), 4_096, "source URL")?;
                validate_optional_text(mime_type.as_deref(), 255, "MIME type")?;
                if let Some(hash) = content_hash {
                    if hash.len() != 64
                        || !hash.chars().all(|character| character.is_ascii_hexdigit())
                    {
                        return Err(
                            "Follow Me content hash must be 64 hexadecimal characters".to_string()
                        );
                    }
                }
                Ok(())
            }
            Self::Remove { .. }
            | Self::SetExpiration { .. }
            | Self::ClearShelf
            | Self::ClearClipboardHistory => Ok(()),
            Self::Rename { name, .. } => validate_follow_me_name(name),
            Self::Reorder { ordered_item_ids } => {
                if ordered_item_ids.len() > MAX_FOLLOW_ME_ITEMS {
                    return Err(format!(
                        "Follow Me reorder exceeds {MAX_FOLLOW_ME_ITEMS} items"
                    ));
                }
                let unique = ordered_item_ids.iter().copied().collect::<BTreeSet<_>>();
                if unique.len() != ordered_item_ids.len()
                    || ordered_item_ids.iter().any(Uuid::is_nil)
                {
                    return Err("Follow Me reorder IDs must be non-nil and unique".to_string());
                }
                Ok(())
            }
            Self::ChangeColor { color } => validate_follow_me_color(color),
        }
    }

    pub fn to_payload(&self) -> Result<BTreeMap<String, String>, String> {
        self.validate()?;
        Ok(BTreeMap::from([
            ("schema".to_string(), FOLLOW_ME_PAYLOAD_SCHEMA.to_string()),
            (
                "mutation".to_string(),
                serde_json::to_string(self)
                    .map_err(|error| format!("could not encode Follow Me mutation: {error}"))?,
            ),
        ]))
    }

    pub fn from_payload(
        operation: ShelfEventOperation,
        shelf_id: Uuid,
        entity_id: Uuid,
        payload: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let mutation =
            if payload.get("schema").map(String::as_str) == Some(FOLLOW_ME_PAYLOAD_SCHEMA) {
                let encoded = payload
                    .get("mutation")
                    .ok_or_else(|| "Follow Me payload is missing its mutation".to_string())?;
                serde_json::from_str(encoded)
                    .map_err(|error| format!("Follow Me mutation is invalid JSON: {error}"))?
            } else {
                decode_legacy_follow_me_payload(operation, shelf_id, entity_id, payload)?
            };
        if mutation.operation() != operation {
            return Err("Follow Me operation does not match its typed mutation".to_string());
        }
        mutation.validate()?;
        Ok(mutation)
    }
}

impl SignedShelfEventContract {
    pub fn from_mutation(
        shelf_id: Uuid,
        entity_id: Uuid,
        origin: DeviceIdentity,
        mutation: ShelfMutationContract,
    ) -> Result<Self, String> {
        let operation = mutation.operation();
        let payload = mutation.to_payload()?;
        let event = Self {
            event_id: Uuid::new_v4(),
            shelf_id,
            entity_id,
            origin,
            sequence: 0,
            created_at: Utc::now(),
            operation,
            payload,
            signature_base64: String::new(),
        };
        event.validate_template()?;
        Ok(event)
    }

    pub fn mutation(&self) -> Result<ShelfMutationContract, String> {
        ShelfMutationContract::from_payload(
            self.operation,
            self.shelf_id,
            self.entity_id,
            &self.payload,
        )
    }

    pub fn validate_template(&self) -> Result<(), String> {
        if self.event_id.is_nil() || self.origin.id.is_nil() {
            return Err("Follow Me event IDs must not be nil".to_string());
        }
        let mutation = self.mutation()?;
        validate_follow_me_entity_ids(self.shelf_id, self.entity_id, &mutation)
    }

    pub fn validate_signed(&self) -> Result<(), String> {
        self.validate_template()?;
        if self.sequence == 0 || self.signature_base64.is_empty() {
            return Err("signed Follow Me events require a sequence and signature".to_string());
        }
        Ok(())
    }
}

fn validate_follow_me_entity_ids(
    shelf_id: Uuid,
    entity_id: Uuid,
    mutation: &ShelfMutationContract,
) -> Result<(), String> {
    if matches!(mutation, ShelfMutationContract::ClearClipboardHistory) {
        return if shelf_id.is_nil() && entity_id.is_nil() {
            Ok(())
        } else {
            Err("clipboard-history clear requires nil shelf and entity IDs".to_string())
        };
    }
    if shelf_id.is_nil() || entity_id.is_nil() {
        return Err("Follow Me shelf and item IDs must not be nil".to_string());
    }
    let targets_shelf = matches!(
        mutation,
        ShelfMutationContract::AddShelf { .. }
            | ShelfMutationContract::Remove {
                entity_kind: ShelfEntityKind::Shelf
            }
            | ShelfMutationContract::Rename {
                entity_kind: ShelfEntityKind::Shelf,
                ..
            }
            | ShelfMutationContract::ChangeColor { .. }
            | ShelfMutationContract::SetExpiration {
                entity_kind: ShelfEntityKind::Shelf,
                ..
            }
            | ShelfMutationContract::Reorder { .. }
            | ShelfMutationContract::ClearShelf
    );
    if targets_shelf && shelf_id != entity_id {
        return Err("shelf mutations require matching shelf and entity IDs".to_string());
    }
    if !targets_shelf && shelf_id == entity_id {
        return Err("item mutations require distinct shelf and entity IDs".to_string());
    }
    Ok(())
}

fn decode_legacy_follow_me_payload(
    operation: ShelfEventOperation,
    shelf_id: Uuid,
    entity_id: Uuid,
    payload: &BTreeMap<String, String>,
) -> Result<ShelfMutationContract, String> {
    let entity_kind = if shelf_id == entity_id {
        ShelfEntityKind::Shelf
    } else {
        ShelfEntityKind::Item
    };
    match operation {
        ShelfEventOperation::Rename => Ok(ShelfMutationContract::Rename {
            entity_kind,
            name: payload
                .get("name")
                .cloned()
                .ok_or_else(|| "legacy Follow Me rename is missing name".to_string())?,
        }),
        ShelfEventOperation::ClearEverywhere => match payload.get("scope").map(String::as_str) {
            Some("shelf") => Ok(ShelfMutationContract::ClearShelf),
            Some("clipboard") => Ok(ShelfMutationContract::ClearClipboardHistory),
            _ => Err("legacy clear-everywhere payload has an unsupported scope".to_string()),
        },
        ShelfEventOperation::PinLocal => {
            Err("pin state is local-only and must not be sent through Follow Me".to_string())
        }
        _ => Err("legacy Follow Me payload is not supported for this operation".to_string()),
    }
}

fn validate_follow_me_name(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control) {
        return Err("Follow Me names must contain 1 to 80 printable characters".to_string());
    }
    Ok(())
}

fn validate_follow_me_color(value: &str) -> Result<(), String> {
    if value.len() != 7
        || !value.starts_with('#')
        || !value[1..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("Follow Me colors must use #RRGGBB notation".to_string());
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    max_chars: usize,
    label: &str,
) -> Result<(), String> {
    if value.is_some_and(|value| {
        value.chars().count() > max_chars || value.chars().any(char::is_control)
    }) {
        return Err(format!(
            "Follow Me {label} exceeds {max_chars} printable characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_contract_round_trips_without_changing_identity_fields() {
        let item = ClipboardItemContract {
            id: Uuid::new_v4(),
            origin_device_id: Uuid::new_v4(),
            kind: ClipboardKind::PlainText,
            encoded_content: "aGVsbG8".to_string(),
            content_type: Some("text/plain;charset=utf-8".to_string()),
            content_hash: "abc123".to_string(),
            sequence: 9,
            created_at: Utc::now(),
            expires_at: None,
            byte_len: 5,
            private_once: false,
        };
        let json = serde_json::to_vec(&item).expect("serialize clipboard contract");
        let decoded: ClipboardItemContract =
            serde_json::from_slice(&json).expect("deserialize clipboard contract");
        assert_eq!(decoded, item);
    }

    #[test]
    fn device_platform_json_is_stable_and_unknown_values_are_compatible() {
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Windows).unwrap(),
            "\"windows\""
        );
        assert_eq!(
            serde_json::to_string(&DevicePlatform::Macos).unwrap(),
            "\"macos\""
        );
        assert_eq!(
            serde_json::from_str::<DevicePlatform>("\"linux\"").unwrap(),
            DevicePlatform::Linux
        );
        assert_eq!(
            serde_json::from_str::<DevicePlatform>("\"future_os\"").unwrap(),
            DevicePlatform::Unknown
        );
    }

    #[test]
    fn remote_clipboard_snapshot_debug_never_exposes_body_or_hash() {
        let encoded = "cHJpdmF0ZSBjbGlwYm9hcmQgYm9keQ".to_string();
        let hash = "a".repeat(64);
        let snapshot = RemoteClipboardSnapshot {
            device: DeviceIdentity::new("Editing Mac"),
            platform: DevicePlatform::Macos,
            captured_at: Utc::now(),
            item: Some(RemoteClipboardSnapshotItem {
                kind: ClipboardKind::PlainText,
                encoded_content: Some(encoded.clone()),
                content_type: Some("text/plain;charset=utf-8".to_string()),
                content_hash: Some(hash.clone()),
                byte_len: 22,
                file_count: None,
            }),
        };
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains(&encoded));
        assert!(!debug.contains(&hash));
        let round_trip: RemoteClipboardSnapshot =
            serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
        assert_eq!(round_trip, snapshot);
    }

    #[test]
    fn default_chunk_size_fits_inside_the_shared_json_frame_limit() {
        let base64_upper_bound = usize::try_from(DEFAULT_TRANSFER_CHUNK_BYTES)
            .expect("chunk size")
            .div_ceil(3)
            * 4;
        assert!(base64_upper_bound < crate::DEFAULT_MAX_FRAME_BYTES);
    }

    #[test]
    fn follow_me_folder_paths_are_portable_and_traversal_free() {
        assert_eq!(
            normalize_follow_me_folder_path(Path::new("Selects/Angle A/hero.mov")).unwrap(),
            "Selects/Angle A/hero.mov"
        );
        for invalid in [
            Path::new("../escape.mov"),
            Path::new("CON/file.mov"),
            Path::new("folder/trailing. "),
            Path::new("folder/name?.mov"),
        ] {
            assert!(normalize_follow_me_folder_path(invalid).is_err());
        }
    }

    #[test]
    fn typed_follow_me_mutation_round_trips_and_rejects_local_pin_wire_state() {
        let shelf_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let mutation = ShelfMutationContract::AddItem {
            kind: crate::ShelfItemKind::Video,
            display_name: "Hero.mov".to_string(),
            content: None,
            source_url: None,
            mime_type: Some("video/quicktime".to_string()),
            size: Some(1_024),
            content_hash: Some("a".repeat(64)),
            position: 2,
        };
        let event = SignedShelfEventContract::from_mutation(
            shelf_id,
            item_id,
            DeviceIdentity::new("Editing PC"),
            mutation.clone(),
        )
        .expect("typed event");
        assert_eq!(event.mutation().expect("decode mutation"), mutation);
        assert_eq!(event.operation, ShelfEventOperation::Add);
        assert_eq!(event.sequence, 0);
        assert!(event.validate_signed().is_err());

        let local_pin = SignedShelfEventContract {
            event_id: Uuid::new_v4(),
            shelf_id,
            entity_id: item_id,
            origin: DeviceIdentity::new("Editing PC"),
            sequence: 1,
            created_at: Utc::now(),
            operation: ShelfEventOperation::PinLocal,
            payload: BTreeMap::new(),
            signature_base64: "signed".to_string(),
        };
        assert!(local_pin.validate_signed().is_err());
    }

    #[test]
    fn follow_me_reorder_requires_unique_bounded_item_ids() {
        let duplicate = Uuid::new_v4();
        let mutation = ShelfMutationContract::Reorder {
            ordered_item_ids: vec![duplicate, duplicate],
        };
        assert!(mutation.validate().is_err());
    }
}
