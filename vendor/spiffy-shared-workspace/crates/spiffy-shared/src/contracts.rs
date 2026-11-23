use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cross_shelf::TransferThumbnailContract;
use crate::identity::{DeviceIdentity, StableFileIdentity};

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
pub const SEARCH_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 5);
pub const SEARCH_SERVICE_PROTOCOL_MINOR: u16 = 5;
pub const MAX_REMOTE_SEARCH_QUERY_CHARS: usize = 1_024;
pub const MAX_REMOTE_SEARCH_ROOTS: usize = 64;
pub const MAX_REMOTE_SEARCH_RESULTS: u16 = 100;
pub const REMOTE_SEARCH_LEASE_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppKind {
    ShelfUi,
    ShelfAgent,
    ClipboardProvider,
    MediaActionWorker,
    ActionProviderRouter,
    CaptureAgent,
    CrossShelfAgent,
    SearchUi,
    SearchAgent,
    FileDialogBridge,
    CommandLine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub protocol: ProtocolVersion,
    pub message_id: Uuid,
    pub sender: AppKind,
    pub sent_at: DateTime<Utc>,
    pub payload: T,
}

impl<T> Envelope<T> {
    pub fn new(sender: AppKind, payload: T) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender,
            sent_at: Utc::now(),
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub app: AppKind,
    pub version: String,
    pub commit: String,
    pub healthy: bool,
    pub started_at: DateTime<Utc>,
    pub checked_at: DateTime<Utc>,
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShelfItemKind {
    File,
    Folder,
    Image,
    Video,
    Audio,
    Text,
    Url,
    Html,
    FileList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShelfItemContract {
    pub id: Uuid,
    pub shelf_id: Uuid,
    pub kind: ShelfItemKind,
    pub display_name: String,
    pub local_path: Option<String>,
    pub text_preview: Option<String>,
    pub source_device: DeviceIdentity,
    pub file_identity: Option<StableFileIdentity>,
    pub content_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub pinned: bool,
    pub missing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSearchQuery {
    pub query_id: Uuid,
    pub text: String,
    pub permitted_root_ids: Vec<Uuid>,
    pub result_limit: u16,
    pub include_thumbnails: bool,
}

impl RemoteSearchQuery {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.query_id.is_nil() {
            return Err("remote search query ID must not be nil");
        }
        let query_chars = self.text.chars().count();
        if self.text.trim().is_empty() || query_chars > MAX_REMOTE_SEARCH_QUERY_CHARS {
            return Err("remote search text must contain 1 to 1024 characters");
        }
        if self.permitted_root_ids.len() > MAX_REMOTE_SEARCH_ROOTS {
            return Err("remote search permits at most 64 roots");
        }
        if self.permitted_root_ids.iter().any(Uuid::is_nil) {
            return Err("remote search root IDs must not be nil");
        }
        let unique_roots = self
            .permitted_root_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if unique_roots.len() != self.permitted_root_ids.len() {
            return Err("remote search root IDs must be unique");
        }
        if !(1..=MAX_REMOTE_SEARCH_RESULTS).contains(&self.result_limit) {
            return Err("remote search result limit must be between 1 and 100");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAvailability {
    Available,
    MetadataOnly,
    Missing,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResultContract {
    pub result_id: Uuid,
    pub device: DeviceIdentity,
    pub remote_root_id: Uuid,
    pub stable_file_id: Option<StableFileIdentity>,
    pub display_name: String,
    pub privacy_safe_path: String,
    pub kind: ShelfItemKind,
    pub size: Option<u64>,
    pub modified_at: Option<DateTime<Utc>>,
    pub availability: RemoteAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<TransferThumbnailContract>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSearchResponse {
    pub query_id: Uuid,
    pub results: Vec<SearchResultContract>,
    pub truncated: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteResultResolution {
    pub result_id: Uuid,
    pub remote_root_id: Uuid,
    pub stable_key: String,
    pub canonical_path: String,
    pub stable_file_id: Option<StableFileIdentity>,
    pub byte_len: u64,
    pub modified_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for RemoteResultResolution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteResultResolution")
            .field("result_id", &self.result_id)
            .field("remote_root_id", &self.remote_root_id)
            .field("stable_key", &"[redacted]")
            .field("canonical_path", &"[redacted]")
            .field("stable_file_id", &self.stable_file_id)
            .field("byte_len", &self.byte_len)
            .field("modified_at", &self.modified_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum SearchServiceCommand {
    RemoteSearch {
        requester_device_id: Uuid,
        serving_device: DeviceIdentity,
        query: RemoteSearchQuery,
    },
    ResolveRemoteResult {
        requester_device_id: Uuid,
        result_id: Uuid,
    },
}

impl SearchServiceCommand {
    pub const fn minimum_protocol_minor(&self) -> u16 {
        SEARCH_SERVICE_PROTOCOL_MINOR
    }
}

impl std::fmt::Debug for SearchServiceCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RemoteSearch { .. } => "SearchServiceCommand::RemoteSearch([query redacted])",
            Self::ResolveRemoteResult { .. } => "SearchServiceCommand::ResolveRemoteResult",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Queued,
    Negotiating,
    Transferring,
    Verifying,
    Complete,
    Cancelled,
    Failed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferReceipt {
    pub transfer_id: Uuid,
    pub source_device: DeviceIdentity,
    pub destination_device: DeviceIdentity,
    pub source_item_id: Uuid,
    pub destination_relative_path: Option<String>,
    pub expected_size: u64,
    pub transferred_size: u64,
    pub blake3: Option<String>,
    pub state: TransferState,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_a_different_major() {
        assert!(PROTOCOL_VERSION.is_compatible_with(ProtocolVersion::new(1, 9)));
        assert!(!PROTOCOL_VERSION.is_compatible_with(ProtocolVersion::new(2, 0)));
    }

    #[test]
    fn remote_search_query_rejects_unbounded_or_duplicated_inputs() {
        let root = Uuid::new_v4();
        let mut query = RemoteSearchQuery {
            query_id: Uuid::new_v4(),
            text: "edit proxy".to_string(),
            permitted_root_ids: vec![root],
            result_limit: 25,
            include_thumbnails: false,
        };
        assert!(query.validate().is_ok());
        query.permitted_root_ids.push(root);
        assert_eq!(
            query.validate(),
            Err("remote search root IDs must be unique")
        );
        query.permitted_root_ids.clear();
        query.result_limit = MAX_REMOTE_SEARCH_RESULTS + 1;
        assert_eq!(
            query.validate(),
            Err("remote search result limit must be between 1 and 100")
        );
        query.result_limit = 1;
        query.query_id = Uuid::nil();
        assert_eq!(
            query.validate(),
            Err("remote search query ID must not be nil")
        );
        query.query_id = Uuid::new_v4();
        query.permitted_root_ids.push(Uuid::nil());
        assert_eq!(
            query.validate(),
            Err("remote search root IDs must not be nil")
        );
    }

    #[test]
    fn remote_resolution_debug_redacts_local_lookup_material() {
        let resolution = RemoteResultResolution {
            result_id: Uuid::new_v4(),
            remote_root_id: Uuid::new_v4(),
            stable_key: "private-stable-key".to_string(),
            canonical_path: "C:/private/edit.mov".to_string(),
            stable_file_id: None,
            byte_len: 42,
            modified_at: None,
        };
        let debug = format!("{resolution:?}");
        assert!(!debug.contains("private-stable-key"));
        assert!(!debug.contains("C:/private"));
    }

    #[test]
    fn envelope_round_trips() {
        let envelope = Envelope::new(AppKind::CommandLine, "ping".to_string());
        let encoded = serde_json::to_vec(&envelope).expect("serialize envelope");
        let decoded: Envelope<String> =
            serde_json::from_slice(&encoded).expect("deserialize envelope");
        assert_eq!(decoded.payload, "ping");
        assert_eq!(decoded.protocol, PROTOCOL_VERSION);
    }
}
