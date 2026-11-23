use crate::browser::{BrowserProvider, BrowserRefreshReport};
use crate::model::{ItemOverlay, SearchHit};
use crate::query::{FilterSuggestion, ParsedQuery};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use spiffy_shared::{LocalIpcRequest, SearchServiceCommand, StableFileIdentity};
use std::fmt;
use uuid::Uuid;

pub const SEARCH_PROTOCOL_VERSION: spiffy_shared::ProtocolVersion =
    spiffy_shared::SEARCH_PROTOCOL_VERSION;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AgentCommand {
    Status,
    Doctor,
    Search {
        query: String,
        generation: u64,
        limit: Option<u16>,
        current_folder: Option<String>,
    },
    // Explicit continuation command: older agents reject it instead of
    // silently dropping an unknown optional cursor and repeating page one.
    ShelfSearchPage {
        query: String,
        generation: u64,
        limit: u16,
        cursor: Option<String>,
    },
    ParseQuery {
        query: String,
    },
    FilterSuggestions {
        prefix: String,
    },
    ListRoots,
    AddRoot {
        path: String,
        remote_searchable: bool,
        exclusions: Vec<String>,
    },
    RemoveRoot {
        root_id: Uuid,
    },
    Reindex {
        root_id: Option<Uuid>,
    },
    SetFavorite {
        stable_key: String,
        display_name: String,
        path: String,
        favorite: bool,
    },
    SetPinned {
        stable_key: String,
        display_name: String,
        path: String,
        pinned: bool,
    },
    SetAliases {
        stable_key: String,
        aliases: Vec<String>,
    },
    RecordUsage {
        stable_key: String,
        selected: bool,
    },
    GetOverlay {
        stable_key: String,
    },
    ContentIndex {
        paths: Vec<String>,
    },
    ContentStatus,
    GetItemMetadata {
        stable_key: String,
    },
    GetPreviewText {
        stable_key: String,
        max_chars: Option<u32>,
    },
    ListFavorites {
        limit: Option<u16>,
    },
    RefreshBrowserHistory,
    BrowserHistoryStatus,
    ClearBrowserHistory,
    FileOperation {
        request: FileOperationRequest,
    },
    UndoFileOperation {
        operation_id: Uuid,
    },
    FileOperationStatus {
        operation_id: Uuid,
    },
    CancelFileOperation {
        operation_id: Uuid,
    },
    Shutdown,
}

impl AgentCommand {
    pub(crate) const fn minimum_protocol_minor(&self) -> u16 {
        match self {
            Self::ShelfSearchPage { .. } => 5,
            Self::ContentIndex { .. } | Self::ContentStatus => 1,
            Self::FileOperation { .. }
            | Self::UndoFileOperation { .. }
            | Self::FileOperationStatus { .. }
            | Self::CancelFileOperation { .. } => 2,
            Self::RefreshBrowserHistory
            | Self::BrowserHistoryStatus
            | Self::ClearBrowserHistory => 3,
            Self::GetItemMetadata { .. }
            | Self::GetPreviewText { .. }
            | Self::ListFavorites { .. } => 4,
            _ => 0,
        }
    }
}

impl fmt::Debug for AgentCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Status => "AgentCommand::Status",
            Self::Doctor => "AgentCommand::Doctor",
            Self::Search { .. } => "AgentCommand::Search([query and path redacted])",
            Self::ShelfSearchPage { .. } => "AgentCommand::ShelfSearchPage([redacted])",
            Self::ParseQuery { .. } => "AgentCommand::ParseQuery([query redacted])",
            Self::FilterSuggestions { .. } => "AgentCommand::FilterSuggestions",
            Self::ListRoots => "AgentCommand::ListRoots",
            Self::AddRoot { .. } => "AgentCommand::AddRoot([path redacted])",
            Self::RemoveRoot { .. } => "AgentCommand::RemoveRoot",
            Self::Reindex { .. } => "AgentCommand::Reindex",
            Self::SetFavorite { .. } => "AgentCommand::SetFavorite([path redacted])",
            Self::SetPinned { .. } => "AgentCommand::SetPinned([path redacted])",
            Self::SetAliases { .. } => "AgentCommand::SetAliases",
            Self::RecordUsage { .. } => "AgentCommand::RecordUsage",
            Self::GetOverlay { .. } => "AgentCommand::GetOverlay",
            Self::ContentIndex { .. } => "AgentCommand::ContentIndex([paths redacted])",
            Self::ContentStatus => "AgentCommand::ContentStatus",
            Self::GetItemMetadata { .. } => "AgentCommand::GetItemMetadata([key redacted])",
            Self::GetPreviewText { .. } => "AgentCommand::GetPreviewText([key redacted])",
            Self::ListFavorites { .. } => "AgentCommand::ListFavorites",
            Self::RefreshBrowserHistory => "AgentCommand::RefreshBrowserHistory",
            Self::BrowserHistoryStatus => "AgentCommand::BrowserHistoryStatus",
            Self::ClearBrowserHistory => "AgentCommand::ClearBrowserHistory",
            Self::FileOperation { .. } => "AgentCommand::FileOperation([paths redacted])",
            Self::UndoFileOperation { .. } => "AgentCommand::UndoFileOperation",
            Self::FileOperationStatus { .. } => "AgentCommand::FileOperationStatus",
            Self::CancelFileOperation { .. } => "AgentCommand::CancelFileOperation",
            Self::Shutdown => "AgentCommand::Shutdown",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationKind {
    Copy,
    Move,
    Rename,
    Trash,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileConflictPolicy {
    #[default]
    Fail,
    KeepBoth,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOperationRequest {
    pub operation_id: Uuid,
    pub kind: FileOperationKind,
    pub sources: Vec<String>,
    pub destination: Option<String>,
    #[serde(default)]
    pub conflict_policy: FileConflictPolicy,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    pub confirmed: bool,
}

impl fmt::Debug for FileOperationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileOperationRequest")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .field("source_count", &self.sources.len())
            .field(
                "destination",
                &self.destination.as_ref().map(|_| "[redacted]"),
            )
            .field("conflict_policy", &self.conflict_policy)
            .field(
                "confirmation_token",
                &self.confirmation_token.as_ref().map(|_| "[redacted]"),
            )
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationState {
    Running,
    Complete,
    Failed,
    Cancelled,
    Undoing,
    Undone,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoActionKind {
    #[default]
    MoveBack,
    RemoveCreated,
    RestoreTrash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoAction {
    #[serde(default)]
    pub kind: UndoActionKind,
    #[serde(default)]
    pub item_index: u64,
    pub source: String,
    pub destination: Option<String>,
    #[serde(default)]
    pub expected_identity: Option<StableFileIdentity>,
    #[serde(default)]
    pub expected_size: Option<u64>,
    #[serde(default)]
    pub trash_item_id: Option<String>,
    #[serde(default)]
    pub trash_deleted_at: Option<i64>,
    #[serde(default)]
    pub undone: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileOperationProgress {
    pub phase: String,
    pub completed_items: u64,
    pub total_items: u64,
    pub completed_bytes: u64,
    pub total_bytes: Option<u64>,
    pub current_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOperationReceipt {
    pub operation_id: Uuid,
    #[serde(default)]
    pub request_fingerprint: String,
    pub kind: FileOperationKind,
    pub sources: Vec<String>,
    pub destination: Option<String>,
    pub state: FileOperationState,
    pub undo_actions: Vec<UndoAction>,
    pub progress: FileOperationProgress,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationItemKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOperationPreviewItem {
    pub source: String,
    pub destination: Option<String>,
    pub item_kind: FileOperationItemKind,
    pub size: u64,
    pub conflict: bool,
    pub conflict_resolved: bool,
    pub undo_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOperationPreview {
    pub operation_id: Uuid,
    pub confirmation_token: String,
    pub kind: FileOperationKind,
    pub conflict_policy: FileConflictPolicy,
    pub items: Vec<FileOperationPreviewItem>,
    pub requires_confirmation: bool,
    pub undo_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOperationStatus {
    pub operation_id: Uuid,
    pub active: bool,
    pub receipt: FileOperationReceipt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResponse {
    pub generation: u64,
    pub index_generation: u64,
    pub elapsed_micros: u64,
    pub total_candidates: u64,
    pub category_counts: std::collections::BTreeMap<String, u64>,
    pub hits: Vec<SearchHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    #[serde(default = "legacy_search_protocol")]
    pub protocol: spiffy_shared::ProtocolVersion,
    pub started_at: DateTime<Utc>,
    pub index_generation: u64,
    pub indexed_documents: u64,
    pub roots: usize,
    pub watcher_roots: usize,
    pub indexing: bool,
    pub content_enabled: bool,
    #[serde(default)]
    pub content_indexing: bool,
    #[serde(default)]
    pub content_pending: usize,
    #[serde(default)]
    pub content_documents: u64,
    #[serde(default)]
    pub browser_enabled: bool,
    #[serde(default)]
    pub browser_refreshing: bool,
    #[serde(default)]
    pub browser_documents: u64,
    pub local_api_address: Option<String>,
}

const fn legacy_search_protocol() -> spiffy_shared::ProtocolVersion {
    spiffy_shared::ProtocolVersion::new(1, 0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserHistoryStatus {
    pub enabled_providers: Vec<BrowserProvider>,
    pub refreshing: bool,
    pub documents: u64,
    pub latest_report: Option<BrowserRefreshReport>,
    pub latest_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub healthy: bool,
    pub schema_version: u16,
    pub sqlite_quick_check: String,
    pub filename_index_healthy: bool,
    pub content_index_healthy: bool,
    pub endpoint_owner_only: bool,
    pub pending_reconciliation: bool,
    pub config_path: String,
    pub database_path: String,
    pub index_path: String,
    #[serde(default)]
    pub content_index_path: Option<String>,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentReply {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl AgentReply {
    pub fn success<T: Serialize>(message: impl Into<String>, value: T) -> Self {
        match serde_json::to_value(value) {
            Ok(data) => Self {
                ok: true,
                code: "ok".to_string(),
                message: message.into(),
                data: Some(data),
            },
            Err(_) => Self::failure("encoding_error", "Could not encode the local response"),
        }
    }

    pub fn empty_success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            code: "ok".to_string(),
            message: message.into(),
            data: None,
        }
    }

    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.into(),
            message: message.into(),
            data: None,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SearchIpcCommand {
    Agent(AgentCommand),
    Service(SearchServiceCommand),
}

impl fmt::Debug for SearchIpcCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(command) => command.fmt(formatter),
            Self::Service(command) => command.fmt(formatter),
        }
    }
}

pub type IpcRequest = LocalIpcRequest<SearchIpcCommand>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedQueryResponse {
    pub parsed: ParsedQuery,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayResponse {
    pub overlay: ItemOverlay,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterSuggestionsResponse {
    pub suggestions: Vec<FilterSuggestion>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_queries_paths_and_tokens() {
        let request = IpcRequest::new(
            SEARCH_PROTOCOL_VERSION,
            "secret-token".to_string(),
            SearchIpcCommand::Agent(AgentCommand::Search {
                query: "private project".to_string(),
                generation: 1,
                limit: None,
                current_folder: Some("C:/Private".to_string()),
            }),
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("private project"));
        assert!(!debug.contains("C:/Private"));

        let preview = format!(
            "{:?}",
            AgentCommand::GetPreviewText {
                stable_key: "private-stable-key".to_string(),
                max_chars: Some(100),
            }
        );
        assert!(!preview.contains("private-stable-key"));
    }

    #[test]
    fn content_commands_require_minor_one_and_old_statuses_remain_readable() {
        assert_eq!(AgentCommand::ContentStatus.minimum_protocol_minor(), 1);
        assert_eq!(
            AgentCommand::ContentIndex { paths: Vec::new() }.minimum_protocol_minor(),
            1
        );
        assert_eq!(AgentCommand::Status.minimum_protocol_minor(), 0);

        let old_status = serde_json::json!({
            "started_at": "2026-08-08T00:00:00Z",
            "roots": 1,
            "indexed_documents": 2,
            "index_generation": 3,
            "watcher_roots": 1,
            "indexing": false,
            "content_enabled": false,
            "local_api_address": null
        });
        let decoded: AgentStatus = serde_json::from_value(old_status).unwrap();
        assert_eq!(decoded.protocol, spiffy_shared::ProtocolVersion::new(1, 0));
        assert!(!decoded.content_indexing);
        assert_eq!(decoded.content_pending, 0);
        assert_eq!(decoded.content_documents, 0);
        assert!(!decoded.browser_enabled);
        assert!(!decoded.browser_refreshing);
        assert_eq!(decoded.browser_documents, 0);
    }

    #[test]
    fn file_commands_require_minor_two_and_legacy_requests_default_to_fail() {
        let operation_id = Uuid::new_v4();
        assert_eq!(
            AgentCommand::FileOperationStatus { operation_id }.minimum_protocol_minor(),
            2
        );
        assert_eq!(
            AgentCommand::CancelFileOperation { operation_id }.minimum_protocol_minor(),
            2
        );
        let legacy = serde_json::json!({
            "operation_id": operation_id,
            "kind": "copy",
            "sources": ["C:/Media/Clip.mov"],
            "destination": "C:/Archive",
            "confirmed": false
        });
        let decoded: FileOperationRequest = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.conflict_policy, FileConflictPolicy::Fail);
    }

    #[test]
    fn browser_commands_require_minor_three() {
        assert_eq!(
            AgentCommand::RefreshBrowserHistory.minimum_protocol_minor(),
            3
        );
        assert_eq!(
            AgentCommand::BrowserHistoryStatus.minimum_protocol_minor(),
            3
        );
        assert_eq!(
            AgentCommand::ClearBrowserHistory.minimum_protocol_minor(),
            3
        );
    }

    #[test]
    fn read_only_access_commands_require_minor_four() {
        assert_eq!(
            AgentCommand::GetItemMetadata {
                stable_key: "key".to_string(),
            }
            .minimum_protocol_minor(),
            4
        );
        assert_eq!(
            AgentCommand::GetPreviewText {
                stable_key: "key".to_string(),
                max_chars: None,
            }
            .minimum_protocol_minor(),
            4
        );
        assert_eq!(
            AgentCommand::ListFavorites { limit: None }.minimum_protocol_minor(),
            4
        );
    }
}
