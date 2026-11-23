use std::fmt;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    ClipboardKind, ProtocolVersion, RemoteSearchQuery, SignedShelfEventContract,
    TransferThumbnailContract,
};

pub const CROSS_SHELF_IPC_ENDPOINT_SCHEMA_VERSION: u16 = 1;
pub const CROSS_SHELF_MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FOLLOW_ME_WAIT_MILLIS: u32 = 60_000;
pub const MAX_PENDING_SHELF_EVENTS: u16 = 100;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CrossShelfControlCommand {
    Status,
    Doctor,
    BeginPairing,
    Pair {
        address: SocketAddr,
        one_time_code: String,
    },
    ConfirmPairing {
        peer_id: Uuid,
        verification_code: String,
    },
    RevokePeer {
        peer_id: Uuid,
    },
    SetPeerPaused {
        peer_id: Uuid,
        paused: bool,
    },
    SendClipboard {
        peer_id: Uuid,
        kind: ClipboardKind,
        encoded_content: String,
        source_application: Option<String>,
        explicit_private: bool,
        send_private_once: bool,
    },
    RemoteClipboardSnapshot {
        peer_id: Uuid,
    },
    StartLiveClipboard {
        peer_id: Uuid,
        duration_seconds: Option<u32>,
    },
    StopLiveClipboard,
    PauseClipboard {
        duration_seconds: u32,
    },
    ClearLocalClipboard,
    SendFile {
        peer_id: Uuid,
        path: String,
        #[serde(default)]
        thumbnail: Option<TransferThumbnailContract>,
    },
    AcceptTransfer {
        transfer_id: Uuid,
    },
    RejectTransfer {
        transfer_id: Uuid,
        reason: String,
    },
    CancelTransfer {
        transfer_id: Uuid,
    },
    ListTransfers,
    ListClipboardHistory,
    ClearClipboardHistory {
        everywhere: bool,
    },
    SendShelfEvent {
        peer_id: Uuid,
        event: SignedShelfEventContract,
        #[serde(default)]
        source_path: Option<String>,
    },
    SetFollowMeShelf {
        peer_id: Uuid,
        enabled: bool,
    },
    RemoteSearch {
        peer_id: Uuid,
        query: RemoteSearchQuery,
    },
    FetchRemoteResult {
        peer_id: Uuid,
        result_id: Uuid,
    },
    FetchShelfItem {
        peer_id: Uuid,
        shelf_id: Uuid,
        item_id: Uuid,
    },
    GetTransfer {
        transfer_id: Uuid,
    },
    ListPendingShelfEvents,
    WaitPendingShelfEvents {
        timeout_millis: u32,
        limit: u16,
    },
    MarkShelfEventApplied {
        event_id: Uuid,
    },
    Shutdown,
}

impl fmt::Debug for CrossShelfControlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Status => "CrossShelfControlCommand::Status",
            Self::Doctor => "CrossShelfControlCommand::Doctor",
            Self::BeginPairing => "CrossShelfControlCommand::BeginPairing",
            Self::Pair { .. } => "CrossShelfControlCommand::Pair([code redacted])",
            Self::ConfirmPairing { .. } => {
                "CrossShelfControlCommand::ConfirmPairing([code redacted])"
            }
            Self::RevokePeer { .. } => "CrossShelfControlCommand::RevokePeer",
            Self::SetPeerPaused { .. } => "CrossShelfControlCommand::SetPeerPaused",
            Self::SendClipboard { .. } => {
                "CrossShelfControlCommand::SendClipboard([body redacted])"
            }
            Self::RemoteClipboardSnapshot { .. } => {
                "CrossShelfControlCommand::RemoteClipboardSnapshot"
            }
            Self::StartLiveClipboard { .. } => "CrossShelfControlCommand::StartLiveClipboard",
            Self::StopLiveClipboard => "CrossShelfControlCommand::StopLiveClipboard",
            Self::PauseClipboard { .. } => "CrossShelfControlCommand::PauseClipboard",
            Self::ClearLocalClipboard => "CrossShelfControlCommand::ClearLocalClipboard",
            Self::SendFile { .. } => {
                "CrossShelfControlCommand::SendFile([path and thumbnail redacted])"
            }
            Self::AcceptTransfer { .. } => "CrossShelfControlCommand::AcceptTransfer",
            Self::RejectTransfer { .. } => "CrossShelfControlCommand::RejectTransfer",
            Self::CancelTransfer { .. } => "CrossShelfControlCommand::CancelTransfer",
            Self::ListTransfers => "CrossShelfControlCommand::ListTransfers",
            Self::ListClipboardHistory => "CrossShelfControlCommand::ListClipboardHistory",
            Self::ClearClipboardHistory { .. } => "CrossShelfControlCommand::ClearClipboardHistory",
            Self::SendShelfEvent { .. } => {
                "CrossShelfControlCommand::SendShelfEvent([payload redacted])"
            }
            Self::SetFollowMeShelf { .. } => "CrossShelfControlCommand::SetFollowMeShelf",
            Self::RemoteSearch { .. } => "CrossShelfControlCommand::RemoteSearch([query redacted])",
            Self::FetchRemoteResult { .. } => "CrossShelfControlCommand::FetchRemoteResult",
            Self::FetchShelfItem { .. } => "CrossShelfControlCommand::FetchShelfItem",
            Self::GetTransfer { .. } => "CrossShelfControlCommand::GetTransfer",
            Self::ListPendingShelfEvents => "CrossShelfControlCommand::ListPendingShelfEvents",
            Self::WaitPendingShelfEvents { .. } => {
                "CrossShelfControlCommand::WaitPendingShelfEvents"
            }
            Self::MarkShelfEventApplied { .. } => "CrossShelfControlCommand::MarkShelfEventApplied",
            Self::Shutdown => "CrossShelfControlCommand::Shutdown",
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct CrossShelfIpcRequest {
    pub token: String,
    pub command: CrossShelfControlCommand,
}

impl fmt::Debug for CrossShelfIpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossShelfIpcRequest")
            .field("token", &"[redacted]")
            .field("command", &self.command)
            .finish()
    }
}

impl Drop for CrossShelfIpcRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossShelfIpcEndpoint {
    pub schema_version: u16,
    pub protocol: ProtocolVersion,
    pub process_id: u32,
    pub address: SocketAddr,
    pub token: String,
    pub started_at: DateTime<Utc>,
}

impl fmt::Debug for CrossShelfIpcEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossShelfIpcEndpoint")
            .field("schema_version", &self.schema_version)
            .field("protocol", &self.protocol)
            .field("process_id", &self.process_id)
            .field("address", &self.address)
            .field("token", &"[redacted]")
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl Drop for CrossShelfIpcEndpoint {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossShelfControlReply {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl fmt::Debug for CrossShelfControlReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossShelfControlReply")
            .field("ok", &self.ok)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("data", &self.data.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingShelfEventContract {
    pub peer_id: Uuid,
    pub event: SignedShelfEventContract,
    pub applied: bool,
    pub received_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_control_debug_is_redacted() {
        let command = CrossShelfControlCommand::SendClipboard {
            peer_id: Uuid::new_v4(),
            kind: ClipboardKind::PlainText,
            encoded_content: "private-body".to_string(),
            source_application: None,
            explicit_private: false,
            send_private_once: false,
        };
        assert!(!format!("{command:?}").contains("private-body"));

        let request = CrossShelfIpcRequest {
            token: "private-token".to_string(),
            command,
        };
        assert!(!format!("{request:?}").contains("private-token"));

        let shelf_id = Uuid::new_v4();
        let event = SignedShelfEventContract::from_mutation(
            shelf_id,
            Uuid::new_v4(),
            crate::DeviceIdentity::new("Editing PC"),
            crate::ShelfMutationContract::AddItem {
                kind: crate::ShelfItemKind::Video,
                display_name: "Hero.mov".to_string(),
                content: None,
                source_url: None,
                mime_type: Some("video/quicktime".to_string()),
                size: Some(10),
                content_hash: None,
                position: 0,
            },
        )
        .expect("event");
        let source_path = "C:\\Private\\Client\\Hero.mov";
        let command = CrossShelfControlCommand::SendShelfEvent {
            peer_id: Uuid::new_v4(),
            event,
            source_path: Some(source_path.to_string()),
        };
        assert!(!format!("{command:?}").contains(source_path));
    }

    #[test]
    fn remote_clipboard_snapshot_command_is_stable_and_reply_debug_redacts_data() {
        let peer_id = Uuid::new_v4();
        let command = CrossShelfControlCommand::RemoteClipboardSnapshot { peer_id };
        let value = serde_json::to_value(&command).unwrap();
        assert_eq!(value["command"], "remote_clipboard_snapshot");
        assert_eq!(value["peer_id"], peer_id.to_string());

        let secret = "remote clipboard body";
        let reply = CrossShelfControlReply {
            ok: true,
            code: "ok".to_string(),
            message: "snapshot".to_string(),
            data: Some(serde_json::json!({ "encoded_content": secret })),
        };
        assert!(!format!("{reply:?}").contains(secret));
    }
}
