use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SpiffyEvent {
    ShelfChanged {
        shelf_id: Uuid,
        revision: u64,
    },
    ItemAdded {
        shelf_id: Uuid,
        item_id: Uuid,
        revision: u64,
    },
    ItemRemoved {
        shelf_id: Uuid,
        item_id: Uuid,
        revision: u64,
    },
    TransferProgress {
        transfer_id: Uuid,
        completed_bytes: u64,
        total_bytes: u64,
    },
    SearchIndexChanged {
        generation: u64,
    },
    Tombstone {
        entity_id: Uuid,
        deleted_at: DateTime<Utc>,
        sequence: u64,
    },
}
