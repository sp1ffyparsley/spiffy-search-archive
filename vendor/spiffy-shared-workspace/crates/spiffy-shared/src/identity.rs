use std::path::Path;

use file_id::FileId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub id: Uuid,
    pub display_name: String,
}

impl DeviceIdentity {
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            display_name: display_name.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StableFileIdentity {
    pub volume_id: String,
    pub file_id: String,
    pub creation_time_millis: Option<u64>,
    pub path_fallback: bool,
}

impl StableFileIdentity {
    pub fn from_path(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::metadata(path)?;
        let created = metadata
            .created()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as u64);

        let identity = match file_id::get_file_id(path) {
            Ok(FileId::Inode {
                device_id,
                inode_number,
            }) => Self {
                volume_id: format!("{device_id:x}"),
                file_id: format!("{inode_number:x}"),
                creation_time_millis: created,
                path_fallback: false,
            },
            Ok(FileId::LowRes {
                volume_serial_number,
                file_index,
            }) => Self {
                volume_id: format!("{volume_serial_number:08x}"),
                file_id: format!("{file_index:016x}"),
                creation_time_millis: created,
                path_fallback: false,
            },
            Ok(FileId::HighRes {
                volume_serial_number,
                file_id,
            }) => Self {
                volume_id: format!("{volume_serial_number:016x}"),
                file_id: format!("{file_id:032x}"),
                creation_time_millis: created,
                path_fallback: false,
            },
            Err(_) => fallback_identity(path, &metadata, created),
        };
        Ok(identity)
    }
}

fn fallback_identity(
    path: &Path,
    metadata: &std::fs::Metadata,
    created: Option<u64>,
) -> StableFileIdentity {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let fingerprint = format!("{}:{}:{created:?}", canonical.display(), metadata.len());
    StableFileIdentity {
        volume_id: "path-fallback".to_string(),
        file_id: blake3::hash(fingerprint.as_bytes()).to_hex().to_string(),
        creation_time_millis: created,
        path_fallback: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_executable_has_a_stable_identity() {
        let executable = std::env::current_exe().expect("current executable");
        let identity = StableFileIdentity::from_path(&executable).expect("file identity");
        assert!(!identity.file_id.is_empty());
        assert!(!identity.volume_id.is_empty());
    }
}
