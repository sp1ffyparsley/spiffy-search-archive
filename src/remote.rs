use crate::catalog::SourceRoot;
use crate::engine::SearchRuntime;
use crate::error::{SearchError, SearchResult};
use crate::model::{FileCategory, FileRecord, ItemKind};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use spiffy_shared::{
    DeviceIdentity, RemoteAvailability, RemoteResultResolution, RemoteSearchQuery,
    RemoteSearchResponse, SearchResultContract, ShelfItemKind, REMOTE_SEARCH_LEASE_SECONDS,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path};
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

const MAX_ACTIVE_REMOTE_LEASES: usize = 4_096;

#[derive(Debug, Clone)]
struct RemoteLease {
    requester_device_id: Uuid,
    result_id: Uuid,
    root_id: Uuid,
    stable_key: String,
    stable_file_id: Option<spiffy_shared::StableFileIdentity>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct RemoteLeaseStore {
    leases: HashMap<(Uuid, Uuid), RemoteLease>,
}

impl RemoteLeaseStore {
    fn purge_expired(&mut self, now: DateTime<Utc>) {
        self.leases.retain(|_, lease| lease.expires_at > now);
    }

    fn insert(&mut self, lease: RemoteLease) {
        self.purge_expired(Utc::now());
        let key = (lease.requester_device_id, lease.result_id);
        self.leases.insert(key, lease);
        while self.leases.len() > MAX_ACTIVE_REMOTE_LEASES {
            let Some(oldest) = self
                .leases
                .iter()
                .min_by_key(|(_, lease)| lease.expires_at)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.leases.remove(&oldest);
        }
    }

    fn resolve(
        &mut self,
        requester_device_id: Uuid,
        result_id: Uuid,
        now: DateTime<Utc>,
    ) -> Option<RemoteLease> {
        self.purge_expired(now);
        self.leases.get(&(requester_device_id, result_id)).cloned()
    }
}

#[derive(Debug, Default)]
pub struct RemoteSearchBroker {
    leases: Mutex<RemoteLeaseStore>,
}

impl RemoteSearchBroker {
    pub fn search(
        &self,
        runtime: &SearchRuntime,
        requester_device_id: Uuid,
        serving_device: &DeviceIdentity,
        query: &RemoteSearchQuery,
    ) -> SearchResult<RemoteSearchResponse> {
        query
            .validate()
            .map_err(|message| SearchError::Query(message.to_string()))?;
        let roots = permitted_roots(runtime, query)?;
        let root_ids = roots.keys().copied().collect::<BTreeSet<_>>();
        let search =
            runtime.search_in_roots(&query.text, 0, Some(query.result_limit), &root_ids)?;
        let expires_at = Utc::now() + ChronoDuration::seconds(REMOTE_SEARCH_LEASE_SECONDS);
        let mut results = Vec::with_capacity(search.hits.len());
        let mut leases = self.lease_lock()?;
        leases.purge_expired(Utc::now());

        for hit in search.hits {
            let record = hit.record;
            let Some(root) = roots.get(&record.root_id) else {
                continue;
            };
            if !record_is_within_root(&record, root) {
                continue;
            }
            let result_id = stable_result_id(serving_device.id, &record);
            let availability = remote_availability(&record);
            if availability == RemoteAvailability::Available {
                leases.insert(RemoteLease {
                    requester_device_id,
                    result_id,
                    root_id: record.root_id,
                    stable_key: record.stable_key.clone(),
                    stable_file_id: record.stable_file_id.clone(),
                    expires_at,
                });
            }
            results.push(SearchResultContract {
                result_id,
                device: serving_device.clone(),
                remote_root_id: record.root_id,
                stable_file_id: None,
                display_name: record.filename.clone(),
                privacy_safe_path: privacy_safe_path(&record, root)?,
                kind: shelf_item_kind(&record),
                size: record.file.then_some(record.size),
                modified_at: record.modified_time,
                availability,
                thumbnail: None,
                expires_at,
            });
        }

        Ok(RemoteSearchResponse {
            query_id: query.query_id,
            truncated: search.total_candidates > results.len() as u64,
            results,
            expires_at,
        })
    }

    pub fn resolve(
        &self,
        runtime: &SearchRuntime,
        requester_device_id: Uuid,
        result_id: Uuid,
    ) -> SearchResult<RemoteResultResolution> {
        let lease = self
            .lease_lock()?
            .resolve(requester_device_id, result_id, Utc::now())
            .ok_or_else(|| {
                SearchError::Access("remote result is unknown or expired".to_string())
            })?;
        let root = runtime
            .roots()?
            .into_iter()
            .find(|root| root.id == lease.root_id && root.enabled && root.remote_searchable)
            .ok_or_else(|| {
                SearchError::Access("remote result root is no longer shared".to_string())
            })?;
        let indexed = runtime
            .item_metadata(&lease.stable_key)?
            .map(|metadata| metadata.record)
            .ok_or_else(|| SearchError::Access("remote result is no longer indexed".to_string()))?;
        if indexed.root_id != root.id
            || indexed.missing
            || indexed.tombstone
            || !indexed.file
            || indexed.stable_file_id != lease.stable_file_id
            || !record_is_within_root(&indexed, &root)
        {
            return Err(SearchError::Access(
                "remote result changed or is no longer transferable".to_string(),
            ));
        }

        if !Path::new(&indexed.canonical_path).is_file() {
            return Err(SearchError::Access(
                "remote result is no longer available for transfer".to_string(),
            ));
        }

        let fresh = crate::platform::file_record(
            Path::new(&indexed.canonical_path),
            root.id,
            runtime.device_id(),
        )?;
        if !fresh.file
            || fresh.stable_key != lease.stable_key
            || fresh.stable_file_id != lease.stable_file_id
            || !record_is_within_root(&fresh, &root)
        {
            return Err(SearchError::Access(
                "remote result identity changed before transfer".to_string(),
            ));
        }

        Ok(RemoteResultResolution {
            result_id,
            remote_root_id: root.id,
            stable_key: fresh.stable_key,
            canonical_path: fresh.canonical_path,
            stable_file_id: fresh.stable_file_id,
            byte_len: fresh.size,
            modified_at: fresh.modified_time,
        })
    }

    fn lease_lock(&self) -> SearchResult<MutexGuard<'_, RemoteLeaseStore>> {
        self.leases
            .lock()
            .map_err(|_| SearchError::State("remote search lease lock was poisoned".to_string()))
    }
}

fn permitted_roots(
    runtime: &SearchRuntime,
    query: &RemoteSearchQuery,
) -> SearchResult<BTreeMap<Uuid, SourceRoot>> {
    let available = runtime
        .roots()?
        .into_iter()
        .filter(|root| root.enabled && root.remote_searchable)
        .map(|root| (root.id, root))
        .collect::<BTreeMap<_, _>>();
    if query.permitted_root_ids.is_empty() {
        return Ok(available);
    }
    if query
        .permitted_root_ids
        .iter()
        .any(|root_id| !available.contains_key(root_id))
    {
        return Err(SearchError::Access(
            "requested roots are not available for remote search".to_string(),
        ));
    }
    Ok(query
        .permitted_root_ids
        .iter()
        .filter_map(|root_id| available.get(root_id).cloned().map(|root| (*root_id, root)))
        .collect())
}

fn stable_result_id(device_id: Uuid, record: &FileRecord) -> Uuid {
    let material = format!("{}:{}", record.root_id, record.stable_key);
    Uuid::new_v5(&device_id, material.as_bytes())
}

fn record_is_within_root(record: &FileRecord, root: &SourceRoot) -> bool {
    record.normalized_path == root.normalized_path
        || record
            .normalized_path
            .strip_prefix(&root.normalized_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn privacy_safe_path(record: &FileRecord, root: &SourceRoot) -> SearchResult<String> {
    let root_label = Path::new(&root.canonical_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("shared-root-{}", &root.id.simple().to_string()[..8]));
    let relative = Path::new(&record.canonical_path)
        .strip_prefix(Path::new(&root.canonical_path))
        .ok()
        .map(safe_relative_components)
        .transpose()?
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| record.filename.clone());
    Ok(format!("{root_label}/{relative}"))
}

fn safe_relative_components(path: &Path) -> SearchResult<String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| {
                    SearchError::Access(
                        "remote result path is not cross-platform UTF-8".to_string(),
                    )
                })?;
                components.push(value.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SearchError::Access(
                    "remote result path escaped its shared root".to_string(),
                ));
            }
        }
    }
    Ok(components.join("/"))
}

fn remote_availability(record: &FileRecord) -> RemoteAvailability {
    if record.missing || record.tombstone || !Path::new(&record.canonical_path).exists() {
        RemoteAvailability::Missing
    } else if record.file && !record.offline && !record.cloud_placeholder {
        RemoteAvailability::Available
    } else {
        RemoteAvailability::MetadataOnly
    }
}

fn shelf_item_kind(record: &FileRecord) -> ShelfItemKind {
    if record.folder {
        return ShelfItemKind::Folder;
    }
    match record.category {
        FileCategory::Image => ShelfItemKind::Image,
        FileCategory::Video => ShelfItemKind::Video,
        FileCategory::Audio => ShelfItemKind::Audio,
        _ if record.item_kind == ItemKind::Browser => ShelfItemKind::Url,
        _ => ShelfItemKind::File,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_leases_are_removed_before_resolution() {
        let requester = Uuid::new_v4();
        let result_id = Uuid::new_v4();
        let mut store = RemoteLeaseStore::default();
        store.insert(RemoteLease {
            requester_device_id: requester,
            result_id,
            root_id: Uuid::new_v4(),
            stable_key: "key".to_string(),
            stable_file_id: None,
            expires_at: Utc::now() - ChronoDuration::seconds(1),
        });
        assert!(store.resolve(requester, result_id, Utc::now()).is_none());
        assert!(store.leases.is_empty());
    }
}
