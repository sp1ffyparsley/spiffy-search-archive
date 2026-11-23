use crate::catalog::SourceRoot;
use crate::error::{SearchError, SearchResult};
use crate::model::normalize_path;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchChangeKind {
    Upsert,
    Delete,
    Reconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchChange {
    pub root_id: Option<Uuid>,
    pub path: PathBuf,
    pub kind: WatchChangeKind,
    pub recursive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchBatch {
    pub changes: Vec<WatchChange>,
    pub overflowed: bool,
    pub dropped_events: u64,
    pub backend_errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherHealth {
    pub backend: String,
    pub roots: usize,
    pub overflowed: bool,
    pub dropped_events: u64,
}

enum WatchMessage {
    Event(Event),
    Error,
}

pub struct WatchCoordinator {
    watcher: RecommendedWatcher,
    receiver: mpsc::Receiver<WatchMessage>,
    roots: BTreeMap<Uuid, PathBuf>,
    debounce: Duration,
    overflowed: Arc<AtomicBool>,
    dropped_events: Arc<AtomicU64>,
}

impl WatchCoordinator {
    pub fn new(channel_capacity: usize, debounce: Duration) -> SearchResult<Self> {
        if !(128..=16_384).contains(&channel_capacity)
            || !(Duration::from_millis(100)..=Duration::from_secs(5)).contains(&debounce)
        {
            return Err(SearchError::Config(
                "watcher capacity or debounce is outside supported bounds".to_string(),
            ));
        }
        let (sender, receiver) = mpsc::sync_channel(channel_capacity);
        let overflowed = Arc::new(AtomicBool::new(false));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let callback_overflowed = Arc::clone(&overflowed);
        let callback_dropped = Arc::clone(&dropped_events);
        let watcher = notify::recommended_watcher(move |result| {
            let message = match result {
                Ok(event) => WatchMessage::Event(event),
                Err(_) => WatchMessage::Error,
            };
            match sender.try_send(message) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    callback_overflowed.store(true, Ordering::Relaxed);
                    callback_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {}
            }
        })
        .map_err(notify_error)?;
        Ok(Self {
            watcher,
            receiver,
            roots: BTreeMap::new(),
            debounce,
            overflowed,
            dropped_events,
        })
    }

    pub fn from_config(config: &crate::config::SearchConfig) -> SearchResult<Self> {
        Self::new(
            usize::from(config.watcher_channel_capacity),
            Duration::from_millis(u64::from(config.watcher_debounce_ms)),
        )
    }

    pub fn refresh_roots(&mut self, roots: &[SourceRoot]) -> SearchResult<()> {
        let desired = roots
            .iter()
            .filter(|root| root.enabled)
            .filter_map(|root| {
                let path = PathBuf::from(&root.canonical_path);
                if path.is_dir() {
                    Some((root.id, path))
                } else {
                    tracing::warn!(
                        root_id = %root.id,
                        path = %path.display(),
                        "watch root is unavailable; leaving it configured and continuing without a watcher"
                    );
                    None
                }
            })
            .collect::<BTreeMap<_, _>>();

        let stale = self
            .roots
            .iter()
            .filter(|(id, path)| desired.get(id) != Some(path))
            .map(|(id, path)| (*id, path.clone()))
            .collect::<Vec<_>>();
        for (id, path) in stale {
            self.watcher.unwatch(&path).map_err(notify_error)?;
            self.roots.remove(&id);
        }

        for (id, path) in desired {
            if self.roots.get(&id) == Some(&path) {
                continue;
            }
            self.watcher
                .watch(&path, RecursiveMode::Recursive)
                .map_err(notify_error)?;
            self.roots.insert(id, path);
        }
        Ok(())
    }

    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    pub fn health(&self) -> WatcherHealth {
        WatcherHealth {
            backend: recommended_backend_name().to_string(),
            roots: self.roots.len(),
            overflowed: self.overflowed.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
        }
    }

    pub fn receive_batch(&self, wait: Duration) -> SearchResult<WatchBatch> {
        let mut events = Vec::new();
        let mut backend_errors = 0_u64;
        match self.receiver.recv_timeout(wait) {
            Ok(WatchMessage::Event(event)) => events.push(event),
            Ok(WatchMessage::Error) => backend_errors = 1,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Ok(self.finish_batch(events, backend_errors));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(SearchError::State(
                    "filesystem watcher channel disconnected".to_string(),
                ));
            }
        }

        let maximum_deadline = Instant::now() + self.debounce.saturating_mul(8);
        let mut quiet_deadline = Instant::now() + self.debounce;
        while let Some(remaining) = quiet_deadline.checked_duration_since(Instant::now()) {
            match self.receiver.recv_timeout(remaining) {
                Ok(WatchMessage::Event(event)) => {
                    events.push(event);
                    quiet_deadline = (Instant::now() + self.debounce).min(maximum_deadline);
                }
                Ok(WatchMessage::Error) => {
                    backend_errors = backend_errors.saturating_add(1);
                    quiet_deadline = (Instant::now() + self.debounce).min(maximum_deadline);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(SearchError::State(
                        "filesystem watcher channel disconnected".to_string(),
                    ));
                }
            }
        }
        Ok(self.finish_batch(events, backend_errors))
    }

    fn finish_batch(&self, events: Vec<Event>, backend_errors: u64) -> WatchBatch {
        let mut changes: BTreeMap<(Option<Uuid>, String), WatchChange> = BTreeMap::new();
        for event in events {
            for change in changes_from_event(&event, &self.roots) {
                coalesce_change(&mut changes, change);
            }
        }
        let overflowed = self.overflowed.swap(false, Ordering::Relaxed);
        let dropped_events = self.dropped_events.swap(0, Ordering::Relaxed);
        if overflowed || backend_errors > 0 {
            for (root_id, path) in &self.roots {
                let change = WatchChange {
                    root_id: Some(*root_id),
                    path: path.clone(),
                    kind: WatchChangeKind::Reconcile,
                    recursive: true,
                };
                coalesce_change(&mut changes, change);
            }
        }
        WatchBatch {
            changes: changes.into_values().collect(),
            overflowed,
            dropped_events,
            backend_errors,
        }
    }
}

fn coalesce_change(
    changes: &mut BTreeMap<(Option<Uuid>, String), WatchChange>,
    mut incoming: WatchChange,
) {
    let key = (incoming.root_id, normalize_path(&incoming.path));
    if let Some(previous) = changes.get(&key) {
        incoming.recursive |= previous.recursive;
        if previous.kind == WatchChangeKind::Reconcile {
            incoming.kind = WatchChangeKind::Reconcile;
        }
    }
    changes.insert(key, incoming);
}

fn changes_from_event(event: &Event, roots: &BTreeMap<Uuid, PathBuf>) -> Vec<WatchChange> {
    match event.kind {
        EventKind::Access(_) => Vec::new(),
        EventKind::Remove(_) => event
            .paths
            .iter()
            .map(|path| {
                change(
                    path,
                    WatchChangeKind::Delete,
                    matches!(
                        event.kind,
                        EventKind::Remove(notify::event::RemoveKind::Folder)
                    ),
                    roots,
                )
            })
            .collect(),
        EventKind::Create(_) => event
            .paths
            .iter()
            .map(|path| {
                change(
                    path,
                    WatchChangeKind::Upsert,
                    matches!(
                        event.kind,
                        EventKind::Create(notify::event::CreateKind::Folder)
                    ),
                    roots,
                )
            })
            .collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) if event.paths.len() >= 2 => {
            vec![
                change(
                    &event.paths[0],
                    WatchChangeKind::Delete,
                    event.paths[1].is_dir(),
                    roots,
                ),
                change(
                    &event.paths[1],
                    WatchChangeKind::Upsert,
                    event.paths[1].is_dir(),
                    roots,
                ),
            ]
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => event
            .paths
            .iter()
            .map(|path| change(path, WatchChangeKind::Delete, true, roots))
            .collect(),
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => event
            .paths
            .iter()
            .map(|path| change(path, WatchChangeKind::Upsert, path.is_dir(), roots))
            .collect(),
        EventKind::Modify(ModifyKind::Name(_)) | EventKind::Any | EventKind::Other => event
            .paths
            .iter()
            .map(|path| change(path, WatchChangeKind::Reconcile, true, roots))
            .collect(),
        EventKind::Modify(_) => event
            .paths
            .iter()
            .map(|path| change(path, WatchChangeKind::Upsert, path.is_dir(), roots))
            .collect(),
    }
}

fn change(
    path: &Path,
    kind: WatchChangeKind,
    recursive: bool,
    roots: &BTreeMap<Uuid, PathBuf>,
) -> WatchChange {
    WatchChange {
        root_id: root_for_path(path, roots),
        path: path.to_path_buf(),
        kind,
        recursive,
    }
}

fn root_for_path(path: &Path, roots: &BTreeMap<Uuid, PathBuf>) -> Option<Uuid> {
    let normalized = normalize_path(path);
    roots
        .iter()
        .filter_map(|(id, root)| {
            let root = normalize_path(root);
            let matches = normalized == root
                || normalized
                    .strip_prefix(&root)
                    .is_some_and(|suffix| suffix.starts_with('/'));
            matches.then_some((*id, root.len()))
        })
        .max_by_key(|(_, length)| *length)
        .map(|(id, _)| id)
}

fn notify_error(error: notify::Error) -> SearchError {
    SearchError::State(format!("native filesystem watcher failed: {error}"))
}

fn recommended_backend_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "read_directory_changes_w"
    } else if cfg!(target_os = "macos") {
        "fsevents"
    } else {
        "recommended"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::SearchCatalog;
    use notify::event::{CreateKind, ModifyKind};
    use std::fs;

    #[test]
    fn rename_events_become_delete_and_upsert_with_longest_root_owner() {
        let parent = Uuid::new_v4();
        let nested = Uuid::new_v4();
        let roots = BTreeMap::from([
            (parent, PathBuf::from("C:/Media")),
            (nested, PathBuf::from("C:/Media/Project")),
        ]);
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            paths: vec![
                PathBuf::from("C:/Media/Project/Old.mov"),
                PathBuf::from("C:/Media/Project/New.mov"),
            ],
            attrs: Default::default(),
        };
        let changes = changes_from_event(&event, &roots);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].kind, WatchChangeKind::Delete);
        assert_eq!(changes[1].kind, WatchChangeKind::Upsert);
        assert!(changes.iter().all(|change| change.root_id == Some(nested)));
    }

    #[test]
    fn create_events_map_to_upserts() {
        let root = Uuid::new_v4();
        let roots = BTreeMap::from([(root, PathBuf::from("C:/Media"))]);
        let event = Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![PathBuf::from("C:/Media/Clip.mov")],
            attrs: Default::default(),
        };
        assert_eq!(
            changes_from_event(&event, &roots),
            [WatchChange {
                root_id: Some(root),
                path: PathBuf::from("C:/Media/Clip.mov"),
                kind: WatchChangeKind::Upsert,
                recursive: false,
            }]
        );
    }

    #[test]
    fn same_path_events_keep_last_semantic_state_and_reconcile_wins() {
        let root = Uuid::new_v4();
        let path = PathBuf::from("C:/Media/Clip.mov");
        let mut changes = BTreeMap::new();

        coalesce_change(
            &mut changes,
            WatchChange {
                root_id: Some(root),
                path: path.clone(),
                kind: WatchChangeKind::Delete,
                recursive: false,
            },
        );
        coalesce_change(
            &mut changes,
            WatchChange {
                root_id: Some(root),
                path: path.clone(),
                kind: WatchChangeKind::Upsert,
                recursive: false,
            },
        );
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes.values().next().unwrap().kind,
            WatchChangeKind::Upsert
        );

        coalesce_change(
            &mut changes,
            WatchChange {
                root_id: Some(root),
                path: path.clone(),
                kind: WatchChangeKind::Reconcile,
                recursive: true,
            },
        );
        coalesce_change(
            &mut changes,
            WatchChange {
                root_id: Some(root),
                path,
                kind: WatchChangeKind::Upsert,
                recursive: false,
            },
        );
        let change = changes.values().next().unwrap();
        assert_eq!(change.kind, WatchChangeKind::Reconcile);
        assert!(change.recursive);
    }

    #[test]
    fn native_watcher_observes_a_real_file_creation() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Root");
        fs::create_dir(&root_path).unwrap();
        let mut catalog = SearchCatalog::open(temp.path().join("search.db")).unwrap();
        let root = catalog.add_root(&root_path, false, Vec::new()).unwrap();
        let mut watcher = WatchCoordinator::new(128, Duration::from_millis(100)).unwrap();
        watcher.refresh_roots(std::slice::from_ref(&root)).unwrap();
        let created = root_path.join("Created.txt");
        fs::write(&created, b"created").unwrap();
        let batch = watcher.receive_batch(Duration::from_secs(5)).unwrap();
        assert!(batch.changes.iter().any(|change| {
            change.root_id == Some(root.id)
                && change.kind == WatchChangeKind::Upsert
                && normalize_path(&change.path) == normalize_path(&created)
        }));
        assert_eq!(watcher.health().roots, 1);
    }

    #[test]
    fn unavailable_configured_root_does_not_block_available_watch_roots() {
        let temp = tempfile::tempdir().unwrap();
        let available_path = temp.path().join("Available");
        let unavailable_path = temp.path().join("Unavailable");
        fs::create_dir(&available_path).unwrap();
        fs::create_dir(&unavailable_path).unwrap();
        let mut catalog = SearchCatalog::open(temp.path().join("search.db")).unwrap();
        let available = catalog
            .add_root(&available_path, false, Vec::new())
            .unwrap();
        let unavailable = catalog
            .add_root(&unavailable_path, false, Vec::new())
            .unwrap();
        fs::remove_dir(&unavailable_path).unwrap();

        let mut watcher = WatchCoordinator::new(128, Duration::from_millis(100)).unwrap();
        watcher
            .refresh_roots(&[available.clone(), unavailable])
            .unwrap();

        assert_eq!(watcher.root_count(), 1);
        assert_eq!(
            watcher.roots.get(&available.id),
            Some(&PathBuf::from(&available.canonical_path))
        );
    }
}
