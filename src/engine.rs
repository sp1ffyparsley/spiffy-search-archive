use crate::browser::{BrowserClearReport, BrowserCollection, BrowserRefreshReport};
use crate::catalog::{SearchCatalog, SourceRoot};
use crate::config::SearchConfig;
use crate::content::{ContentIndexReport, ContentSearchReader, ContentService};
use crate::error::{SearchError, SearchResult};
use crate::index::{FilenameIndex, FilenameSearchReader};
use crate::model::{
    normalize_path, FavoriteItem, ItemKind, ItemMetadata, ItemOverlay, PreviewText,
};
use crate::protocol::{AgentStatus, DoctorReport, FileOperationReceipt, SearchResponse};
use crate::query::{ParsedQuery, SearchMode};
use crate::ranking::{rank_candidates, rank_content_candidates, RankingContext};
use crate::scanner::{scan_root, ScanOptions, ScanStats};
use crate::watcher::{WatchBatch, WatchChangeKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexingReport {
    pub root_id: Uuid,
    pub scan: ScanStats,
    pub index_generation: u64,
    pub indexed_documents: u64,
    pub commit_opstamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchApplyReport {
    pub upserts: u64,
    pub deletes: u64,
    pub ignored: u64,
    pub reconciliation_roots: Vec<Uuid>,
    pub index_generation: u64,
    pub indexed_documents: u64,
    pub content_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceCatalogRefreshReport {
    pub root_id: Uuid,
    pub indexed_workspace_records: u64,
    pub index_generation: u64,
    pub indexed_documents: u64,
}

pub struct SearchEngine {
    config: SearchConfig,
    config_path: PathBuf,
    catalog: SearchCatalog,
    filename_index: FilenameIndex,
    content: Option<Arc<ContentService>>,
    browser_snapshot_cache_path: PathBuf,
    device_id: Uuid,
    started_at: DateTime<Utc>,
    indexing: bool,
}

pub struct SearchRuntime {
    config: SearchConfig,
    config_path: PathBuf,
    index_path: PathBuf,
    catalog: Mutex<SearchCatalog>,
    filename_reader: FilenameSearchReader,
    content: Option<Arc<ContentService>>,
    device_id: Uuid,
    started_at: DateTime<Utc>,
}

impl SearchEngine {
    pub fn open_default() -> SearchResult<Self> {
        let config_path = crate::config::config_path();
        let config = SearchConfig::load_or_create(&config_path)?;
        Self::open_paths(
            config,
            config_path,
            crate::config::database_path(),
            crate::config::filename_index_path(),
            crate::config::content_index_path(),
            crate::config::browser_snapshot_cache_dir(),
        )
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(base: &Path, config: SearchConfig) -> SearchResult<Self> {
        let config_path = base.join("search-config.json");
        config.save(&config_path)?;
        Self::open_paths(
            config,
            config_path,
            base.join("search.db"),
            base.join("index"),
            base.join("content-index"),
            base.join("browser-snapshots"),
        )
    }

    fn open_paths(
        config: SearchConfig,
        config_path: PathBuf,
        database_path: PathBuf,
        index_path: PathBuf,
        content_index_path: PathBuf,
        browser_snapshot_cache_path: PathBuf,
    ) -> SearchResult<Self> {
        config.validate()?;
        let mut catalog = SearchCatalog::open(database_path)?;
        let mut interrupted_operations = catalog.interrupted_operation_receipts()?;
        for receipt in &mut interrupted_operations {
            let was_undoing = receipt.state == crate::protocol::FileOperationState::Undoing;
            crate::file_ops::reconcile_interrupted_actions(receipt);
            let cleanup = crate::file_ops::cleanup_interrupted_staging(receipt);
            let undo_completed =
                was_undoing && receipt.undo_actions.iter().all(|action| action.undone);
            receipt.completed_at = Some(Utc::now());
            receipt.progress.current_path = None;
            if undo_completed {
                receipt.state = crate::protocol::FileOperationState::Undone;
                receipt.progress.phase = "undone".to_string();
                receipt.error_code = None;
                receipt.message = Some(
                    "The agent restarted after undo completed; the receipt was reconciled"
                        .to_string(),
                );
            } else {
                receipt.state = crate::protocol::FileOperationState::Failed;
                receipt.progress.phase = "failed".to_string();
                match cleanup {
                    Ok(removed) => {
                        receipt.error_code = Some("agent_restarted".to_string());
                        receipt.message = Some(format!(
                            "The agent restarted before the operation completed; removed {removed} owned staging item(s)"
                        ));
                    }
                    Err(error) => {
                        receipt.error_code = Some("agent_restart_cleanup_failed".to_string());
                        receipt.message = Some(format!(
                            "The agent restarted before the operation completed; owned staging cleanup failed: {error}"
                        ));
                    }
                }
            }
            catalog.write_operation_receipt(receipt)?;
        }
        if !interrupted_operations.is_empty() {
            tracing::warn!(
                recovered_operations = interrupted_operations.len(),
                "interrupted file operations reconciled after restart"
            );
        }
        let device_id = catalog.local_device_id()?;
        let filename_index = if index_path == crate::config::filename_index_path() {
            FilenameIndex::open_default(config.index_writer_memory_mb)?
        } else {
            #[cfg(test)]
            {
                FilenameIndex::open_for_test(&index_path, config.index_writer_memory_mb)?
            }
            #[cfg(not(test))]
            {
                return Err(SearchError::Config(format!(
                    "custom filename index path is unsupported: {}",
                    index_path.display()
                )));
            }
        };
        let index_documents = filename_index.document_count();
        let content = if config.content.enabled {
            if content_index_path == crate::config::content_index_path() {
                Some(Arc::new(ContentService::open_default(
                    config.content.clone(),
                    config.index_writer_memory_mb,
                )?))
            } else {
                #[cfg(test)]
                {
                    Some(Arc::new(ContentService::open_for_test(
                        &content_index_path,
                        config.content.clone(),
                        config.index_writer_memory_mb,
                    )?))
                }
                #[cfg(not(test))]
                {
                    return Err(SearchError::Config(format!(
                        "custom content index path is unsupported: {}",
                        content_index_path.display()
                    )));
                }
            }
        } else {
            None
        };
        let state = catalog.index_state()?;
        if state.indexed_documents != index_documents {
            catalog.synchronize_index_snapshot(
                index_documents,
                true,
                Some("catalog_index_count_mismatch"),
            )?;
        }
        tracing::info!(
            config = %config_path.display(),
            database = %catalog.database_path().display(),
            index = %filename_index.path().display(),
            device_id = %device_id,
            documents = index_documents,
            "Spiffy Search engine opened"
        );
        let mut engine = Self {
            config,
            config_path,
            catalog,
            filename_index,
            content,
            browser_snapshot_cache_path,
            device_id,
            started_at: Utc::now(),
            indexing: false,
        };
        if let Some(path) = engine.config.workspace_catalog_path.clone() {
            match engine.refresh_workspace_catalog(&path) {
                Ok(report) => tracing::info!(
                    catalog = %path.display(),
                    records = report.indexed_workspace_records,
                    generation = report.index_generation,
                    "workspace launch catalog indexed"
                ),
                Err(error) => tracing::warn!(
                    catalog = %path.display(),
                    %error,
                    "workspace launch catalog refresh failed; keeping the last indexed snapshot"
                ),
            }
        }
        Ok(engine)
    }

    pub fn config(&self) -> &SearchConfig {
        &self.config
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn search_runtime(&self) -> SearchResult<SearchRuntime> {
        Ok(SearchRuntime {
            config: self.config.clone(),
            config_path: self.config_path.clone(),
            index_path: self.filename_index.path().to_path_buf(),
            catalog: Mutex::new(SearchCatalog::open(
                self.catalog.database_path().to_path_buf(),
            )?),
            filename_reader: self.filename_index.search_reader(),
            content: self.content.clone(),
            device_id: self.device_id,
            started_at: self.started_at,
        })
    }

    pub fn roots(&self) -> SearchResult<Vec<SourceRoot>> {
        self.catalog.roots(false)
    }

    pub fn add_root(
        &mut self,
        path: &Path,
        remote_searchable: bool,
        exclusions: Vec<String>,
    ) -> SearchResult<SourceRoot> {
        let root = self.catalog.add_root(path, remote_searchable, exclusions)?;
        tracing::info!(root_id = %root.id, path = %root.canonical_path, "search root added");
        Ok(root)
    }

    pub fn remove_root(&mut self, root_id: Uuid) -> SearchResult<bool> {
        if self.catalog.root(root_id)?.is_none() {
            return Ok(false);
        }
        if let Some(content) = &self.content {
            content.delete_root(root_id)?;
        }
        self.filename_index.begin_root_replace(root_id);
        let commit = self.filename_index.commit()?;
        self.catalog
            .advance_index_generation(commit.indexed_documents)?;
        let removed = self.catalog.remove_root(root_id)?;
        tracing::info!(%root_id, documents = commit.indexed_documents, "search root removed");
        Ok(removed)
    }

    pub fn index_root(
        &mut self,
        root_id: Uuid,
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<IndexingReport> {
        if self.indexing {
            return Err(SearchError::State(
                "an index operation is already running".to_string(),
            ));
        }
        let root = self
            .catalog
            .root(root_id)?
            .ok_or_else(|| SearchError::State(format!("source root {root_id} was not found")))?;
        self.indexing = true;
        let result = self.index_root_inner(&root, cancellation);
        self.indexing = false;
        result
    }

    fn index_root_inner(
        &mut self,
        root: &SourceRoot,
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<IndexingReport> {
        self.catalog.mark_root_scan_started(root.id)?;
        self.filename_index.begin_root_replace(root.id);
        let options = ScanOptions::from_config(&self.config);
        let scan_result = scan_root(
            root,
            self.device_id,
            &options,
            Arc::clone(&cancellation),
            |batch| self.filename_index.add_batch(&batch),
        );
        let scan = match scan_result {
            Ok(scan) if scan.cancelled => {
                self.filename_index.rollback()?;
                self.catalog
                    .mark_root_scan_failed(root.id, "scan_cancelled")?;
                self.catalog
                    .set_reconciliation_pending(true, Some("scan_cancelled"))?;
                return Err(SearchError::State(format!(
                    "indexing source root {} was cancelled",
                    root.id
                )));
            }
            Ok(scan) if scan.metadata_errors > 0 => {
                self.filename_index.rollback()?;
                self.catalog
                    .mark_root_scan_failed(root.id, "scan_metadata_errors")?;
                self.catalog
                    .set_reconciliation_pending(true, Some("scan_metadata_errors"))?;
                return Err(SearchError::State(format!(
                    "indexing source root {} encountered {} metadata errors; the prior snapshot was retained",
                    root.id, scan.metadata_errors
                )));
            }
            Ok(scan) => scan,
            Err(error) => {
                if let Err(rollback_error) = self.filename_index.rollback() {
                    tracing::error!(%rollback_error, root_id = %root.id, "index rollback failed");
                }
                let _ = self.catalog.mark_root_scan_failed(root.id, "scan_failed");
                let _ = self
                    .catalog
                    .set_reconciliation_pending(true, Some("scan_failed"));
                return Err(error);
            }
        };
        let commit = self.filename_index.commit()?;
        let state = match self
            .catalog
            .mark_root_scan_completed(root.id, commit.indexed_documents)
        {
            Ok(state) => state,
            Err(error) => {
                let _ = self.catalog.synchronize_index_snapshot(
                    commit.indexed_documents,
                    true,
                    Some("catalog_commit_failed"),
                );
                return Err(error);
            }
        };
        tracing::info!(
            root_id = %root.id,
            indexed = scan.indexed_entries,
            errors = scan.metadata_errors,
            elapsed_ms = scan.elapsed_millis,
            generation = state.generation,
            "search root indexed"
        );
        Ok(IndexingReport {
            root_id: root.id,
            scan,
            index_generation: state.generation,
            indexed_documents: commit.indexed_documents,
            commit_opstamp: commit.opstamp,
        })
    }

    pub fn index_all(
        &mut self,
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<Vec<IndexingReport>> {
        let roots = self.catalog.roots(true)?;
        let mut reports = Vec::with_capacity(roots.len());
        for root in roots {
            if cancellation.load(Ordering::Relaxed) {
                return Err(SearchError::State(
                    "full indexing was cancelled".to_string(),
                ));
            }
            reports.push(self.index_root(root.id, Arc::clone(&cancellation))?);
        }
        Ok(reports)
    }

    pub fn apply_watch_batch(&mut self, batch: &WatchBatch) -> SearchResult<WatchApplyReport> {
        if self.indexing {
            return Err(SearchError::State(
                "cannot apply watcher changes during a full index operation".to_string(),
            ));
        }
        let mut upserts = 0_u64;
        let mut deletes = 0_u64;
        let mut ignored = 0_u64;
        let mut touched_index = false;
        let mut content_deletes = BTreeSet::new();
        let mut content_paths = BTreeSet::new();
        let mut reconciliation_roots = BTreeSet::new();
        let apply_result = (|| -> SearchResult<()> {
            for change in &batch.changes {
                if crate::file_ops::is_operation_staging_path(&change.path) {
                    ignored = ignored.saturating_add(1);
                    continue;
                }
                let Some(root_id) = change.root_id else {
                    ignored = ignored.saturating_add(1);
                    continue;
                };
                let Some(root) = self.catalog.root(root_id)? else {
                    ignored = ignored.saturating_add(1);
                    continue;
                };
                if !path_is_within_root(&change.path, &root) {
                    ignored = ignored.saturating_add(1);
                    reconciliation_roots.insert(root_id);
                    continue;
                }
                if change.kind == WatchChangeKind::Reconcile {
                    reconciliation_roots.insert(root_id);
                    continue;
                }
                if change.recursive {
                    reconciliation_roots.insert(root_id);
                }
                match change.kind {
                    WatchChangeKind::Delete => {
                        let normalized_path = normalize_path(&change.path);
                        self.filename_index
                            .delete_normalized_path(&normalized_path)?;
                        if self.content.is_some() {
                            content_deletes.insert(normalized_path);
                        }
                        touched_index = true;
                        deletes = deletes.saturating_add(1);
                    }
                    WatchChangeKind::Upsert => {
                        let symlink_metadata = match std::fs::symlink_metadata(&change.path) {
                            Ok(metadata) => metadata,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                self.filename_index
                                    .delete_normalized_path(&normalize_path(&change.path))?;
                                if self.content.is_some() {
                                    content_deletes.insert(normalize_path(&change.path));
                                }
                                touched_index = true;
                                deletes = deletes.saturating_add(1);
                                continue;
                            }
                            Err(error) => {
                                return Err(crate::error::io_error(&change.path, error));
                            }
                        };
                        if symlink_metadata.file_type().is_symlink() {
                            ignored = ignored.saturating_add(1);
                            continue;
                        }
                        let is_directory = symlink_metadata.is_dir();
                        if path_is_excluded(&root, &change.path, is_directory)? {
                            self.filename_index
                                .delete_normalized_path(&normalize_path(&change.path))?;
                            if self.content.is_some() {
                                content_deletes.insert(normalize_path(&change.path));
                            }
                            touched_index = true;
                            deletes = deletes.saturating_add(1);
                            continue;
                        }
                        let record =
                            crate::platform::file_record(&change.path, root_id, self.device_id)?;
                        if (!self.config.include_hidden && record.hidden)
                            || (!self.config.include_system && record.system)
                        {
                            self.filename_index
                                .delete_normalized_path(&record.normalized_path)?;
                            if self.content.is_some() {
                                content_deletes.insert(record.normalized_path.clone());
                            }
                            touched_index = true;
                            deletes = deletes.saturating_add(1);
                            continue;
                        }
                        self.filename_index
                            .add_batch(std::slice::from_ref(&record))?;
                        if self.content.is_some() && record.file {
                            content_paths.insert(record.canonical_path.clone());
                        }
                        touched_index = true;
                        upserts = upserts.saturating_add(1);
                    }
                    WatchChangeKind::Reconcile => unreachable!("handled above"),
                }
            }
            Ok(())
        })();
        if let Err(error) = apply_result {
            if let Err(rollback_error) = self.filename_index.rollback() {
                tracing::error!(%rollback_error, "watch batch rollback failed");
            }
            let _ = self
                .catalog
                .set_reconciliation_pending(true, Some("watch_apply_failed"));
            return Err(error);
        }

        if let Some(content) = &self.content {
            if let Err(error) =
                content.delete_normalized_paths(&content_deletes.into_iter().collect::<Vec<_>>())
            {
                if let Err(rollback_error) = self.filename_index.rollback() {
                    tracing::error!(%rollback_error, "filename rollback after content delete failed");
                }
                return Err(error);
            }
        }

        let state = if touched_index {
            let commit = self.filename_index.commit()?;
            self.catalog
                .advance_index_generation(commit.indexed_documents)?
        } else {
            self.catalog.index_state()?
        };
        let reconciliation_code = if batch.overflowed {
            Some("watcher_overflow")
        } else if batch.backend_errors > 0 {
            Some("watcher_backend_error")
        } else if !reconciliation_roots.is_empty() {
            Some("watcher_subtree_change")
        } else {
            None
        };
        if let Some(code) = reconciliation_code {
            self.catalog.set_reconciliation_pending(true, Some(code))?;
        }
        Ok(WatchApplyReport {
            upserts,
            deletes,
            ignored,
            reconciliation_roots: reconciliation_roots.into_iter().collect(),
            index_generation: state.generation,
            indexed_documents: state.indexed_documents,
            content_paths: content_paths.into_iter().collect(),
        })
    }

    pub fn refresh_browser_history(
        &mut self,
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<BrowserRefreshReport> {
        if !crate::browser::any_enabled(&self.config.browsers) {
            return Err(SearchError::Browser(
                "browser history is disabled in Search configuration".to_string(),
            ));
        }
        let collection = crate::browser::collect_enabled(
            &self.config.browsers,
            self.device_id,
            &self.browser_snapshot_cache_path,
            &cancellation,
        )?;
        if cancellation.load(Ordering::Acquire) {
            return Err(SearchError::Browser(
                "browser history refresh was cancelled".to_string(),
            ));
        }
        self.apply_browser_collection(collection)
    }

    pub fn refresh_workspace_catalog(
        &mut self,
        path: &Path,
    ) -> SearchResult<WorkspaceCatalogRefreshReport> {
        let snapshot = crate::workspace_catalog::load(path, self.device_id)?;
        let root_id = snapshot.root_id;
        let record_count = u64::try_from(snapshot.records.len()).map_err(|_| {
            SearchError::State("workspace catalog record count exceeds u64".to_string())
        })?;
        self.filename_index.begin_root_replace(root_id);
        let apply_result = snapshot
            .records
            .chunks(512)
            .try_for_each(|batch| self.filename_index.add_batch(batch));
        if let Err(error) = apply_result {
            if let Err(rollback_error) = self.filename_index.rollback() {
                tracing::error!(%rollback_error, "workspace catalog index rollback failed");
            }
            return Err(error);
        }
        let commit = self.filename_index.commit()?;
        let state = match self
            .catalog
            .advance_index_generation(commit.indexed_documents)
        {
            Ok(state) => state,
            Err(error) => {
                let _ = self.catalog.synchronize_index_snapshot(
                    commit.indexed_documents,
                    true,
                    Some("workspace_catalog_commit_failed"),
                );
                return Err(error);
            }
        };
        Ok(WorkspaceCatalogRefreshReport {
            root_id,
            indexed_workspace_records: record_count,
            index_generation: state.generation,
            indexed_documents: state.indexed_documents,
        })
    }

    fn apply_browser_collection(
        &mut self,
        collection: BrowserCollection,
    ) -> SearchResult<BrowserRefreshReport> {
        let mut report = BrowserRefreshReport::from_collection(&collection);
        let apply_result = (|| -> SearchResult<()> {
            for snapshot in &collection.snapshots {
                self.filename_index
                    .begin_root_replace(snapshot.provider.root_id());
                for batch in snapshot.records.chunks(512) {
                    self.filename_index.add_batch(batch)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = apply_result {
            if let Err(rollback_error) = self.filename_index.rollback() {
                tracing::error!(%rollback_error, "browser index rollback failed");
            }
            return Err(error);
        }
        let commit = self.filename_index.commit()?;
        let state = match self
            .catalog
            .advance_index_generation(commit.indexed_documents)
        {
            Ok(state) => state,
            Err(error) => {
                let _ = self.catalog.synchronize_index_snapshot(
                    commit.indexed_documents,
                    true,
                    Some("browser_catalog_commit_failed"),
                );
                return Err(error);
            }
        };
        report.completed_at = Utc::now();
        report.indexed_browser_records =
            self.filename_index.kind_document_count(ItemKind::Browser)?;
        report.index_generation = state.generation;
        report.indexed_documents = state.indexed_documents;
        Ok(report)
    }

    pub fn clear_browser_history(&mut self) -> SearchResult<BrowserClearReport> {
        let before = self.filename_index.kind_document_count(ItemKind::Browser)?;
        for provider in crate::browser::BrowserProvider::ALL {
            self.filename_index.begin_root_replace(provider.root_id());
        }
        let commit = self.filename_index.commit()?;
        let state = match self
            .catalog
            .advance_index_generation(commit.indexed_documents)
        {
            Ok(state) => state,
            Err(error) => {
                let _ = self.catalog.synchronize_index_snapshot(
                    commit.indexed_documents,
                    true,
                    Some("browser_clear_catalog_commit_failed"),
                );
                return Err(error);
            }
        };
        let after = self.filename_index.kind_document_count(ItemKind::Browser)?;
        crate::browser::clear_snapshot_cache(&self.browser_snapshot_cache_path)?;
        Ok(BrowserClearReport {
            removed_records: before.saturating_sub(after),
            index_generation: state.generation,
            indexed_documents: state.indexed_documents,
        })
    }

    pub fn search(
        &self,
        raw_query: &str,
        request_generation: u64,
        requested_limit: Option<u16>,
        current_folder: Option<&Path>,
    ) -> SearchResult<SearchResponse> {
        search_with(
            SearchBackends {
                config: &self.config,
                catalog: &self.catalog,
                filename: &self.filename_index.search_reader(),
                content: self.content.as_ref().map(|content| content.search_reader()),
            },
            raw_query,
            request_generation,
            requested_limit,
            current_folder,
            None,
        )
    }

    pub fn set_favorite(
        &mut self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        favorite: bool,
    ) -> SearchResult<ItemOverlay> {
        self.catalog
            .set_favorite(stable_key, display_name, path, favorite)
    }

    pub fn set_pinned(
        &mut self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        pinned: bool,
    ) -> SearchResult<ItemOverlay> {
        self.catalog
            .set_pinned(stable_key, display_name, path, pinned)
    }

    pub fn set_aliases(
        &mut self,
        stable_key: &str,
        aliases: Vec<String>,
    ) -> SearchResult<ItemOverlay> {
        self.catalog.set_aliases(stable_key, aliases)
    }

    pub fn record_usage(&mut self, stable_key: &str, selected: bool) -> SearchResult<ItemOverlay> {
        self.catalog.record_usage(stable_key, selected)
    }

    pub fn overlay(&self, stable_key: &str) -> SearchResult<ItemOverlay> {
        self.catalog.overlay(stable_key)
    }

    pub fn status(
        &self,
        watcher_roots: usize,
        local_api_address: Option<String>,
    ) -> SearchResult<AgentStatus> {
        let state = self.catalog.index_state()?;
        Ok(AgentStatus {
            protocol: crate::protocol::SEARCH_PROTOCOL_VERSION,
            started_at: self.started_at,
            index_generation: state.generation,
            indexed_documents: self.filename_index.document_count(),
            roots: self.catalog.roots(false)?.len(),
            watcher_roots,
            indexing: self.indexing,
            content_enabled: self.config.content.enabled,
            content_indexing: false,
            content_pending: 0,
            content_documents: self
                .content
                .as_ref()
                .map_or(0, |content| content.document_count()),
            browser_enabled: crate::browser::any_enabled(&self.config.browsers),
            browser_refreshing: false,
            browser_documents: self.filename_index.kind_document_count(ItemKind::Browser)?,
            local_api_address,
        })
    }

    pub fn doctor(&self, endpoint_owner_only: bool) -> SearchResult<DoctorReport> {
        let catalog = self.catalog.doctor()?;
        let state = self.catalog.index_state()?;
        let filename_documents = self.filename_index.verify()?;
        let filename_index_healthy = filename_documents == state.indexed_documents;
        let content_index_healthy = if self.config.content.enabled {
            self.content
                .as_ref()
                .is_some_and(|content| content.verify().is_ok())
        } else {
            true
        };
        Ok(DoctorReport {
            healthy: catalog.healthy
                && filename_index_healthy
                && content_index_healthy
                && endpoint_owner_only
                && !state.pending_reconciliation,
            schema_version: u16::try_from(catalog.schema_version).unwrap_or(u16::MAX),
            sqlite_quick_check: catalog.quick_check,
            filename_index_healthy,
            content_index_healthy,
            endpoint_owner_only,
            pending_reconciliation: state.pending_reconciliation,
            config_path: self.config_path.to_string_lossy().to_string(),
            database_path: self.catalog.database_path().to_string_lossy().to_string(),
            index_path: self.filename_index.path().to_string_lossy().to_string(),
            content_index_path: self
                .content
                .as_ref()
                .map(|content| content.path().to_string_lossy().to_string()),
            last_error_code: state.last_error_code,
        })
    }
}

impl SearchRuntime {
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn max_results(&self) -> u16 {
        self.config.max_results
    }

    pub fn preview_text_allowed(&self) -> bool {
        self.config.local_api.allow_preview_text
    }

    pub fn item_metadata(&self, stable_key: &str) -> SearchResult<Option<ItemMetadata>> {
        let Some(record) = self.filename_reader.record_by_stable_key(stable_key)? else {
            return Ok(None);
        };
        let overlay = self
            .catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .overlay(stable_key)?;
        Ok(Some(ItemMetadata { record, overlay }))
    }

    pub fn preview_text(
        &self,
        stable_key: &str,
        max_chars: u32,
    ) -> SearchResult<Option<PreviewText>> {
        if !self.preview_text_allowed() {
            return Err(SearchError::Content(
                "preview text access is disabled in Search configuration".to_string(),
            ));
        }
        self.content
            .as_ref()
            .ok_or_else(|| {
                SearchError::Content("preview text requires the optional content index".to_string())
            })?
            .search_reader()
            .preview_text(stable_key, max_chars)
    }

    pub fn favorite_items(&self, limit: u16) -> SearchResult<Vec<FavoriteItem>> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .favorite_items(limit)
    }

    pub fn browser_history_enabled(&self) -> bool {
        crate::browser::any_enabled(&self.config.browsers)
    }

    pub fn browser_config(&self) -> &crate::config::BrowserConfig {
        &self.config.browsers
    }

    pub fn browser_document_count(&self) -> SearchResult<u64> {
        self.filename_reader.kind_document_count(ItemKind::Browser)
    }

    pub fn content_enabled(&self) -> bool {
        self.content.is_some()
    }

    pub fn content_document_count(&self) -> u64 {
        self.content
            .as_ref()
            .map_or(0, |content| content.document_count())
    }

    pub fn search(
        &self,
        raw_query: &str,
        request_generation: u64,
        requested_limit: Option<u16>,
        current_folder: Option<&Path>,
    ) -> SearchResult<SearchResponse> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?;
        search_with(
            SearchBackends {
                config: &self.config,
                catalog: &catalog,
                filename: &self.filename_reader,
                content: self.content.as_ref().map(|content| content.search_reader()),
            },
            raw_query,
            request_generation,
            requested_limit,
            current_folder,
            None,
        )
    }

    pub fn search_in_roots(
        &self,
        raw_query: &str,
        request_generation: u64,
        requested_limit: Option<u16>,
        allowed_root_ids: &std::collections::BTreeSet<Uuid>,
    ) -> SearchResult<SearchResponse> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?;
        search_with(
            SearchBackends {
                config: &self.config,
                catalog: &catalog,
                filename: &self.filename_reader,
                content: self.content.as_ref().map(|content| content.search_reader()),
            },
            raw_query,
            request_generation,
            requested_limit,
            None,
            Some(allowed_root_ids),
        )
    }

    pub fn roots(&self) -> SearchResult<Vec<SourceRoot>> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .roots(false)
    }

    pub fn set_favorite(
        &self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        favorite: bool,
    ) -> SearchResult<ItemOverlay> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .set_favorite(stable_key, display_name, path, favorite)
    }

    pub fn set_pinned(
        &self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        pinned: bool,
    ) -> SearchResult<ItemOverlay> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .set_pinned(stable_key, display_name, path, pinned)
    }

    pub fn set_aliases(&self, stable_key: &str, aliases: Vec<String>) -> SearchResult<ItemOverlay> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .set_aliases(stable_key, aliases)
    }

    pub fn record_usage(&self, stable_key: &str, selected: bool) -> SearchResult<ItemOverlay> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .record_usage(stable_key, selected)
    }

    pub fn overlay(&self, stable_key: &str) -> SearchResult<ItemOverlay> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .overlay(stable_key)
    }

    pub fn write_operation_receipt(&self, receipt: &FileOperationReceipt) -> SearchResult<()> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .write_operation_receipt(receipt)
    }

    pub fn operation_receipt(
        &self,
        operation_id: Uuid,
    ) -> SearchResult<Option<FileOperationReceipt>> {
        self.catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .operation_receipt(operation_id)
    }

    pub fn index_content(
        &self,
        paths: &[String],
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<ContentIndexReport> {
        let content = self.content.as_ref().ok_or_else(|| {
            SearchError::Content(
                "content indexing is disabled in the current configuration".to_string(),
            )
        })?;
        let roots = self
            .catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?
            .roots(true)?;
        if paths.is_empty() {
            return self.index_all_content(content, &roots, cancellation);
        }
        if paths.len() > 512 {
            return Err(SearchError::Content(
                "one content request may contain at most 512 paths".to_string(),
            ));
        }
        let started = Instant::now();
        let mut records = Vec::with_capacity(paths.len());
        let mut deletes = Vec::new();
        let mut report = ContentIndexReport::empty();
        for raw_path in paths {
            if cancellation.load(Ordering::Acquire) {
                report.cancelled = report.cancelled.saturating_add(1);
                continue;
            }
            let requested = Path::new(raw_path);
            let absolute = std::path::absolute(requested)
                .map_err(|error| crate::error::io_error(requested, error))?;
            root_for_content_path(&absolute, &roots).ok_or_else(|| {
                SearchError::Content(format!(
                    "content source is outside every enabled Search root: {}",
                    requested.display()
                ))
            })?;
            let metadata = match std::fs::symlink_metadata(&absolute) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    deletes.push(normalize_path(&absolute));
                    report.deleted = report.deleted.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(crate::error::io_error(&absolute, error)),
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                report.excluded = report.excluded.saturating_add(1);
                continue;
            }
            let canonical = crate::model::canonical_or_original(&absolute);
            let root = root_for_content_path(&canonical, &roots).ok_or_else(|| {
                SearchError::Content(format!(
                    "content source is outside every enabled Search root: {}",
                    requested.display()
                ))
            })?;
            if path_is_excluded(root, &canonical, false)?
                || content_path_is_excluded(root, &canonical, &self.config)?
            {
                deletes.push(normalize_path(&canonical));
                report.excluded = report.excluded.saturating_add(1);
                continue;
            }
            let record = crate::platform::file_record(&canonical, root.id, self.device_id)?;
            if (!self.config.include_hidden && record.hidden)
                || (!self.config.include_system && record.system)
            {
                deletes.push(record.normalized_path.clone());
                report.excluded = report.excluded.saturating_add(1);
                continue;
            }
            records.push(record);
        }
        if !deletes.is_empty() {
            content.delete_normalized_paths(&deletes)?;
        }
        let indexed = content.index_records(records, cancellation)?;
        report.merge(indexed);
        report.requested = paths.len() as u64;
        report.indexed_documents = content.document_count();
        report.elapsed_millis = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        Ok(report)
    }

    fn index_all_content(
        &self,
        content: &Arc<ContentService>,
        roots: &[SourceRoot],
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<ContentIndexReport> {
        let started = Instant::now();
        let mut report = ContentIndexReport::empty();
        let options = ScanOptions::from_config(&self.config);
        for root in roots {
            if cancellation.load(Ordering::Acquire) {
                report.cancelled = report.cancelled.saturating_add(1);
                break;
            }
            let content_exclusions = build_content_exclusions(root, &self.config)?;
            let mut seen_paths = HashSet::new();
            let scan = scan_root(
                root,
                self.device_id,
                &options,
                Arc::clone(&cancellation),
                |batch| {
                    let mut selected = Vec::new();
                    for record in batch {
                        if content.tracks_record(&record)
                            && !content_exclusions
                                .matched(Path::new(&record.canonical_path), false)
                                .is_ignore()
                        {
                            seen_paths.insert(record.normalized_path.clone());
                            selected.push(record);
                        }
                    }
                    report.merge(content.index_records(selected, Arc::clone(&cancellation))?);
                    Ok(())
                },
            )?;
            if scan.cancelled || cancellation.load(Ordering::Acquire) {
                report.cancelled = report.cancelled.saturating_add(1);
                break;
            }
            if scan.metadata_errors > 0 {
                return Err(SearchError::Content(format!(
                    "content scan for root {} encountered {} metadata errors; stale records were retained",
                    root.id, scan.metadata_errors
                )));
            }
            let reconciled = content.reconcile_root_paths(root.id, &seen_paths)?;
            if reconciled.deleted > 0 {
                tracing::info!(
                    root_id = %root.id,
                    deleted = reconciled.deleted,
                    "stale content records pruned"
                );
            }
            report.merge(reconciled);
        }
        report.indexed_documents = content.document_count();
        report.elapsed_millis = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        Ok(report)
    }

    pub fn status(
        &self,
        indexing: bool,
        content_indexing: bool,
        content_pending: usize,
        watcher_roots: usize,
        local_api_address: Option<String>,
    ) -> SearchResult<AgentStatus> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?;
        let state = catalog.index_state()?;
        Ok(AgentStatus {
            protocol: crate::protocol::SEARCH_PROTOCOL_VERSION,
            started_at: self.started_at,
            index_generation: state.generation,
            indexed_documents: self.filename_reader.document_count(),
            roots: catalog.roots(false)?.len(),
            watcher_roots,
            indexing,
            content_enabled: self.config.content.enabled,
            content_indexing,
            content_pending,
            content_documents: self
                .content
                .as_ref()
                .map_or(0, |content| content.document_count()),
            browser_enabled: crate::browser::any_enabled(&self.config.browsers),
            browser_refreshing: false,
            browser_documents: self
                .filename_reader
                .kind_document_count(ItemKind::Browser)?,
            local_api_address,
        })
    }

    pub fn doctor(&self, endpoint_owner_only: bool) -> SearchResult<DoctorReport> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| SearchError::State("search catalog lock was poisoned".to_string()))?;
        let doctor = catalog.doctor()?;
        let state = catalog.index_state()?;
        let filename_documents = self.filename_reader.verify()?;
        let filename_index_healthy = filename_documents == state.indexed_documents;
        let content_index_healthy = if self.config.content.enabled {
            self.content
                .as_ref()
                .is_some_and(|content| content.verify().is_ok())
        } else {
            true
        };
        Ok(DoctorReport {
            healthy: doctor.healthy
                && filename_index_healthy
                && content_index_healthy
                && endpoint_owner_only
                && !state.pending_reconciliation,
            schema_version: u16::try_from(doctor.schema_version).unwrap_or(u16::MAX),
            sqlite_quick_check: doctor.quick_check,
            filename_index_healthy,
            content_index_healthy,
            endpoint_owner_only,
            pending_reconciliation: state.pending_reconciliation,
            config_path: self.config_path.to_string_lossy().to_string(),
            database_path: catalog.database_path().to_string_lossy().to_string(),
            index_path: self.index_path.to_string_lossy().to_string(),
            content_index_path: self
                .content
                .as_ref()
                .map(|content| content.path().to_string_lossy().to_string()),
            last_error_code: state.last_error_code,
        })
    }
}

struct SearchBackends<'a> {
    config: &'a SearchConfig,
    catalog: &'a SearchCatalog,
    filename: &'a FilenameSearchReader,
    content: Option<ContentSearchReader>,
}

fn search_with(
    backends: SearchBackends<'_>,
    raw_query: &str,
    request_generation: u64,
    requested_limit: Option<u16>,
    current_folder: Option<&Path>,
    allowed_root_ids: Option<&std::collections::BTreeSet<Uuid>>,
) -> SearchResult<SearchResponse> {
    let started = Instant::now();
    let query = ParsedQuery::parse(raw_query)?;
    if query.current_only && current_folder.is_none() {
        return Err(SearchError::Query(
            "current: requires a current folder context".to_string(),
        ));
    }
    let limit = usize::from(
        requested_limit
            .unwrap_or(backends.config.max_results)
            .clamp(1, backends.config.max_results),
    );
    let candidate_limit = limit
        .saturating_mul(usize::from(backends.config.candidate_multiplier))
        .clamp(limit, 10_000);
    let normalized_current = current_folder.map(normalize_path);
    let ranking_context = RankingContext {
        current_folder: normalized_current.clone(),
        open_folders: Vec::new(),
    };
    let (hits, total_candidates) = match query.mode {
        SearchMode::Filename | SearchMode::Browser => {
            let candidates =
                backends
                    .filename
                    .search_in_roots(&query, candidate_limit, allowed_root_ids)?;
            let keys = candidates
                .records
                .iter()
                .map(|record| record.stable_key.clone())
                .collect::<Vec<_>>();
            let mut overlays = backends.catalog.overlays(&keys)?;
            let ranked_input = candidates
                .records
                .into_iter()
                .filter_map(|record| {
                    let overlay = overlays.remove(&record.stable_key).unwrap_or_default();
                    result_allowed(
                        &record,
                        &overlay,
                        &query,
                        normalized_current.as_deref(),
                        allowed_root_ids,
                    )
                    .then_some((record, overlay))
                })
                .collect::<Vec<_>>();
            (
                rank_candidates(&query, ranked_input, &ranking_context, limit),
                candidates.total_candidates,
            )
        }
        SearchMode::Content => {
            let content_reader = backends.content.as_ref().ok_or_else(|| {
                SearchError::Content(
                    "content search is disabled in the current configuration".to_string(),
                )
            })?;
            let candidates =
                content_reader.search_in_roots(&query, candidate_limit, allowed_root_ids)?;
            let keys = candidates
                .candidates
                .iter()
                .map(|candidate| candidate.record.stable_key.clone())
                .collect::<Vec<_>>();
            let mut overlays = backends.catalog.overlays(&keys)?;
            let ranked_input = candidates
                .candidates
                .into_iter()
                .filter_map(|candidate| {
                    let overlay = overlays
                        .remove(&candidate.record.stable_key)
                        .unwrap_or_default();
                    result_allowed(
                        &candidate.record,
                        &overlay,
                        &query,
                        normalized_current.as_deref(),
                        allowed_root_ids,
                    )
                    .then_some((
                        candidate.record,
                        overlay,
                        candidate.relevance,
                        candidate.content_match,
                    ))
                })
                .collect::<Vec<_>>();
            (
                rank_content_candidates(&query, ranked_input, &ranking_context, limit),
                candidates.total_candidates,
            )
        }
        SearchMode::Shelf => return Err(SearchError::Query("saved Shelf metadata uses the authenticated shelf: agent route or spiffy-searchctl shelf search".into())),
        _ => (Vec::new(), 0),
    };
    let mut category_counts = BTreeMap::new();
    for hit in &hits {
        *category_counts
            .entry(category_name(hit.record.category).to_string())
            .or_insert(0) += 1;
    }
    Ok(SearchResponse {
        generation: request_generation,
        index_generation: backends.catalog.index_state()?.generation,
        elapsed_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        total_candidates,
        category_counts,
        hits,
    })
}

fn result_allowed(
    record: &crate::model::FileRecord,
    overlay: &ItemOverlay,
    query: &ParsedQuery,
    normalized_current: Option<&str>,
    allowed_root_ids: Option<&std::collections::BTreeSet<Uuid>>,
) -> bool {
    if allowed_root_ids.is_some_and(|root_ids| !root_ids.contains(&record.root_id)) {
        return false;
    }
    if query.favorite_only && !overlay.favorite {
        return false;
    }
    !query.current_only
        || normalized_current
            .is_some_and(|folder| normalized_path_is_within(&record.normalized_path, folder))
}

fn category_name(category: crate::model::FileCategory) -> &'static str {
    match category {
        crate::model::FileCategory::Document => "document",
        crate::model::FileCategory::Image => "image",
        crate::model::FileCategory::Video => "video",
        crate::model::FileCategory::Audio => "audio",
        crate::model::FileCategory::Archive => "archive",
        crate::model::FileCategory::Code => "code",
        crate::model::FileCategory::Other => "other",
    }
}

fn path_is_within_root(path: &Path, root: &SourceRoot) -> bool {
    let path = normalize_path(path);
    normalized_path_is_within(&path, &root.normalized_path)
}

fn normalized_path_is_within(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| parent.ends_with('/') || suffix.starts_with('/'))
}

fn root_for_content_path<'a>(path: &Path, roots: &'a [SourceRoot]) -> Option<&'a SourceRoot> {
    roots
        .iter()
        .filter(|root| path_is_within_root(path, root))
        .max_by_key(|root| root.normalized_path.len())
}

fn content_path_is_excluded(
    root: &SourceRoot,
    path: &Path,
    config: &SearchConfig,
) -> SearchResult<bool> {
    Ok(build_content_exclusions(root, config)?
        .matched(path, false)
        .is_ignore())
}

fn build_content_exclusions(
    root: &SourceRoot,
    config: &SearchConfig,
) -> SearchResult<ignore::overrides::Override> {
    if config.content.exclusions.is_empty() {
        return Ok(ignore::overrides::Override::empty());
    }
    let mut builder = ignore::overrides::OverrideBuilder::new(&root.canonical_path);
    #[cfg(target_os = "windows")]
    builder.case_insensitive(true).map_err(|error| {
        SearchError::Config(format!(
            "could not configure content exclusion case handling: {error}"
        ))
    })?;
    for exclusion in &config.content.exclusions {
        builder.add(&format!("!{exclusion}")).map_err(|error| {
            SearchError::Config(format!("invalid content exclusion '{exclusion}': {error}"))
        })?;
    }
    builder
        .build()
        .map_err(|error| SearchError::Config(format!("invalid content exclusions: {error}")))
}

fn path_is_excluded(root: &SourceRoot, path: &Path, is_directory: bool) -> SearchResult<bool> {
    if root.exclusions.is_empty() {
        return Ok(false);
    }
    let mut builder = ignore::overrides::OverrideBuilder::new(&root.canonical_path);
    #[cfg(target_os = "windows")]
    builder.case_insensitive(true).map_err(|error| {
        SearchError::Config(format!("could not configure watcher exclusions: {error}"))
    })?;
    for exclusion in &root.exclusions {
        builder.add(&format!("!{exclusion}")).map_err(|error| {
            SearchError::Config(format!("invalid root exclusion '{exclusion}': {error}"))
        })?;
    }
    Ok(builder
        .build()
        .map_err(|error| SearchError::Config(format!("invalid root exclusions: {error}")))?
        .matched(path, is_directory)
        .is_ignore())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn startup_marks_interrupted_operations_failed_and_cleans_owned_staging() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("Runtime");
        let config = SearchConfig::default();
        let engine = SearchEngine::open_for_test(&runtime_dir, config.clone()).unwrap();
        drop(engine);

        let destination = temp.path().join("Destination");
        fs::create_dir(&destination).unwrap();
        let operation_id = Uuid::new_v4();
        let stage = destination.join(format!(".spiffy-search-{operation_id}-0.partial"));
        fs::write(&stage, b"interrupted bytes").unwrap();
        let mut permissions = fs::metadata(&stage).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&stage, permissions).unwrap();
        let mut catalog = SearchCatalog::open(runtime_dir.join("search.db")).unwrap();
        catalog
            .write_operation_receipt(&FileOperationReceipt {
                operation_id,
                request_fingerprint: "c".repeat(64),
                kind: crate::protocol::FileOperationKind::Copy,
                sources: vec![temp.path().join("Source.txt").to_string_lossy().to_string()],
                destination: Some(destination.to_string_lossy().to_string()),
                state: crate::protocol::FileOperationState::Running,
                undo_actions: Vec::new(),
                progress: crate::protocol::FileOperationProgress {
                    phase: "running".to_string(),
                    total_items: 1,
                    ..crate::protocol::FileOperationProgress::default()
                },
                started_at: Utc::now(),
                completed_at: None,
                error_code: None,
                message: None,
            })
            .unwrap();
        drop(catalog);

        let reopened = SearchEngine::open_for_test(&runtime_dir, config).unwrap();
        let receipt = reopened
            .search_runtime()
            .unwrap()
            .operation_receipt(operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, crate::protocol::FileOperationState::Failed);
        assert_eq!(receipt.error_code.as_deref(), Some("agent_restarted"));
        assert_eq!(receipt.progress.phase, "failed");
        assert!(!stage.exists());
    }

    #[test]
    fn engine_indexes_searches_ranks_and_removes_a_real_root() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("Hero Opening.mov"), vec![1_u8; 512]).unwrap();
        fs::write(root_path.join("Production Notes.txt"), b"notes").unwrap();
        let config = SearchConfig {
            index_batch_size: 32,
            scan_workers: 2,
            ..SearchConfig::default()
        };
        let mut engine = SearchEngine::open_for_test(temp.path(), config).unwrap();
        let root = engine.add_root(&root_path, false, Vec::new()).unwrap();
        let report = engine
            .index_root(root.id, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.scan.files, 2);
        let result = engine.search("hero ext:mov", 7, Some(20), None).unwrap();
        assert_eq!(result.generation, 7);
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0].record;
        engine
            .set_favorite(&hit.stable_key, &hit.filename, &hit.display_path, true)
            .unwrap();
        assert_eq!(
            engine
                .search("favorite: hero", 8, Some(20), None)
                .unwrap()
                .hits
                .len(),
            1
        );
        assert!(engine.remove_root(root.id).unwrap());
        assert!(engine
            .search("", 9, Some(20), None)
            .unwrap()
            .hits
            .is_empty());
        assert!(engine.doctor(true).unwrap().healthy);
    }

    #[test]
    fn current_filter_requires_and_honors_folder_context() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        let nested = root_path.join("Current");
        let sibling = root_path.join("CurrentOther");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        fs::write(nested.join("Clip.mov"), b"clip").unwrap();
        fs::write(sibling.join("Clip Other.mov"), b"clip").unwrap();
        let mut engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let root = engine.add_root(&root_path, false, Vec::new()).unwrap();
        engine
            .index_root(root.id, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert!(engine.search("current: clip", 1, None, None).is_err());
        assert_eq!(
            engine
                .search("current: clip", 2, None, Some(&nested))
                .unwrap()
                .hits
                .len(),
            1
        );
    }

    #[test]
    fn full_content_scan_prunes_stale_records_only_after_success() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        let excluded_path = root_path.join("Excluded");
        fs::create_dir_all(&excluded_path).unwrap();
        let retained = root_path.join("Retained.txt");
        let stale = root_path.join("Stale.txt");
        fs::write(&retained, b"retained full content phrase").unwrap();
        fs::write(&stale, b"stale full content phrase").unwrap();
        fs::write(
            excluded_path.join("Secret.txt"),
            b"excluded full content phrase",
        )
        .unwrap();
        let mut config = SearchConfig::default();
        config.content.enabled = true;
        config.content.extensions = vec!["txt".to_string()];
        config.content.exclusions = vec!["Excluded".to_string(), "Excluded/**".to_string()];
        let mut engine = SearchEngine::open_for_test(temp.path(), config).unwrap();
        engine.add_root(&root_path, false, Vec::new()).unwrap();
        let runtime = engine.search_runtime().unwrap();

        let initial = runtime
            .index_content(&[], Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(initial.indexed, 2);
        assert_eq!(runtime.content_document_count(), 2);
        assert_eq!(
            runtime
                .search("content: retained", 1, None, None)
                .unwrap()
                .hits
                .len(),
            1
        );
        assert!(runtime
            .search("content: excluded", 2, None, None)
            .unwrap()
            .hits
            .is_empty());

        fs::remove_file(&stale).unwrap();
        let cancelled = runtime
            .index_content(&[], Arc::new(AtomicBool::new(true)))
            .unwrap();
        assert_eq!(cancelled.cancelled, 1);
        assert_eq!(runtime.content_document_count(), 2);

        let reconciled = runtime
            .index_content(&[], Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(reconciled.deleted, 1);
        assert_eq!(runtime.content_document_count(), 1);
        assert!(runtime
            .search("content: stale", 3, None, None)
            .unwrap()
            .hits
            .is_empty());

        let outside = temp.path().join("Outside").join("Missing.txt");
        let error = runtime
            .index_content(
                &[outside.to_string_lossy().to_string()],
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("outside every enabled Search root"));
    }

    #[test]
    fn watcher_batches_update_incrementally_and_overflow_requests_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        fs::create_dir(&root_path).unwrap();
        let mut engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let root = engine.add_root(&root_path, false, Vec::new()).unwrap();
        engine
            .index_root(root.id, Arc::new(AtomicBool::new(false)))
            .unwrap();

        let created = root_path.join("Watcher Clip.mov");
        fs::write(&created, b"clip").unwrap();
        let report = engine
            .apply_watch_batch(&WatchBatch {
                changes: vec![crate::watcher::WatchChange {
                    root_id: Some(root.id),
                    path: created.clone(),
                    kind: WatchChangeKind::Upsert,
                    recursive: false,
                }],
                ..WatchBatch::default()
            })
            .unwrap();
        assert_eq!(report.upserts, 1);
        assert_eq!(
            engine.search("watcher", 1, None, None).unwrap().hits.len(),
            1
        );

        fs::remove_file(&created).unwrap();
        engine
            .apply_watch_batch(&WatchBatch {
                changes: vec![crate::watcher::WatchChange {
                    root_id: Some(root.id),
                    path: created,
                    kind: WatchChangeKind::Delete,
                    recursive: false,
                }],
                overflowed: true,
                dropped_events: 1,
                backend_errors: 0,
            })
            .unwrap();
        assert!(engine
            .search("watcher", 2, None, None)
            .unwrap()
            .hits
            .is_empty());
        assert!(engine.doctor(true).unwrap().pending_reconciliation);
        engine
            .index_root(root.id, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert!(engine.doctor(true).unwrap().healthy);
    }

    #[test]
    fn browser_snapshots_are_mode_isolated_searchable_by_url_and_clearable() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("Local Hero Clip.mov"), b"local clip").unwrap();
        let mut engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let root = engine.add_root(&root_path, false, Vec::new()).unwrap();
        engine
            .index_root(root.id, Arc::new(AtomicBool::new(false)))
            .unwrap();

        let seed = temp.path().join("Browser Seed.txt");
        fs::write(&seed, b"seed").unwrap();
        let provider = crate::browser::BrowserProvider::Chrome;
        let mut browser_record =
            crate::platform::file_record(&seed, provider.root_id(), engine.device_id()).unwrap();
        browser_record.stable_key = format!("browser:chrome:{}", "a".repeat(64));
        browser_record.stable_file_id = None;
        browser_record.root_id = provider.root_id();
        browser_record.canonical_path = "https://example.com/projects/hero?take=2".to_string();
        browser_record.display_path = browser_record.canonical_path.clone();
        browser_record.normalized_path = browser_record.canonical_path.clone();
        browser_record.filename = "Browser Hero Reference".to_string();
        browser_record.filename_stem = browser_record.filename.clone();
        browser_record.extension.clear();
        browser_record.parent_path = "example.com".to_string();
        browser_record.parent_tokens = "example.com projects hero".to_string();
        browser_record.item_kind = ItemKind::Browser;
        browser_record.category = crate::model::FileCategory::Other;
        browser_record.content_type = "browser_history".to_string();
        browser_record.mime_type = "text/html".to_string();
        browser_record.size = 0;
        browser_record.application = false;
        browser_record.folder = false;
        browser_record.file = false;
        browser_record.source_provider = "browser:chrome".to_string();
        browser_record.content_index_state = "not_applicable".to_string();
        browser_record.preview_state = "url".to_string();

        let report = engine
            .apply_browser_collection(BrowserCollection {
                started_at: Utc::now(),
                snapshots: vec![crate::browser::BrowserSnapshot {
                    provider,
                    records: vec![browser_record],
                }],
                reports: vec![crate::browser::BrowserProviderReport {
                    provider,
                    enabled: true,
                    succeeded: true,
                    discovered_profiles: 1,
                    read_profiles: 1,
                    source_entries: 1,
                    indexed_records: 1,
                    error_code: None,
                    message: None,
                }],
            })
            .unwrap();
        assert_eq!(report.indexed_browser_records, 1);

        let by_title = engine.search("browser:hero", 1, None, None).unwrap();
        assert_eq!(by_title.hits.len(), 1);
        assert_eq!(by_title.hits[0].record.item_kind, ItemKind::Browser);
        let by_url = engine.search("browser:projects", 2, None, None).unwrap();
        assert_eq!(by_url.hits.len(), 1);
        assert!(by_url.hits[0]
            .diagnostics
            .signals
            .contains_key("browser_path"));
        assert!(engine
            .search("Browser Hero Reference", 3, None, None)
            .unwrap()
            .hits
            .is_empty());
        assert_eq!(
            engine
                .search("local hero", 4, None, None)
                .unwrap()
                .hits
                .len(),
            1
        );

        let clear = engine.clear_browser_history().unwrap();
        assert_eq!(clear.removed_records, 1);
        assert!(engine
            .search("browser:hero", 5, None, None)
            .unwrap()
            .hits
            .is_empty());
        assert_eq!(
            engine
                .search("local hero", 6, None, None)
                .unwrap()
                .hits
                .len(),
            1
        );
    }

    #[test]
    fn configured_workspace_catalog_projects_searchable_application_hits() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("Spiffy Workspace");
        fs::create_dir(&workspace).unwrap();
        let video_launcher = workspace.join("Launch Spiffy Workspace.command");
        let clipboard_launcher = workspace.join("Launch Spiffy Photo Editor.command");
        fs::write(&video_launcher, b"#!/bin/zsh\n").unwrap();
        fs::write(&clipboard_launcher, b"#!/bin/zsh\n").unwrap();
        let catalog_path = temp.path().join("workspace_catalog.json");
        let catalog = serde_json::json!({
            "schema": "ss_scripts_workspace_catalog_v1",
            "version": 1,
            "systems": [{
                "id": "spiffy_workspace",
                "label": "Spiffy Workspace",
                "platforms": ["windows", "macos"],
                "launch_targets": [
                    {
                        "id": "spiffy_video_editor",
                        "label": "Spiffy Video Editor",
                        "aliases": ["Spiffy Workspace", "Video Editor"],
                        "platform_paths": {
                            "windows": "Spiffy Workspace/Launch Spiffy Workspace.command",
                            "macos": "Spiffy Workspace/Launch Spiffy Workspace.command"
                        }
                    },
                    {
                        "id": "spiffy_visual_clipboard",
                        "label": "Spiffy Clipboard",
                        "aliases": ["Visual Clipboard", "Spiffy Photo Editor"],
                        "platform_paths": {
                            "windows": "Spiffy Workspace/Launch Spiffy Photo Editor.command",
                            "macos": "Spiffy Workspace/Launch Spiffy Photo Editor.command"
                        }
                    }
                ]
            }],
            "relations": []
        });
        fs::write(&catalog_path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        let config = SearchConfig {
            workspace_catalog_path: Some(catalog_path.canonicalize().unwrap()),
            ..SearchConfig::default()
        };
        let engine = SearchEngine::open_for_test(temp.path(), config).unwrap();

        let video = engine
            .search("app: Spiffy Video Editor", 1, Some(10), None)
            .unwrap();
        assert_eq!(video.hits.len(), 1);
        assert_eq!(video.hits[0].record.item_kind, ItemKind::Application);
        assert_eq!(video.hits[0].record.filename, "Spiffy Video Editor");
        assert_eq!(
            Path::new(&video.hits[0].record.canonical_path),
            video_launcher.canonicalize().unwrap()
        );

        let clipboard = engine
            .search("Spiffy Clipboard", 2, Some(10), None)
            .unwrap();
        assert_eq!(clipboard.hits.len(), 1);
        assert_eq!(clipboard.hits[0].record.filename, "Spiffy Clipboard");
        assert_eq!(
            clipboard.hits[0].record.source_provider,
            "workspace_catalog:spiffy_workspace"
        );
    }
}
