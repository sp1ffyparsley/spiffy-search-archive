use crate::engine::{SearchEngine, SearchRuntime};
use crate::error::{io_error, SearchError, SearchResult};
use crate::file_ops::FileOperationManager;
use crate::ipc::IpcServer;
use crate::logging::{prune_owned_daily_logs, search_env_filter, MAX_RETAINED_DAILY_LOGS};
use crate::protocol::{
    AgentCommand, AgentReply, BrowserHistoryStatus, FilterSuggestionsResponse, OverlayResponse,
    ParsedQueryResponse, SearchIpcCommand,
};
use crate::query::{filter_suggestions, ParsedQuery};
use crate::remote::RemoteSearchBroker;
use crate::watcher::WatchCoordinator;
use serde_json::json;
use spiffy_shared::SearchServiceCommand;
use std::collections::BTreeSet;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_CONCURRENT_CLIENTS: usize = 32;
const WATCH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const RECONCILIATION_SETTLE_TIME: Duration = Duration::from_secs(2);
const BROWSER_BUSY_RETRY_DELAY: Duration = Duration::from_secs(30);
const MAX_PENDING_CONTENT_PATHS: usize = 10_000;
const CONTENT_JOB_PATHS: usize = 512;
const CONTENT_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
];

#[derive(Default)]
struct PendingContent {
    full: bool,
    paths: BTreeSet<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ContentJobError {
    code: String,
    message: String,
    attempt: usize,
    retry_scheduled: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ContentRetryStatus {
    consecutive_failures: usize,
    retry_in_millis: Option<u64>,
    exhausted: bool,
    latest_error: Option<ContentJobError>,
}

#[derive(Default)]
struct ContentRetryState {
    consecutive_failures: usize,
    retry_not_before: Option<Instant>,
    latest_error: Option<ContentJobError>,
}

impl ContentRetryState {
    fn ready(&self, now: Instant) -> bool {
        self.retry_not_before.is_none_or(|due| now >= due)
    }

    fn begin_attempt(&mut self) {
        self.retry_not_before = None;
        if let Some(error) = &mut self.latest_error {
            error.retry_scheduled = false;
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn record_failure(&mut self, error: &SearchError, now: Instant) -> Option<Duration> {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let delay = CONTENT_RETRY_DELAYS
            .get(self.consecutive_failures.saturating_sub(1))
            .copied();
        self.retry_not_before = delay.map(|delay| now + delay);
        self.latest_error = Some(ContentJobError {
            code: error_code(error).to_string(),
            message: error.to_string(),
            attempt: self.consecutive_failures,
            retry_scheduled: delay.is_some(),
        });
        delay
    }

    fn cancel_scheduled_retry(&mut self) {
        self.retry_not_before = None;
        if let Some(error) = &mut self.latest_error {
            error.retry_scheduled = false;
        }
    }

    fn status(&self, now: Instant) -> ContentRetryStatus {
        let retry_in_millis = self.retry_not_before.map(|due| {
            due.saturating_duration_since(now)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64
        });
        ContentRetryStatus {
            consecutive_failures: self.consecutive_failures,
            retry_in_millis,
            exhausted: self.latest_error.is_some()
                && self.retry_not_before.is_none()
                && self.consecutive_failures > CONTENT_RETRY_DELAYS.len(),
            latest_error: self.latest_error.clone(),
        }
    }
}

struct AgentState {
    operation_gate: Arc<Mutex<()>>,
    engine: Arc<Mutex<SearchEngine>>,
    search: Arc<SearchRuntime>,
    file_operations: Arc<FileOperationManager>,
    watcher: Arc<Mutex<WatchCoordinator>>,
    indexing: Arc<AtomicBool>,
    index_cancellation: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    content_indexing: Arc<AtomicBool>,
    content_cancellation: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    pending_content: Arc<Mutex<PendingContent>>,
    latest_content_report: Arc<Mutex<Option<crate::content::ContentIndexReport>>>,
    content_retry: Arc<Mutex<ContentRetryState>>,
    browser_refreshing: Arc<AtomicBool>,
    browser_cancellation: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    latest_browser_report: Arc<Mutex<Option<crate::browser::BrowserRefreshReport>>>,
    latest_browser_error: Arc<Mutex<Option<String>>>,
    browser_refresh_interval: Duration,
    browser_next_due: Arc<Mutex<Instant>>,
    local_api_address: Option<String>,
    shutdown: CancellationToken,
    endpoint_owner_only: bool,
    remote_search: RemoteSearchBroker,
}

impl AgentState {
    fn handle(self: &Arc<Self>, command: AgentCommand) -> AgentReply {
        match self.handle_inner(command) {
            Ok(reply) => reply,
            Err(error) => {
                tracing::warn!(code = error_code(&error), error = %error, "agent command failed");
                AgentReply::failure(error_code(&error), error.to_string())
            }
        }
    }

    fn handle_service(self: &Arc<Self>, command: SearchServiceCommand) -> AgentReply {
        match self.handle_service_inner(command) {
            Ok(reply) => reply,
            Err(error) => {
                tracing::warn!(
                    code = error_code(&error),
                    "Search integration command failed"
                );
                AgentReply::failure(error_code(&error), error.to_string())
            }
        }
    }

    fn handle_service_inner(
        self: &Arc<Self>,
        command: SearchServiceCommand,
    ) -> SearchResult<AgentReply> {
        match command {
            SearchServiceCommand::RemoteSearch {
                requester_device_id,
                serving_device,
                query,
            } => {
                let response = self.remote_search.search(
                    &self.search,
                    requester_device_id,
                    &serving_device,
                    &query,
                )?;
                tracing::info!(
                    requester_device_id = %requester_device_id,
                    query_id = %query.query_id,
                    results = response.results.len(),
                    "Bounded remote search completed"
                );
                Ok(AgentReply::success("Remote search complete", response))
            }
            SearchServiceCommand::ResolveRemoteResult {
                requester_device_id,
                result_id,
            } => {
                let resolution =
                    self.remote_search
                        .resolve(&self.search, requester_device_id, result_id)?;
                tracing::info!(
                    requester_device_id = %requester_device_id,
                    %result_id,
                    "Remote result revalidated for explicit transfer"
                );
                Ok(AgentReply::success(
                    "Remote result resolved for local transfer",
                    resolution,
                ))
            }
        }
    }

    fn handle_inner(self: &Arc<Self>, command: AgentCommand) -> SearchResult<AgentReply> {
        match command {
            AgentCommand::Status => {
                let watcher_roots = lock(&self.watcher, "watcher")?.root_count();
                let mut status = self.search.status(
                    self.indexing.load(Ordering::Acquire),
                    self.content_indexing.load(Ordering::Acquire),
                    self.pending_content_count()?,
                    watcher_roots,
                    self.local_api_address.clone(),
                )?;
                status.browser_refreshing = self.browser_refreshing.load(Ordering::Acquire);
                Ok(AgentReply::success("Spiffy Search agent status", status))
            }
            AgentCommand::Doctor => Ok(AgentReply::success(
                "Spiffy Search diagnostics",
                self.search.doctor(self.endpoint_owner_only)?,
            )),
            AgentCommand::Search {
                query,
                generation,
                limit,
                current_folder,
            } => {
                if let Some(metadata) =
                    crate::shelf::metadata_query(&query, current_folder.as_deref())?
                {
                    return Ok(AgentReply::success(
                        "Saved Shelf metadata page",
                        crate::shelf::query(metadata, generation, limit.unwrap_or(50), None)?,
                    ));
                }
                Ok(AgentReply::success(
                    "Search complete",
                    self.search.search(
                        &query,
                        generation,
                        limit,
                        current_folder.as_deref().map(std::path::Path::new),
                    )?,
                ))
            }
            AgentCommand::ShelfSearchPage {
                query,
                generation,
                limit,
                cursor,
            } => Ok(AgentReply::success(
                "Saved Shelf metadata page",
                crate::shelf::query(query, generation, limit, cursor)?,
            )),
            AgentCommand::ParseQuery { query } => Ok(AgentReply::success(
                "Query parsed",
                ParsedQueryResponse {
                    parsed: ParsedQuery::parse(&query)?,
                },
            )),
            AgentCommand::FilterSuggestions { prefix } => Ok(AgentReply::success(
                "Filter suggestions",
                FilterSuggestionsResponse {
                    suggestions: filter_suggestions(&prefix),
                },
            )),
            AgentCommand::ListRoots => Ok(AgentReply::success(
                "Configured source roots",
                self.search.roots()?,
            )),
            AgentCommand::AddRoot {
                path,
                remote_searchable,
                exclusions,
            } => {
                let _operation = lock(&self.operation_gate, "operation gate")?;
                self.require_idle()?;
                let root = lock(&self.engine, "search engine")?.add_root(
                    std::path::Path::new(&path),
                    remote_searchable,
                    exclusions,
                )?;
                self.refresh_watcher()?;
                Ok(AgentReply::success("Source root added", root))
            }
            AgentCommand::RemoveRoot { root_id } => {
                let _operation = lock(&self.operation_gate, "operation gate")?;
                self.require_idle()?;
                let removed = lock(&self.engine, "search engine")?.remove_root(root_id)?;
                self.refresh_watcher()?;
                if removed && self.search.content_enabled() {
                    self.queue_content(Vec::new())?;
                }
                Ok(AgentReply::success(
                    if removed {
                        "Source root removed"
                    } else {
                        "Source root was not configured"
                    },
                    json!({"removed": removed, "root_id": root_id}),
                ))
            }
            AgentCommand::Reindex { root_id } => {
                if self.start_reindex(root_id) {
                    Ok(AgentReply::success(
                        "Indexing started",
                        json!({"started": true, "root_id": root_id}),
                    ))
                } else {
                    Ok(AgentReply::failure(
                        "indexing_busy",
                        "An index operation is already running",
                    ))
                }
            }
            AgentCommand::SetFavorite {
                stable_key,
                display_name,
                path,
                favorite,
            } => Ok(AgentReply::success(
                "Favorite updated",
                OverlayResponse {
                    overlay: self.search.set_favorite(
                        &stable_key,
                        &display_name,
                        &path,
                        favorite,
                    )?,
                },
            )),
            AgentCommand::SetPinned {
                stable_key,
                display_name,
                path,
                pinned,
            } => Ok(AgentReply::success(
                "Pin updated",
                OverlayResponse {
                    overlay: self
                        .search
                        .set_pinned(&stable_key, &display_name, &path, pinned)?,
                },
            )),
            AgentCommand::SetAliases {
                stable_key,
                aliases,
            } => Ok(AgentReply::success(
                "Aliases updated",
                OverlayResponse {
                    overlay: self.search.set_aliases(&stable_key, aliases)?,
                },
            )),
            AgentCommand::RecordUsage {
                stable_key,
                selected,
            } => Ok(AgentReply::success(
                "Usage recorded",
                OverlayResponse {
                    overlay: self.search.record_usage(&stable_key, selected)?,
                },
            )),
            AgentCommand::GetOverlay { stable_key } => Ok(AgentReply::success(
                "Item overlay",
                OverlayResponse {
                    overlay: self.search.overlay(&stable_key)?,
                },
            )),
            AgentCommand::ContentIndex { paths } => {
                if !self.search.content_enabled() {
                    return Ok(AgentReply::failure(
                        "content_index_disabled",
                        "Content indexing is disabled in Search configuration",
                    ));
                }
                let queued = self.queue_content(paths)?;
                let started = self.start_content_index_if_pending();
                Ok(AgentReply::success(
                    "Content indexing queued",
                    json!({"queued": queued, "started": started}),
                ))
            }
            AgentCommand::ContentStatus => {
                let report = lock(&self.latest_content_report, "content report")?.clone();
                let retry = lock(&self.content_retry, "content retry")?.status(Instant::now());
                Ok(AgentReply::success(
                    "Content indexing status",
                    json!({
                        "enabled": self.search.content_enabled(),
                        "indexing": self.content_indexing.load(Ordering::Acquire),
                        "pending": self.pending_content_count()?,
                        "documents": self.search.content_document_count(),
                        "latest_report": report,
                        "retry": retry,
                    }),
                ))
            }
            AgentCommand::GetItemMetadata { stable_key } => {
                match self.search.item_metadata(&stable_key)? {
                    Some(metadata) => Ok(AgentReply::success("Indexed item metadata", metadata)),
                    None => Ok(AgentReply::failure(
                        "item_not_found",
                        "No indexed item has that stable key",
                    )),
                }
            }
            AgentCommand::GetPreviewText {
                stable_key,
                max_chars,
            } => {
                if !self.search.preview_text_allowed() {
                    return Ok(AgentReply::failure(
                        "preview_text_disabled",
                        "Preview text access is disabled in Search configuration",
                    ));
                }
                if !self.search.content_enabled() {
                    return Ok(AgentReply::failure(
                        "content_index_disabled",
                        "Preview text requires the optional content index",
                    ));
                }
                let max_chars = crate::access::bounded_preview_chars(max_chars);
                match self.search.preview_text(&stable_key, max_chars)? {
                    Some(preview) => Ok(AgentReply::success("Indexed preview text", preview)),
                    None => Ok(AgentReply::failure(
                        "preview_not_available",
                        "No indexed preview text is available for that stable key",
                    )),
                }
            }
            AgentCommand::ListFavorites { limit } => {
                let limit = crate::access::bounded_result_limit(limit, self.search.max_results());
                Ok(AgentReply::success(
                    "Favorite items",
                    self.search.favorite_items(limit)?,
                ))
            }
            AgentCommand::RefreshBrowserHistory => {
                if !self.search.browser_history_enabled() {
                    return Ok(AgentReply::failure(
                        "browser_history_disabled",
                        "Browser history search is disabled until a browser source is explicitly enabled",
                    ));
                }
                if self.start_browser_refresh() {
                    Ok(AgentReply::success(
                        "Browser history refresh started",
                        json!({"started": true}),
                    ))
                } else {
                    Ok(AgentReply::failure(
                        "browser_history_busy",
                        "Another mutating operation is already running",
                    ))
                }
            }
            AgentCommand::BrowserHistoryStatus => Ok(AgentReply::success(
                "Browser history status",
                BrowserHistoryStatus {
                    enabled_providers: crate::browser::enabled_providers(
                        self.search.browser_config(),
                    ),
                    refreshing: self.browser_refreshing.load(Ordering::Acquire),
                    documents: self.search.browser_document_count()?,
                    latest_report: lock(&self.latest_browser_report, "browser report")?.clone(),
                    latest_error: lock(&self.latest_browser_error, "browser error")?.clone(),
                },
            )),
            AgentCommand::ClearBrowserHistory => {
                let _operation = lock(&self.operation_gate, "operation gate")?;
                self.require_idle()?;
                let report = lock(&self.engine, "search engine")?.clear_browser_history()?;
                *lock(&self.latest_browser_report, "browser report")? = None;
                *lock(&self.latest_browser_error, "browser error")? = None;
                Ok(AgentReply::success(
                    "Cached browser history metadata cleared",
                    report,
                ))
            }
            AgentCommand::FileOperation { request } => {
                if !request.confirmed {
                    return Ok(AgentReply::success(
                        "File operation preview",
                        self.file_operations.preview(&request)?,
                    ));
                }
                let _operation = lock(&self.operation_gate, "operation gate")?;
                self.require_idle()?;
                let operation_id = request.operation_id;
                tracing::info!(%operation_id, kind = ?request.kind, "file operation accepted");
                Ok(AgentReply::success(
                    "File operation started",
                    Arc::clone(&self.file_operations).start(request, Arc::clone(&self.search))?,
                ))
            }
            AgentCommand::UndoFileOperation { operation_id } => {
                let _operation = lock(&self.operation_gate, "operation gate")?;
                self.require_idle()?;
                tracing::info!(%operation_id, "file operation undo accepted");
                Ok(AgentReply::success(
                    "File operation undo started",
                    Arc::clone(&self.file_operations)
                        .start_undo(operation_id, Arc::clone(&self.search))?,
                ))
            }
            AgentCommand::FileOperationStatus { operation_id } => Ok(AgentReply::success(
                "File operation status",
                self.file_operations.status(operation_id, &self.search)?,
            )),
            AgentCommand::CancelFileOperation { operation_id } => Ok(AgentReply::success(
                "File operation cancellation requested",
                self.file_operations.cancel(operation_id, &self.search)?,
            )),
            AgentCommand::Shutdown => {
                let _operation = lock(&self.operation_gate, "operation gate")?;
                if let Some(cancellation) = lock(&self.index_cancellation, "index job")?.as_ref() {
                    cancellation.store(true, Ordering::Release);
                }
                if let Some(cancellation) =
                    lock(&self.content_cancellation, "content job")?.as_ref()
                {
                    cancellation.store(true, Ordering::Release);
                }
                self.file_operations.cancel_active();
                self.shutdown.cancel();
                Ok(AgentReply::empty_success(
                    "Spiffy Search agent is shutting down",
                ))
            }
        }
    }

    fn require_idle(&self) -> SearchResult<()> {
        if self.indexing.load(Ordering::Acquire)
            || self.content_indexing.load(Ordering::Acquire)
            || self.file_operations.is_active()
        {
            Err(SearchError::State(
                "a mutating operation cannot start while another background operation is running"
                    .to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn refresh_watcher(&self) -> SearchResult<()> {
        let roots = self.search.roots()?;
        lock(&self.watcher, "watcher")?.refresh_roots(&roots)
    }

    fn start_reindex(self: &Arc<Self>, root_id: Option<Uuid>) -> bool {
        let _operation = match lock(&self.operation_gate, "operation gate") {
            Ok(operation) => operation,
            Err(error) => {
                tracing::error!(%error, "could not coordinate filename indexing");
                return false;
            }
        };
        if self.shutdown.is_cancelled()
            || self.content_indexing.load(Ordering::Acquire)
            || self.file_operations.is_active()
        {
            return false;
        }
        if self
            .indexing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        match lock(&self.index_cancellation, "index job") {
            Ok(mut slot) => *slot = Some(Arc::clone(&cancellation)),
            Err(error) => {
                tracing::error!(%error, "could not register index cancellation");
                self.indexing.store(false, Ordering::Release);
                return false;
            }
        }
        let state = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let result =
                lock(&state.engine, "search engine").and_then(|mut engine| match root_id {
                    Some(root_id) => engine
                        .index_root(root_id, cancellation)
                        .map(|report| json!({"root": report})),
                    None => engine
                        .index_all(cancellation)
                        .map(|reports| json!({"roots": reports})),
                });
            let succeeded = result.is_ok();
            match result {
                Ok(report) => tracing::info!(report = %report, "background indexing completed"),
                Err(error) => tracing::error!(%error, "background indexing failed"),
            }
            if let Ok(mut slot) = lock(&state.index_cancellation, "index job") {
                *slot = None;
            }
            state.indexing.store(false, Ordering::Release);
            if succeeded && state.search.content_enabled() {
                if let Err(error) = state.queue_content(Vec::new()) {
                    tracing::error!(%error, "could not queue content reconciliation");
                }
            }
        });
        true
    }

    fn start_browser_refresh(self: &Arc<Self>) -> bool {
        let _operation = match lock(&self.operation_gate, "operation gate") {
            Ok(operation) => operation,
            Err(error) => {
                tracing::error!(%error, "could not coordinate browser history refresh");
                return false;
            }
        };
        if self.shutdown.is_cancelled()
            || !self.search.browser_history_enabled()
            || self.content_indexing.load(Ordering::Acquire)
            || self.file_operations.is_active()
            || self
                .indexing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            if let Ok(mut due) = lock(&self.browser_next_due, "browser refresh schedule") {
                *due = Instant::now() + BROWSER_BUSY_RETRY_DELAY;
            }
            return false;
        }
        self.browser_refreshing.store(true, Ordering::Release);
        let cancellation = Arc::new(AtomicBool::new(false));
        match lock(&self.browser_cancellation, "browser refresh") {
            Ok(mut slot) => *slot = Some(Arc::clone(&cancellation)),
            Err(error) => {
                tracing::error!(%error, "could not register browser refresh cancellation");
                self.browser_refreshing.store(false, Ordering::Release);
                self.indexing.store(false, Ordering::Release);
                return false;
            }
        }
        if let Ok(mut latest) = lock(&self.latest_browser_error, "browser error") {
            *latest = None;
        }
        if let Ok(mut due) = lock(&self.browser_next_due, "browser refresh schedule") {
            *due = Instant::now() + self.browser_refresh_interval;
        }
        let state = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let result = lock(&state.engine, "search engine")
                .and_then(|mut engine| engine.refresh_browser_history(Arc::clone(&cancellation)));
            match result {
                Ok(report) => {
                    tracing::info!(
                        providers = report
                            .providers
                            .iter()
                            .filter(|provider| provider.enabled)
                            .count(),
                        failed_providers = report
                            .providers
                            .iter()
                            .filter(|provider| provider.enabled && !provider.succeeded)
                            .count(),
                        browser_records = report.indexed_browser_records,
                        "browser history refresh completed"
                    );
                    if let Ok(mut latest) = lock(&state.latest_browser_report, "browser report") {
                        *latest = Some(report);
                    }
                }
                Err(error)
                    if cancellation.load(Ordering::Acquire) || state.shutdown.is_cancelled() =>
                {
                    tracing::info!(
                        code = error_code(&error),
                        "browser history refresh cancelled"
                    );
                }
                Err(error) => {
                    tracing::error!(code = error_code(&error), "browser history refresh failed");
                    if let Ok(mut latest) = lock(&state.latest_browser_error, "browser error") {
                        *latest = Some(error.to_string());
                    }
                }
            }
            if let Ok(mut slot) = lock(&state.browser_cancellation, "browser refresh") {
                *slot = None;
            }
            state.browser_refreshing.store(false, Ordering::Release);
            state.indexing.store(false, Ordering::Release);
        });
        true
    }

    fn browser_refresh_due(&self) -> bool {
        self.search.browser_history_enabled()
            && lock(&self.browser_next_due, "browser refresh schedule")
                .map(|due| Instant::now() >= *due)
                .unwrap_or(false)
    }

    fn queue_content(&self, paths: Vec<String>) -> SearchResult<usize> {
        let mut pending = lock(&self.pending_content, "pending content queue")?;
        let queued = if paths.is_empty() {
            pending.full = true;
            pending.paths.clear();
            1
        } else if pending.full {
            0
        } else {
            for path in paths {
                if path.is_empty() || path.len() > 32_768 {
                    return Err(SearchError::Content(
                        "content queue contains an invalid path".to_string(),
                    ));
                }
                if pending.paths.len() >= MAX_PENDING_CONTENT_PATHS
                    && !pending.paths.contains(&path)
                {
                    pending.full = true;
                    pending.paths.clear();
                    tracing::warn!(
                        limit = MAX_PENDING_CONTENT_PATHS,
                        "content queue reached its bound; scheduling full reconciliation"
                    );
                    break;
                }
                pending.paths.insert(path);
            }
            if pending.full {
                1
            } else {
                pending.paths.len()
            }
        };
        drop(pending);
        lock(&self.content_retry, "content retry")?.reset();
        Ok(queued)
    }

    fn pending_content_count(&self) -> SearchResult<usize> {
        let pending = lock(&self.pending_content, "pending content queue")?;
        Ok(if pending.full { 1 } else { pending.paths.len() })
    }

    fn restore_content_job(&self, paths: &[String], full_job: bool) -> SearchResult<()> {
        let mut pending = lock(&self.pending_content, "pending content queue")?;
        if full_job {
            pending.full = true;
            pending.paths.clear();
        } else if !pending.full {
            for path in paths {
                if pending.paths.len() >= MAX_PENDING_CONTENT_PATHS && !pending.paths.contains(path)
                {
                    pending.full = true;
                    pending.paths.clear();
                    break;
                }
                pending.paths.insert(path.clone());
            }
        }
        Ok(())
    }

    fn schedule_content_retry(&self, paths: &[String], full_job: bool, error: &SearchError) {
        let (attempt, delay) = match lock(&self.content_retry, "content retry") {
            Ok(mut retry) => {
                let delay = retry.record_failure(error, Instant::now());
                (retry.consecutive_failures, delay)
            }
            Err(lock_error) => {
                tracing::error!(
                    code = error_code(&lock_error),
                    "content retry state is unavailable"
                );
                return;
            }
        };
        if let Some(delay) = delay {
            if let Err(queue_error) = self.restore_content_job(paths, full_job) {
                if let Ok(mut retry) = lock(&self.content_retry, "content retry") {
                    retry.cancel_scheduled_retry();
                }
                tracing::error!(
                    code = error_code(&queue_error),
                    attempt,
                    "content retry could not restore its bounded work queue"
                );
                return;
            }
            tracing::error!(
                code = error_code(error),
                attempt,
                retry_ms = delay.as_millis(),
                "background content indexing failed; retry scheduled"
            );
        } else {
            tracing::error!(
                code = error_code(error),
                attempt,
                "background content indexing failed; automatic retries exhausted"
            );
        }
    }

    fn start_content_index_if_pending(self: &Arc<Self>) -> bool {
        let _operation = match lock(&self.operation_gate, "operation gate") {
            Ok(operation) => operation,
            Err(error) => {
                tracing::error!(%error, "could not coordinate content indexing");
                return false;
            }
        };
        if self.shutdown.is_cancelled()
            || !self.search.content_enabled()
            || self.indexing.load(Ordering::Acquire)
            || self.file_operations.is_active()
            || lock(&self.content_retry, "content retry")
                .map(|retry| !retry.ready(Instant::now()))
                .unwrap_or(true)
            || self
                .content_indexing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        let (paths, full_job) = match lock(&self.pending_content, "pending content queue") {
            Ok(mut pending) if pending.full => {
                pending.full = false;
                pending.paths.clear();
                (Vec::new(), true)
            }
            Ok(mut pending) => {
                let paths = pending
                    .paths
                    .iter()
                    .take(CONTENT_JOB_PATHS)
                    .cloned()
                    .collect::<Vec<_>>();
                for path in &paths {
                    pending.paths.remove(path);
                }
                (paths, false)
            }
            Err(error) => {
                tracing::error!(%error, "could not read pending content queue");
                self.content_indexing.store(false, Ordering::Release);
                return false;
            }
        };
        if paths.is_empty() && !full_job {
            self.content_indexing.store(false, Ordering::Release);
            return false;
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        match lock(&self.content_cancellation, "content job") {
            Ok(mut slot) => *slot = Some(Arc::clone(&cancellation)),
            Err(error) => {
                tracing::error!(%error, "could not register content cancellation");
                self.schedule_content_retry(&paths, full_job, &error);
                self.content_indexing.store(false, Ordering::Release);
                return false;
            }
        }
        if let Ok(mut retry) = lock(&self.content_retry, "content retry") {
            retry.begin_attempt();
        }
        let state = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let result = state
                .search
                .index_content(&paths, Arc::clone(&cancellation));
            match result {
                Ok(report) => {
                    tracing::info!(
                        requested = report.requested,
                        indexed = report.indexed,
                        cached = report.cached,
                        failed = report.failed,
                        excluded = report.excluded,
                        elapsed_ms = report.elapsed_millis,
                        "background content indexing completed"
                    );
                    if let Ok(mut latest) = lock(&state.latest_content_report, "content report") {
                        *latest = Some(report);
                    }
                    if let Ok(mut retry) = lock(&state.content_retry, "content retry") {
                        retry.reset();
                    }
                }
                Err(error)
                    if cancellation.load(Ordering::Acquire) || state.shutdown.is_cancelled() =>
                {
                    tracing::info!(
                        code = error_code(&error),
                        "background content indexing cancelled"
                    );
                }
                Err(error) => state.schedule_content_retry(&paths, full_job, &error),
            }
            if let Ok(mut slot) = lock(&state.content_cancellation, "content job") {
                *slot = None;
            }
            state.content_indexing.store(false, Ordering::Release);
        });
        true
    }

    fn poll_watcher(&self) -> SearchResult<bool> {
        if self.indexing.load(Ordering::Acquire) {
            return Ok(false);
        }
        let batch = lock(&self.watcher, "watcher")?.receive_batch(Duration::ZERO)?;
        if batch.changes.is_empty() && !batch.overflowed && batch.backend_errors == 0 {
            return Ok(false);
        }
        let report = lock(&self.engine, "search engine")?.apply_watch_batch(&batch)?;
        if self.search.content_enabled() {
            if !report.content_paths.is_empty() {
                self.queue_content(report.content_paths.clone())?;
            }
            if batch.overflowed
                || batch.backend_errors > 0
                || !report.reconciliation_roots.is_empty()
            {
                self.queue_content(Vec::new())?;
            }
        }
        tracing::debug!(
            upserts = report.upserts,
            deletes = report.deletes,
            ignored = report.ignored,
            reconcile_roots = report.reconciliation_roots.len(),
            overflowed = batch.overflowed,
            "watch batch applied"
        );
        Ok(batch.overflowed || batch.backend_errors > 0 || !report.reconciliation_roots.is_empty())
    }
}

pub async fn run() -> SearchResult<()> {
    let _log_guard = initialize_logging()?;
    install_panic_hook();
    if let Err(error) = crate::platform::set_background_priority() {
        tracing::warn!(%error, "could not lower resident agent priority");
    }
    let engine = SearchEngine::open_default()?;
    let config = engine.config().clone();
    let search = Arc::new(engine.search_runtime()?);
    let mut watcher = WatchCoordinator::from_config(&config)?;
    watcher.refresh_roots(&search.roots()?)?;
    let server = Arc::new(IpcServer::bind_default().await?);
    let local_api_server = if config.local_api.enabled {
        let server = crate::local_api::LocalApiServer::bind(
            config.local_api.clone(),
            Arc::clone(&search),
            crate::config::local_api_endpoint_path(),
        )
        .await?;
        tracing::info!(address = %server.base_url()?, "optional local API enabled");
        Some(server)
    } else {
        crate::local_api::remove_stale_endpoint(&crate::config::local_api_endpoint_path())?;
        None
    };
    let local_api_address = local_api_server
        .as_ref()
        .map(crate::local_api::LocalApiServer::base_url)
        .transpose()?;
    let state = Arc::new(AgentState {
        operation_gate: Arc::new(Mutex::new(())),
        engine: Arc::new(Mutex::new(engine)),
        search,
        file_operations: Arc::new(FileOperationManager::default()),
        watcher: Arc::new(Mutex::new(watcher)),
        indexing: Arc::new(AtomicBool::new(false)),
        index_cancellation: Arc::new(Mutex::new(None)),
        content_indexing: Arc::new(AtomicBool::new(false)),
        content_cancellation: Arc::new(Mutex::new(None)),
        pending_content: Arc::new(Mutex::new(PendingContent::default())),
        latest_content_report: Arc::new(Mutex::new(None)),
        content_retry: Arc::new(Mutex::new(ContentRetryState::default())),
        browser_refreshing: Arc::new(AtomicBool::new(false)),
        browser_cancellation: Arc::new(Mutex::new(None)),
        latest_browser_report: Arc::new(Mutex::new(None)),
        latest_browser_error: Arc::new(Mutex::new(None)),
        browser_refresh_interval: Duration::from_secs(
            u64::from(config.browsers.refresh_minutes).saturating_mul(60),
        ),
        browser_next_due: Arc::new(Mutex::new(Instant::now())),
        local_api_address,
        shutdown: CancellationToken::new(),
        endpoint_owner_only: server.endpoint_owner_only(),
        remote_search: RemoteSearchBroker::default(),
    });
    let local_api_task = local_api_server.map(|server| {
        let shutdown = state.shutdown.clone();
        tokio::spawn(async move {
            let result = server.serve(shutdown.clone()).await;
            if let Err(error) = &result {
                tracing::error!(
                    code = error_code(error),
                    "local API server stopped unexpectedly"
                );
                shutdown.cancel();
            }
            result
        })
    });
    tracing::info!(
        address = %server.address()?,
        endpoint = %crate::config::ipc_endpoint_path().display(),
        platform = crate::platform::platform_name(),
        "Spiffy Search agent started"
    );

    let initial_status = state
        .search
        .status(false, false, 0, state.search.roots()?.len(), None)?;
    let initial_doctor = state.search.doctor(state.endpoint_owner_only)?;
    if config.initial_scan_on_start
        && initial_status.roots > 0
        && (initial_status.indexed_documents == 0 || initial_doctor.pending_reconciliation)
    {
        state.start_reindex(None);
    } else if config.content.enabled {
        state.queue_content(Vec::new())?;
        state.start_content_index_if_pending();
    }

    let clients = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let mut watch_tick = tokio::time::interval(WATCH_POLL_INTERVAL);
    watch_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let periodic_duration =
        Duration::from_secs(u64::from(config.reconciliation_minutes).saturating_mul(60));
    let mut periodic_due = Instant::now() + periodic_duration;
    let mut watcher_reconciliation_due: Option<Instant> = None;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            result = &mut ctrl_c => {
                if let Err(error) = result {
                    tracing::warn!(%error, "Ctrl-C handler failed");
                }
                state.shutdown.cancel();
            }
            _ = watch_tick.tick() => {
                match state.poll_watcher() {
                    Ok(true) => watcher_reconciliation_due = Some(Instant::now() + RECONCILIATION_SETTLE_TIME),
                    Ok(false) => {}
                    Err(error) => tracing::error!(%error, "watcher polling failed"),
                }
                if watcher_reconciliation_due.is_some_and(|due| Instant::now() >= due)
                    && !state.indexing.load(Ordering::Acquire)
                    && state.start_reindex(None)
                {
                    watcher_reconciliation_due = None;
                }
                if Instant::now() >= periodic_due
                    && !state.indexing.load(Ordering::Acquire)
                    && state.start_reindex(None)
                {
                    periodic_due = Instant::now() + periodic_duration;
                }
                if state.browser_refresh_due() {
                    state.start_browser_refresh();
                }
                if !state.indexing.load(Ordering::Acquire) {
                    state.start_content_index_if_pending();
                }
            }
            accepted = server.accept() => {
                let (stream, source) = accepted?;
                if !source.ip().is_loopback() {
                    tracing::warn!(%source, "rejected non-loopback IPC source");
                    continue;
                }
                let Ok(permit) = Arc::clone(&clients).try_acquire_owned() else {
                    tracing::warn!(%source, "local IPC concurrency limit reached");
                    continue;
                };
                let connection_server = Arc::clone(&server);
                let connection_state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(connection_server, connection_state, stream).await {
                        tracing::warn!(code = error_code(&error), "local IPC connection failed");
                    }
                });
            }
        }
    }
    if let Some(cancellation) = lock(&state.index_cancellation, "index job")?.as_ref() {
        cancellation.store(true, Ordering::Release);
    }
    if let Some(cancellation) = lock(&state.content_cancellation, "content job")?.as_ref() {
        cancellation.store(true, Ordering::Release);
    }
    if let Some(cancellation) = lock(&state.browser_cancellation, "browser refresh")?.as_ref() {
        cancellation.store(true, Ordering::Release);
    }
    state.file_operations.cancel_active();
    let file_operation_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while state.file_operations.is_active() && tokio::time::Instant::now() < file_operation_deadline
    {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if state.file_operations.is_active() {
        tracing::warn!("file operation did not stop within the shutdown grace period");
    }
    let browser_deadline = tokio::time::Instant::now() + Duration::from_secs(11);
    while state.browser_refreshing.load(Ordering::Acquire)
        && tokio::time::Instant::now() < browser_deadline
    {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if state.browser_refreshing.load(Ordering::Acquire) {
        tracing::warn!("browser refresh did not stop within the shutdown grace period");
    }
    if let Some(task) = local_api_task {
        match tokio::time::timeout(Duration::from_secs(2), task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                tracing::error!(code = error_code(&error), "local API shutdown failed")
            }
            Ok(Err(error)) => tracing::error!(%error, "local API task failed"),
            Err(_) => tracing::warn!("local API did not stop within the shutdown grace period"),
        }
    }
    tracing::info!("Spiffy Search agent stopped");
    Ok(())
}

async fn handle_connection(
    server: Arc<IpcServer>,
    state: Arc<AgentState>,
    mut stream: tokio::net::TcpStream,
) -> SearchResult<()> {
    let request = server.read_authenticated(&mut stream).await?;
    let request_id = request.request_id;
    let reply = tokio::task::spawn_blocking(move || match request.command {
        SearchIpcCommand::Agent(command) => state.handle(command),
        SearchIpcCommand::Service(command) => state.handle_service(command),
    })
    .await
    .map_err(|error| SearchError::State(format!("command worker failed: {error}")))?;
    tracing::debug!(%request_id, ok = reply.ok, code = %reply.code, "agent command completed");
    server.write_reply(&mut stream, &reply).await
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> SearchResult<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| SearchError::State(format!("{name} lock was poisoned")))
}

fn error_code(error: &SearchError) -> &'static str {
    match error {
        SearchError::Config(_) => "config_error",
        SearchError::Query(_) => "query_error",
        SearchError::Index(_) | SearchError::Tantivy(_) => "index_error",
        SearchError::State(_) => "state_error",
        SearchError::Protocol(_) => "protocol_error",
        SearchError::Authentication(_) => "authentication_error",
        SearchError::Access(_) => "access_denied",
        SearchError::Content(_) => "content_error",
        SearchError::Browser(_) => "browser_history_error",
        SearchError::FileOperation(_) => "file_operation_error",
        SearchError::Io { .. } => "io_error",
        SearchError::Database(_) => "database_error",
        SearchError::Json(_) => "json_error",
    }
}

fn initialize_logging() -> SearchResult<tracing_appender::non_blocking::WorkerGuard> {
    let log_dir = spiffy_shared::product_log_dir(spiffy_shared::Product::Search);
    fs::create_dir_all(&log_dir).map_err(|error| io_error(&log_dir, error))?;
    if let Err(error) =
        prune_owned_daily_logs(&log_dir, "search-agent.log", MAX_RETAINED_DAILY_LOGS)
    {
        eprintln!("could not prune old Spiffy Search agent logs: {error}");
    }
    let appender = tracing_appender::rolling::daily(&log_dir, "search-agent.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = search_env_filter();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .map_err(|error| SearchError::State(format!("could not initialize logging: {error}")))?;
    Ok(guard)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic| {
        tracing::error!(panic = %panic, "Spiffy Search agent panicked");
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SearchConfig;
    use spiffy_shared::{
        DeviceIdentity, RemoteResultResolution, RemoteSearchQuery, RemoteSearchResponse,
    };
    use std::fs;
    use std::path::Path;

    fn test_state(engine: SearchEngine) -> Arc<AgentState> {
        let search = Arc::new(engine.search_runtime().unwrap());
        let watcher = WatchCoordinator::new(128, Duration::from_millis(100)).unwrap();
        Arc::new(AgentState {
            operation_gate: Arc::new(Mutex::new(())),
            engine: Arc::new(Mutex::new(engine)),
            search,
            file_operations: Arc::new(FileOperationManager::default()),
            watcher: Arc::new(Mutex::new(watcher)),
            indexing: Arc::new(AtomicBool::new(false)),
            index_cancellation: Arc::new(Mutex::new(None)),
            content_indexing: Arc::new(AtomicBool::new(false)),
            content_cancellation: Arc::new(Mutex::new(None)),
            pending_content: Arc::new(Mutex::new(PendingContent::default())),
            latest_content_report: Arc::new(Mutex::new(None)),
            content_retry: Arc::new(Mutex::new(ContentRetryState::default())),
            browser_refreshing: Arc::new(AtomicBool::new(false)),
            browser_cancellation: Arc::new(Mutex::new(None)),
            latest_browser_report: Arc::new(Mutex::new(None)),
            latest_browser_error: Arc::new(Mutex::new(None)),
            browser_refresh_interval: Duration::from_secs(15 * 60),
            browser_next_due: Arc::new(Mutex::new(Instant::now())),
            local_api_address: None,
            shutdown: CancellationToken::new(),
            endpoint_owner_only: true,
            remote_search: RemoteSearchBroker::default(),
        })
    }

    #[test]
    fn content_retry_backoff_is_bounded_and_resettable() {
        let mut retry = ContentRetryState::default();
        let now = Instant::now();
        let error = SearchError::Content("worker unavailable".to_string());

        for expected in CONTENT_RETRY_DELAYS {
            let delay = retry.record_failure(&error, now).unwrap();
            assert_eq!(delay, expected);
            assert!(!retry.ready(now));
            assert!(retry.ready(now + expected));
            retry.begin_attempt();
        }
        assert!(retry.record_failure(&error, now).is_none());
        let exhausted = retry.status(now);
        assert!(exhausted.exhausted);
        assert_eq!(exhausted.consecutive_failures, 4);
        assert!(!exhausted.latest_error.unwrap().retry_scheduled);

        retry.reset();
        let recovered = retry.status(now);
        assert_eq!(recovered.consecutive_failures, 0);
        assert!(recovered.latest_error.is_none());
        assert!(!recovered.exhausted);
    }

    #[test]
    fn active_content_job_blocks_root_mutation_and_filename_reindex() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        fs::create_dir(&root_path).unwrap();
        let engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let state = test_state(engine);
        state.content_indexing.store(true, Ordering::Release);

        let add = state.handle(AgentCommand::AddRoot {
            path: root_path.to_string_lossy().to_string(),
            remote_searchable: false,
            exclusions: Vec::new(),
        });

        assert!(!add.ok);
        assert_eq!(add.code, "state_error");
        assert!(state.search.roots().unwrap().is_empty());
        assert!(!state.start_reindex(None));
        state.content_indexing.store(false, Ordering::Release);
    }

    #[test]
    fn disabled_browser_history_is_idle_observable_and_clearable() {
        let temp = tempfile::tempdir().unwrap();
        let engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let state = test_state(engine);

        let status = state.handle(AgentCommand::BrowserHistoryStatus);
        assert!(status.ok, "{status:?}");
        let status: BrowserHistoryStatus = serde_json::from_value(status.data.unwrap()).unwrap();
        assert!(status.enabled_providers.is_empty());
        assert!(!status.refreshing);
        assert_eq!(status.documents, 0);
        assert!(status.latest_report.is_none());
        assert!(status.latest_error.is_none());

        let refresh = state.handle(AgentCommand::RefreshBrowserHistory);
        assert!(!refresh.ok);
        assert_eq!(refresh.code, "browser_history_disabled");
        assert!(!state.browser_refreshing.load(Ordering::Acquire));
        assert!(!state.indexing.load(Ordering::Acquire));

        let clear = state.handle(AgentCommand::ClearBrowserHistory);
        assert!(clear.ok, "{clear:?}");
        assert_eq!(clear.data.unwrap()["removed_records"], 0);
    }

    #[test]
    fn busy_browser_refresh_is_deferred_instead_of_polled_repeatedly() {
        let temp = tempfile::tempdir().unwrap();
        let config = SearchConfig {
            browsers: crate::config::BrowserConfig {
                chrome: true,
                ..crate::config::BrowserConfig::default()
            },
            ..SearchConfig::default()
        };
        let engine = SearchEngine::open_for_test(temp.path(), config).unwrap();
        let state = test_state(engine);
        state.indexing.store(true, Ordering::Release);
        *lock(&state.browser_next_due, "browser refresh schedule").unwrap() = Instant::now();

        assert!(!state.start_browser_refresh());
        assert!(
            *lock(&state.browser_next_due, "browser refresh schedule").unwrap()
                >= Instant::now() + Duration::from_secs(29)
        );
        assert!(!state.browser_refreshing.load(Ordering::Acquire));
        state.indexing.store(false, Ordering::Release);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn command_handler_runs_real_background_index_and_search() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Media");
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("Agent Hero.mov"), b"hero").unwrap();
        let engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let state = test_state(engine);
        let add = state.handle(AgentCommand::AddRoot {
            path: root_path.to_string_lossy().to_string(),
            remote_searchable: false,
            exclusions: Vec::new(),
        });
        assert!(add.ok);
        assert!(state.handle(AgentCommand::Reindex { root_id: None }).ok);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while state.indexing.load(Ordering::Acquire) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "index job timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let search = state.handle(AgentCommand::Search {
            query: "agent hero".to_string(),
            generation: 4,
            limit: Some(20),
            current_folder: None,
        });
        assert!(search.ok, "{search:?}");
        assert_eq!(search.data.unwrap()["hits"].as_array().unwrap().len(), 1);
        assert!(state.handle(AgentCommand::Shutdown).ok);
        assert!(state.shutdown.is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_search_is_root_scoped_path_safe_and_requester_bound() {
        let temp = tempfile::tempdir().unwrap();
        let shared_root = temp.path().join("Shared Media");
        let private_root = temp.path().join("Private Media");
        fs::create_dir(&shared_root).unwrap();
        fs::create_dir(&private_root).unwrap();
        let shared_file = shared_root.join("Remote Hero.mov");
        fs::write(&shared_file, b"shared hero").unwrap();
        fs::write(private_root.join("Private Hero.mov"), b"private hero").unwrap();
        let engine =
            SearchEngine::open_for_test(&temp.path().join("Runtime"), SearchConfig::default())
                .unwrap();
        let state = test_state(engine);
        let shared = state.handle(AgentCommand::AddRoot {
            path: shared_root.to_string_lossy().into_owned(),
            remote_searchable: true,
            exclusions: Vec::new(),
        });
        let shared_root_id =
            serde_json::from_value::<crate::catalog::SourceRoot>(shared.data.unwrap())
                .unwrap()
                .id;
        let private = state.handle(AgentCommand::AddRoot {
            path: private_root.to_string_lossy().into_owned(),
            remote_searchable: false,
            exclusions: Vec::new(),
        });
        let private_root_id =
            serde_json::from_value::<crate::catalog::SourceRoot>(private.data.unwrap())
                .unwrap()
                .id;
        assert!(state.handle(AgentCommand::Reindex { root_id: None }).ok);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while state.indexing.load(Ordering::Acquire) {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let requester = Uuid::new_v4();
        let serving = DeviceIdentity {
            id: Uuid::new_v4(),
            display_name: "Editing PC".to_string(),
        };
        let query = RemoteSearchQuery {
            query_id: Uuid::new_v4(),
            text: "hero".to_string(),
            permitted_root_ids: Vec::new(),
            result_limit: 25,
            include_thumbnails: true,
        };
        let reply = state.handle_service(SearchServiceCommand::RemoteSearch {
            requester_device_id: requester,
            serving_device: serving.clone(),
            query: query.clone(),
        });
        assert!(reply.ok, "{reply:?}");
        let response: RemoteSearchResponse = serde_json::from_value(reply.data.unwrap()).unwrap();
        assert_eq!(response.query_id, query.query_id);
        assert_eq!(response.results.len(), 1);
        let result = &response.results[0];
        assert_eq!(result.remote_root_id, shared_root_id);
        assert_eq!(result.device, serving);
        assert!(result.stable_file_id.is_none());
        assert_eq!(result.privacy_safe_path, "Shared Media/Remote Hero.mov");
        assert!(!result
            .privacy_safe_path
            .contains(&temp.path().to_string_lossy().to_string()));
        assert!(result.thumbnail.is_none());

        let denied = state.handle_service(SearchServiceCommand::RemoteSearch {
            requester_device_id: requester,
            serving_device: serving.clone(),
            query: RemoteSearchQuery {
                permitted_root_ids: vec![private_root_id],
                ..query.clone()
            },
        });
        assert!(!denied.ok);
        assert_eq!(denied.code, "access_denied");

        let wrong_requester = state.handle_service(SearchServiceCommand::ResolveRemoteResult {
            requester_device_id: Uuid::new_v4(),
            result_id: result.result_id,
        });
        assert!(!wrong_requester.ok);
        assert_eq!(wrong_requester.code, "access_denied");

        let resolved = state.handle_service(SearchServiceCommand::ResolveRemoteResult {
            requester_device_id: requester,
            result_id: result.result_id,
        });
        assert!(resolved.ok, "{resolved:?}");
        let resolution: RemoteResultResolution =
            serde_json::from_value(resolved.data.unwrap()).unwrap();
        assert_eq!(
            crate::model::normalize_path(Path::new(&resolution.canonical_path)),
            crate::model::normalize_path(&shared_file)
        );
        assert!(resolution.stable_file_id.is_some());

        fs::remove_file(&shared_file).unwrap();
        let stale = state.handle_service(SearchServiceCommand::ResolveRemoteResult {
            requester_device_id: requester,
            result_id: result.result_id,
        });
        assert!(!stale.ok);
        assert_eq!(stale.code, "access_denied");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn command_handler_queues_content_and_searches_the_separate_index() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Documents");
        fs::create_dir(&root_path).unwrap();
        let note = root_path.join("Agent Notes.txt");
        fs::write(&note, b"private content needle for the production worker").unwrap();
        let mut config = SearchConfig::default();
        config.content.enabled = true;
        config.content.extensions = vec!["txt".to_string()];
        config.local_api.allow_preview_text = true;
        let engine = SearchEngine::open_for_test(temp.path(), config).unwrap();
        let state = test_state(engine);
        assert!(
            state
                .handle(AgentCommand::AddRoot {
                    path: root_path.to_string_lossy().to_string(),
                    remote_searchable: false,
                    exclusions: Vec::new(),
                })
                .ok
        );
        assert!(state.handle(AgentCommand::Reindex { root_id: None }).ok);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while state.indexing.load(Ordering::Acquire) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "index job timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let queued = state.handle(AgentCommand::ContentIndex {
            paths: vec![note.to_string_lossy().to_string()],
        });
        assert!(queued.ok, "{queued:?}");
        while state.content_indexing.load(Ordering::Acquire) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "content job timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let search = state.handle(AgentCommand::Search {
            query: "content:needle".to_string(),
            generation: 5,
            limit: Some(20),
            current_folder: None,
        });
        assert!(search.ok, "{search:?}");
        let hits = search.data.unwrap()["hits"].as_array().unwrap().clone();
        assert_eq!(hits.len(), 1);
        assert!(hits[0]["content_match"]["snippet"]
            .as_str()
            .unwrap()
            .contains("content needle"));
        let stable_key = hits[0]["record"]["stable_key"]
            .as_str()
            .unwrap()
            .to_string();
        let metadata = state.handle(AgentCommand::GetItemMetadata {
            stable_key: stable_key.clone(),
        });
        assert!(metadata.ok, "{metadata:?}");
        assert_eq!(
            metadata.data.unwrap()["record"]["filename"],
            "Agent Notes.txt"
        );
        let preview = state.handle(AgentCommand::GetPreviewText {
            stable_key: stable_key.clone(),
            max_chars: Some(12),
        });
        assert!(preview.ok, "{preview:?}");
        let preview = preview.data.unwrap();
        assert_eq!(preview["text"], "private cont");
        assert_eq!(preview["truncated"], true);
        assert!(
            state
                .handle(AgentCommand::SetFavorite {
                    stable_key,
                    display_name: "Agent Notes.txt".to_string(),
                    path: note.to_string_lossy().to_string(),
                    favorite: true,
                })
                .ok
        );
        let favorites = state.handle(AgentCommand::ListFavorites { limit: Some(10) });
        assert!(favorites.ok, "{favorites:?}");
        assert_eq!(favorites.data.unwrap().as_array().unwrap().len(), 1);
        let status = state.handle(AgentCommand::ContentStatus);
        assert!(status.ok);
        assert_eq!(status.data.unwrap()["documents"], 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn command_handler_previews_executes_reports_and_undoes_file_moves() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination).unwrap();
        let source = source_dir.join("Agent Move.txt");
        fs::write(&source, b"agent file operation payload").unwrap();
        let engine =
            SearchEngine::open_for_test(&temp.path().join("Runtime"), SearchConfig::default())
                .unwrap();
        let state = test_state(engine);
        let operation_id = Uuid::new_v4();
        let mut request = crate::protocol::FileOperationRequest {
            operation_id,
            kind: crate::protocol::FileOperationKind::Move,
            sources: vec![source.to_string_lossy().to_string()],
            destination: Some(destination.to_string_lossy().to_string()),
            conflict_policy: crate::protocol::FileConflictPolicy::Fail,
            confirmation_token: None,
            confirmed: false,
        };
        let preview = state.handle(AgentCommand::FileOperation {
            request: request.clone(),
        });
        assert!(preview.ok, "{preview:?}");
        let preview_data = preview.data.unwrap();
        assert_eq!(preview_data["items"].as_array().unwrap().len(), 1);
        request.confirmation_token = Some(
            preview_data["confirmation_token"]
                .as_str()
                .unwrap()
                .to_string(),
        );

        request.confirmed = true;
        let started = state.handle(AgentCommand::FileOperation { request });
        assert!(started.ok, "{started:?}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while state.file_operations.is_active() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let status = state.handle(AgentCommand::FileOperationStatus { operation_id });
        assert!(status.ok, "{status:?}");
        let status: crate::protocol::FileOperationStatus =
            serde_json::from_value(status.data.unwrap()).unwrap();
        assert_eq!(
            status.receipt.state,
            crate::protocol::FileOperationState::Complete
        );
        assert!(!source.exists());
        assert!(destination.join("Agent Move.txt").exists());

        let undo = state.handle(AgentCommand::UndoFileOperation { operation_id });
        assert!(undo.ok, "{undo:?}");
        while state.file_operations.is_active() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let status = state.handle(AgentCommand::FileOperationStatus { operation_id });
        let status: crate::protocol::FileOperationStatus =
            serde_json::from_value(status.data.unwrap()).unwrap();
        assert_eq!(
            status.receipt.state,
            crate::protocol::FileOperationState::Undone
        );
        assert_eq!(fs::read(&source).unwrap(), b"agent file operation payload");
        assert!(!destination.join("Agent Move.txt").exists());
    }
}
