use crate::engine::SearchRuntime;
use crate::error::{io_error, SearchError, SearchResult};
use crate::model::normalize_path;
use crate::protocol::{
    FileConflictPolicy, FileOperationItemKind, FileOperationKind, FileOperationPreview,
    FileOperationPreviewItem, FileOperationProgress, FileOperationReceipt, FileOperationRequest,
    FileOperationState, FileOperationStatus, UndoAction, UndoActionKind,
};
#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use filetime::FileTime;
use spiffy_shared::StableFileIdentity;
use std::cell::Cell;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
use std::time::{Duration, Instant};
use uuid::Uuid;

const COPY_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_OPERATION_SOURCES: usize = 1024;
const MAX_DIRECTORY_ENTRIES: usize = 1_000_000;
const MAX_DIRECTORY_DEPTH: usize = 256;
const MAX_KEEP_BOTH_ATTEMPTS: usize = 10_000;
#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
const TRASH_RECEIPT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
const TRASH_RECEIPT_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
struct PlannedItem {
    source: PathBuf,
    source_identity: StableFileIdentity,
    source_modified_nanos: Option<u128>,
    destination: Option<PathBuf>,
    destination_parent_identity: Option<StableFileIdentity>,
    item_kind: FileOperationItemKind,
    size: u64,
    conflict: bool,
    conflict_resolved: bool,
    undo_supported: bool,
}

#[derive(Debug, Clone)]
struct OperationPlan {
    operation_id: Uuid,
    request_fingerprint: String,
    confirmation_token: String,
    kind: FileOperationKind,
    conflict_policy: FileConflictPolicy,
    items: Vec<PlannedItem>,
    destination: Option<String>,
}

#[derive(Debug)]
struct OperationFailure {
    code: &'static str,
    message: String,
}

type OperationResult<T> = Result<T, OperationFailure>;
type UndoJournal<'a> = dyn FnMut(&UndoAction) -> OperationResult<()> + 'a;

impl OperationFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn io(action: &str, path: &Path, error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::AlreadyExists => "destination_conflict",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::NotFound => "source_missing",
            _ => "file_io_error",
        };
        Self::new(
            code,
            format!("{action} failed for {}: {error}", path.display()),
        )
    }

    fn cancelled() -> Self {
        Self::new("operation_cancelled", "file operation was cancelled")
    }
}

#[derive(Clone)]
struct ActiveOperation {
    operation_id: Uuid,
    cancellation: Arc<AtomicBool>,
    receipt: FileOperationReceipt,
}

#[derive(Default)]
pub struct FileOperationManager {
    active: Arc<Mutex<Option<ActiveOperation>>>,
}

impl FileOperationManager {
    pub fn preview(&self, request: &FileOperationRequest) -> SearchResult<FileOperationPreview> {
        Ok(plan_operation(request)?.public_preview())
    }

    pub fn start(
        self: &Arc<Self>,
        request: FileOperationRequest,
        runtime: Arc<SearchRuntime>,
    ) -> SearchResult<FileOperationStatus> {
        if !request.confirmed {
            return Err(SearchError::FileOperation(
                "execute requires an explicitly confirmed operation".to_string(),
            ));
        }
        let request_fingerprint = request_fingerprint(&request)?;
        let mut active = lock(&self.active, "file operation manager")?;
        if let Some(existing) = active.as_ref() {
            if existing.operation_id == request.operation_id {
                ensure_receipt_matches_request(
                    &existing.receipt,
                    request.operation_id,
                    &request_fingerprint,
                )?;
                return Ok(FileOperationStatus {
                    operation_id: request.operation_id,
                    active: true,
                    receipt: existing.receipt.clone(),
                });
            }
            return Err(SearchError::FileOperation(format!(
                "file operation {} is already running",
                existing.operation_id
            )));
        }
        if let Some(receipt) = runtime.operation_receipt(request.operation_id)? {
            ensure_receipt_matches_request(&receipt, request.operation_id, &request_fingerprint)?;
            return Ok(FileOperationStatus {
                operation_id: request.operation_id,
                active: false,
                receipt,
            });
        }
        let plan = plan_operation_with_fingerprint(&request, request_fingerprint)?;
        ensure_plan_can_execute(&plan)?;
        if request.confirmation_token.as_deref() != Some(&plan.confirmation_token) {
            return Err(SearchError::FileOperation(
                "confirmation token is missing or stale; request a new preview before executing"
                    .to_string(),
            ));
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        let receipt = new_receipt(&plan, FileOperationState::Running, "running");
        runtime.write_operation_receipt(&receipt)?;
        *active = Some(ActiveOperation {
            operation_id: plan.operation_id,
            cancellation: Arc::clone(&cancellation),
            receipt: receipt.clone(),
        });
        drop(active);

        let manager = Arc::clone(self);
        let progress_manager = Arc::clone(self);
        let persist_runtime = Arc::clone(&runtime);
        let initial_receipt = receipt.clone();
        tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                execute_plan(
                    plan,
                    initial_receipt,
                    cancellation,
                    |progress| progress_manager.update_progress(progress),
                    |receipt| {
                        progress_manager.update_receipt(receipt);
                        persist_runtime.write_operation_receipt(receipt)
                    },
                )
            }))
            .unwrap_or_else(|_| {
                Err(SearchError::State(
                    "file operation worker panicked; inspect the agent log".to_string(),
                ))
            });
            manager.finish_background(result, runtime);
        });

        Ok(FileOperationStatus {
            operation_id: receipt.operation_id,
            active: true,
            receipt,
        })
    }

    pub fn start_undo(
        self: &Arc<Self>,
        operation_id: Uuid,
        runtime: Arc<SearchRuntime>,
    ) -> SearchResult<FileOperationStatus> {
        let mut active = lock(&self.active, "file operation manager")?;
        if let Some(existing) = active.as_ref() {
            if existing.operation_id == operation_id {
                return Ok(FileOperationStatus {
                    operation_id,
                    active: true,
                    receipt: existing.receipt.clone(),
                });
            }
            return Err(SearchError::FileOperation(format!(
                "file operation {} is already running",
                existing.operation_id
            )));
        }
        let mut receipt = runtime.operation_receipt(operation_id)?.ok_or_else(|| {
            SearchError::FileOperation(format!("file operation {operation_id} was not found"))
        })?;
        if receipt.state == FileOperationState::Undone {
            return Ok(FileOperationStatus {
                operation_id,
                active: false,
                receipt,
            });
        }
        if !matches!(
            receipt.state,
            FileOperationState::Complete
                | FileOperationState::Failed
                | FileOperationState::Cancelled
        ) {
            return Err(SearchError::FileOperation(format!(
                "file operation {operation_id} is not eligible for undo"
            )));
        }
        let remaining = receipt
            .undo_actions
            .iter()
            .filter(|action| !action.undone)
            .count();
        if remaining == 0 {
            return Err(SearchError::FileOperation(
                "the operation has no remaining recoverable undo actions".to_string(),
            ));
        }

        receipt.state = FileOperationState::Undoing;
        receipt.completed_at = None;
        receipt.error_code = None;
        receipt.message = None;
        receipt.progress = FileOperationProgress {
            phase: "undoing".to_string(),
            completed_items: 0,
            total_items: remaining as u64,
            completed_bytes: 0,
            total_bytes: None,
            current_path: None,
        };
        runtime.write_operation_receipt(&receipt)?;
        let cancellation = Arc::new(AtomicBool::new(false));
        *active = Some(ActiveOperation {
            operation_id,
            cancellation: Arc::clone(&cancellation),
            receipt: receipt.clone(),
        });
        drop(active);

        let manager = Arc::clone(self);
        let progress_manager = Arc::clone(self);
        let persist_runtime = Arc::clone(&runtime);
        let initial_receipt = receipt.clone();
        tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                execute_undo(
                    initial_receipt,
                    cancellation,
                    |progress| progress_manager.update_progress(progress),
                    |receipt| {
                        progress_manager.update_receipt(receipt);
                        persist_runtime.write_operation_receipt(receipt)
                    },
                )
            }))
            .unwrap_or_else(|_| {
                Err(SearchError::State(
                    "file operation undo worker panicked; inspect the agent log".to_string(),
                ))
            });
            manager.finish_background(result, runtime);
        });

        Ok(FileOperationStatus {
            operation_id,
            active: true,
            receipt,
        })
    }

    pub fn status(
        &self,
        operation_id: Uuid,
        runtime: &SearchRuntime,
    ) -> SearchResult<FileOperationStatus> {
        if let Some(status) = self.active_status(operation_id)? {
            return Ok(status);
        }
        let receipt = runtime.operation_receipt(operation_id)?.ok_or_else(|| {
            SearchError::FileOperation(format!("file operation {operation_id} was not found"))
        })?;
        Ok(FileOperationStatus {
            operation_id,
            active: false,
            receipt,
        })
    }

    pub fn cancel(
        &self,
        operation_id: Uuid,
        runtime: &SearchRuntime,
    ) -> SearchResult<FileOperationStatus> {
        let status = {
            let mut active = lock(&self.active, "file operation manager")?;
            let operation = active.as_mut().ok_or_else(|| {
                SearchError::FileOperation(format!(
                    "file operation {operation_id} is not currently running"
                ))
            })?;
            if operation.operation_id != operation_id {
                return Err(SearchError::FileOperation(format!(
                    "file operation {} is running instead",
                    operation.operation_id
                )));
            }
            operation.cancellation.store(true, Ordering::Release);
            operation.receipt.progress.phase = "cancelling".to_string();
            FileOperationStatus {
                operation_id,
                active: true,
                receipt: operation.receipt.clone(),
            }
        };
        runtime.write_operation_receipt(&status.receipt)?;
        Ok(status)
    }

    pub fn is_active(&self) -> bool {
        self.active
            .lock()
            .map(|active| active.is_some())
            .unwrap_or(true)
    }

    pub fn cancel_active(&self) {
        if let Ok(active) = self.active.lock() {
            if let Some(operation) = active.as_ref() {
                operation.cancellation.store(true, Ordering::Release);
            }
        }
    }

    fn active_status(&self, operation_id: Uuid) -> SearchResult<Option<FileOperationStatus>> {
        let active = lock(&self.active, "file operation manager")?;
        Ok(active
            .as_ref()
            .filter(|operation| operation.operation_id == operation_id)
            .map(|operation| FileOperationStatus {
                operation_id,
                active: true,
                receipt: operation.receipt.clone(),
            }))
    }

    fn update_progress(&self, progress: &FileOperationProgress) {
        if let Ok(mut active) = self.active.lock() {
            if let Some(operation) = active.as_mut() {
                operation.receipt.progress = progress.clone();
            }
        }
    }

    fn update_receipt(&self, receipt: &FileOperationReceipt) {
        if let Ok(mut active) = self.active.lock() {
            if let Some(operation) = active.as_mut() {
                if operation.operation_id == receipt.operation_id {
                    operation.receipt = receipt.clone();
                }
            }
        }
    }

    fn finish_background(
        &self,
        result: SearchResult<FileOperationReceipt>,
        runtime: Arc<SearchRuntime>,
    ) {
        let mut final_receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                let Some(mut receipt) = (match self.active.lock() {
                    Ok(active) => active.as_ref().map(|active| active.receipt.clone()),
                    Err(_) => None,
                }) else {
                    tracing::error!(%error, "file operation failed after its active state was lost");
                    return;
                };
                receipt.state = FileOperationState::Failed;
                receipt.completed_at = Some(Utc::now());
                receipt.error_code = Some("operation_state_error".to_string());
                receipt.message = Some(error.to_string());
                receipt
            }
        };
        if final_receipt.progress.phase.is_empty() {
            final_receipt.progress.phase = state_phase(final_receipt.state).to_string();
        }
        if let Err(error) = runtime.write_operation_receipt(&final_receipt) {
            tracing::error!(
                operation_id = %final_receipt.operation_id,
                %error,
                "could not persist final file operation receipt"
            );
        }
        if let Ok(mut active) = self.active.lock() {
            if active
                .as_ref()
                .is_some_and(|operation| operation.operation_id == final_receipt.operation_id)
            {
                *active = None;
            }
        }
        tracing::info!(
            operation_id = %final_receipt.operation_id,
            state = state_phase(final_receipt.state),
            completed_items = final_receipt.progress.completed_items,
            "file operation finished"
        );
    }
}

fn plan_operation(request: &FileOperationRequest) -> SearchResult<OperationPlan> {
    let fingerprint = request_fingerprint(request)?;
    plan_operation_with_fingerprint(request, fingerprint)
}

fn plan_operation_with_fingerprint(
    request: &FileOperationRequest,
    request_fingerprint: String,
) -> SearchResult<OperationPlan> {
    validate_request_shape(request)?;
    let mut sources = Vec::with_capacity(request.sources.len());
    let mut normalized_sources = HashSet::new();
    for raw_source in &request.sources {
        let source = canonical_source(Path::new(raw_source))?;
        let normalized = normalize_path(&source);
        if !normalized_sources.insert(normalized) {
            return Err(SearchError::FileOperation(
                "file operation contains duplicate source paths".to_string(),
            ));
        }
        let metadata = fs::symlink_metadata(&source).map_err(|error| io_error(&source, error))?;
        sources.push((source, metadata));
    }
    reject_nested_sources(&sources)?;

    match request.kind {
        FileOperationKind::Rename if sources.len() != 1 => {
            return Err(SearchError::FileOperation(
                "rename requires exactly one source".to_string(),
            ));
        }
        FileOperationKind::Trash if request.destination.is_some() => {
            return Err(SearchError::FileOperation(
                "trash does not accept a destination".to_string(),
            ));
        }
        FileOperationKind::Copy | FileOperationKind::Move | FileOperationKind::Rename
            if request.destination.is_none() =>
        {
            return Err(SearchError::FileOperation(
                "copy, move, and rename require a destination".to_string(),
            ));
        }
        _ => {}
    }

    let destination_directory = if matches!(
        request.kind,
        FileOperationKind::Copy | FileOperationKind::Move
    ) {
        Some(canonical_destination_directory(Path::new(
            request
                .destination
                .as_deref()
                .expect("validated destination"),
        ))?)
    } else {
        None
    };
    let mut reserved_targets = HashSet::new();
    let mut items = Vec::with_capacity(sources.len());
    for (source, metadata) in sources {
        let source_identity =
            StableFileIdentity::from_path(&source).map_err(|error| io_error(&source, error))?;
        let source_modified_nanos = metadata_modified_nanos(&metadata);
        let item_kind = if metadata.is_file() {
            FileOperationItemKind::File
        } else if metadata.is_dir() {
            FileOperationItemKind::Directory
        } else {
            return Err(SearchError::FileOperation(format!(
                "file operation source is not a normal file or directory: {}",
                source.display()
            )));
        };
        let proposed = match request.kind {
            FileOperationKind::Copy | FileOperationKind::Move => {
                let directory = destination_directory
                    .as_ref()
                    .expect("validated destination directory");
                Some(directory.join(source.file_name().ok_or_else(|| {
                    SearchError::FileOperation(format!(
                        "source has no movable name: {}",
                        source.display()
                    ))
                })?))
            }
            FileOperationKind::Rename => Some(rename_destination(
                &source,
                request
                    .destination
                    .as_deref()
                    .expect("validated destination"),
            )?),
            FileOperationKind::Trash => None,
        };
        let (destination, conflict, conflict_resolved) = match proposed {
            Some(proposed) => {
                if normalize_path(&proposed) == normalize_path(&source) {
                    return Err(SearchError::FileOperation(
                        "file operation destination resolves to the source path".to_string(),
                    ));
                }
                if item_kind == FileOperationItemKind::Directory
                    && normalized_is_within(&normalize_path(&proposed), &normalize_path(&source))
                {
                    return Err(SearchError::FileOperation(format!(
                        "a directory cannot be copied or moved inside itself: {}",
                        source.display()
                    )));
                }
                let occupied =
                    proposed.exists() || reserved_targets.contains(&normalize_path(&proposed));
                if occupied && request.conflict_policy == FileConflictPolicy::KeepBoth {
                    let available = keep_both_path(&proposed, item_kind, &reserved_targets)?;
                    reserved_targets.insert(normalize_path(&available));
                    (Some(available), true, true)
                } else {
                    reserved_targets.insert(normalize_path(&proposed));
                    (Some(proposed), occupied, false)
                }
            }
            None => (None, false, false),
        };
        let destination_parent_identity = destination
            .as_ref()
            .and_then(|path| path.parent())
            .map(StableFileIdentity::from_path)
            .transpose()
            .map_err(|error| {
                io_error(
                    destination
                        .as_ref()
                        .and_then(|path| path.parent())
                        .unwrap_or_else(|| Path::new("destination parent")),
                    error,
                )
            })?;
        items.push(PlannedItem {
            source,
            source_identity,
            source_modified_nanos,
            destination,
            destination_parent_identity,
            item_kind,
            size: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
            conflict,
            conflict_resolved,
            undo_supported: request.kind != FileOperationKind::Trash || trash_restore_supported(),
        });
    }

    let confirmation_token = plan_confirmation_token(request, &items)?;
    Ok(OperationPlan {
        operation_id: request.operation_id,
        request_fingerprint,
        confirmation_token,
        kind: request.kind,
        conflict_policy: request.conflict_policy,
        items,
        destination: request.destination.clone(),
    })
}

impl OperationPlan {
    fn public_preview(&self) -> FileOperationPreview {
        FileOperationPreview {
            operation_id: self.operation_id,
            confirmation_token: self.confirmation_token.clone(),
            kind: self.kind,
            conflict_policy: self.conflict_policy,
            items: self
                .items
                .iter()
                .map(|item| FileOperationPreviewItem {
                    source: item.source.to_string_lossy().to_string(),
                    destination: item
                        .destination
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string()),
                    item_kind: item.item_kind,
                    size: item.size,
                    conflict: item.conflict,
                    conflict_resolved: item.conflict_resolved,
                    undo_supported: item.undo_supported,
                })
                .collect(),
            requires_confirmation: true,
            undo_supported: self.items.iter().all(|item| item.undo_supported),
        }
    }
}

fn ensure_plan_can_execute(plan: &OperationPlan) -> SearchResult<()> {
    if plan
        .items
        .iter()
        .any(|item| item.conflict && !item.conflict_resolved)
    {
        return Err(SearchError::FileOperation(
            "one or more destinations already exist; choose keep_both or another destination"
                .to_string(),
        ));
    }
    Ok(())
}

fn ensure_receipt_matches_request(
    receipt: &FileOperationReceipt,
    operation_id: Uuid,
    request_fingerprint: &str,
) -> SearchResult<()> {
    if receipt.request_fingerprint.is_empty() || receipt.request_fingerprint != request_fingerprint
    {
        return Err(SearchError::FileOperation(format!(
            "operation ID {operation_id} was already used for a different or legacy request"
        )));
    }
    Ok(())
}

fn request_fingerprint(request: &FileOperationRequest) -> SearchResult<String> {
    validate_request_shape(request)?;
    let payload = serde_json::to_vec(&(
        request.kind,
        &request.sources,
        &request.destination,
        request.conflict_policy,
        &request.confirmation_token,
    ))?;
    Ok(blake3::hash(&payload).to_hex().to_string())
}

fn plan_confirmation_token(
    request: &FileOperationRequest,
    items: &[PlannedItem],
) -> SearchResult<String> {
    let items = items
        .iter()
        .map(|item| {
            serde_json::json!({
                "source": normalize_path(&item.source),
                "source_identity": item.source_identity,
                "source_modified_nanos": item.source_modified_nanos,
                "destination": item.destination.as_ref().map(|path| normalize_path(path)),
                "destination_parent_identity": item.destination_parent_identity,
                "item_kind": item.item_kind,
                "size": item.size,
                "conflict": item.conflict,
                "conflict_resolved": item.conflict_resolved,
                "undo_supported": item.undo_supported,
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&(
        request.operation_id,
        request.kind,
        request.conflict_policy,
        items,
    ))?;
    Ok(blake3::hash(&payload).to_hex().to_string())
}

fn validate_request_shape(request: &FileOperationRequest) -> SearchResult<()> {
    if request.operation_id.is_nil()
        || request.sources.is_empty()
        || request.sources.len() > MAX_OPERATION_SOURCES
        || request
            .sources
            .iter()
            .any(|source| source.is_empty() || source.len() > 32_768)
        || request
            .destination
            .as_ref()
            .is_some_and(|destination| destination.is_empty() || destination.len() > 32_768)
        || request.confirmation_token.as_ref().is_some_and(|token| {
            token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(SearchError::FileOperation(
            "file operation request is outside supported limits".to_string(),
        ));
    }
    Ok(())
}

fn new_receipt(
    plan: &OperationPlan,
    state: FileOperationState,
    phase: &str,
) -> FileOperationReceipt {
    let total_bytes = plan
        .items
        .iter()
        .all(|item| item.item_kind == FileOperationItemKind::File)
        .then(|| {
            plan.items
                .iter()
                .fold(0_u64, |total, item| total.saturating_add(item.size))
        });
    FileOperationReceipt {
        operation_id: plan.operation_id,
        request_fingerprint: plan.request_fingerprint.clone(),
        kind: plan.kind,
        sources: plan
            .items
            .iter()
            .map(|item| item.source.to_string_lossy().to_string())
            .collect(),
        destination: plan.destination.clone(),
        state,
        undo_actions: Vec::new(),
        progress: FileOperationProgress {
            phase: phase.to_string(),
            completed_items: 0,
            total_items: plan.items.len() as u64,
            completed_bytes: 0,
            total_bytes,
            current_path: None,
        },
        started_at: Utc::now(),
        completed_at: None,
        error_code: None,
        message: None,
    }
}

fn execute_plan<P, S>(
    plan: OperationPlan,
    mut receipt: FileOperationReceipt,
    cancellation: Arc<AtomicBool>,
    mut on_progress: P,
    mut persist: S,
) -> SearchResult<FileOperationReceipt>
where
    P: FnMut(&FileOperationProgress),
    S: FnMut(&FileOperationReceipt) -> SearchResult<()>,
{
    for (index, item) in plan.items.iter().enumerate() {
        if cancellation.load(Ordering::Acquire) {
            return finish_operation_failure(receipt, OperationFailure::cancelled(), &mut persist);
        }
        if let Err(error) = validate_planned_item(item) {
            return finish_operation_failure(receipt, error, &mut persist);
        }
        receipt.progress.current_path = Some(item.source.to_string_lossy().to_string());
        on_progress(&receipt.progress);
        let bytes_before = receipt.progress.completed_bytes;
        let item_bytes = Cell::new(0_u64);
        let result = {
            let mut live_progress = receipt.progress.clone();
            let mut bytes = |count: u64| {
                item_bytes.set(item_bytes.get().saturating_add(count));
                live_progress.completed_bytes = bytes_before.saturating_add(item_bytes.get());
                on_progress(&live_progress);
            };
            let mut journal = |action: &UndoAction| -> OperationResult<()> {
                upsert_journal_action(&mut receipt, action.clone());
                receipt.progress.completed_bytes = bytes_before.saturating_add(item_bytes.get());
                persist(&receipt).map_err(|error| {
                    OperationFailure::new(
                        "receipt_persist_failed",
                        format!("could not persist operation intent before mutation: {error}"),
                    )
                })
            };
            match plan.kind {
                FileOperationKind::Copy => {
                    let destination = item
                        .destination
                        .as_deref()
                        .expect("planned copy destination");
                    let mut action = None;
                    let mut ready = |identity: &StableFileIdentity, size: u64| {
                        let prepared = UndoAction {
                            kind: UndoActionKind::RemoveCreated,
                            item_index: index as u64,
                            source: destination.to_string_lossy().to_string(),
                            destination: None,
                            expected_identity: Some(identity.clone()),
                            expected_size: Some(size),
                            trash_item_id: None,
                            trash_deleted_at: None,
                            undone: false,
                        };
                        journal(&prepared)?;
                        action = Some(prepared);
                        Ok(())
                    };
                    copy_entry_atomic(
                        &item.source,
                        destination,
                        plan.operation_id,
                        index,
                        &cancellation,
                        &mut bytes,
                        &mut ready,
                    )
                    .map(|_| action)
                }
                FileOperationKind::Move | FileOperationKind::Rename => move_entry(
                    &item.source,
                    item.destination
                        .as_deref()
                        .expect("planned move destination"),
                    plan.operation_id,
                    index,
                    &cancellation,
                    &mut bytes,
                    Some(&mut journal),
                )
                .map(Some),
                FileOperationKind::Trash => trash_entry(&item.source, index),
            }
        };
        match result {
            Ok(Some(action)) => upsert_journal_action(&mut receipt, action),
            Ok(None) => {}
            Err(error) => {
                reconcile_failed_item_action(&mut receipt, index);
                return finish_operation_failure(receipt, error, &mut persist);
            }
        }
        if matches!(
            plan.kind,
            FileOperationKind::Move | FileOperationKind::Rename | FileOperationKind::Trash
        ) && item.item_kind == FileOperationItemKind::File
            && receipt.progress.completed_bytes == bytes_before
        {
            receipt.progress.completed_bytes =
                receipt.progress.completed_bytes.saturating_add(item.size);
        }
        receipt.progress.completed_items = receipt.progress.completed_items.saturating_add(1);
        receipt.progress.current_path = None;
        if let Err(error) = persist(&receipt) {
            return Ok(receipt_persistence_failure(receipt, error));
        }
        on_progress(&receipt.progress);
    }
    receipt.state = FileOperationState::Complete;
    receipt.completed_at = Some(Utc::now());
    receipt.progress.phase = "complete".to_string();
    receipt.progress.current_path = None;
    if let Err(error) = persist(&receipt) {
        return Ok(receipt_persistence_failure(receipt, error));
    }
    on_progress(&receipt.progress);
    Ok(receipt)
}

fn upsert_journal_action(receipt: &mut FileOperationReceipt, action: UndoAction) {
    if let Some(existing) = receipt
        .undo_actions
        .iter_mut()
        .find(|existing| existing.item_index == action.item_index)
    {
        *existing = action;
    } else {
        receipt.undo_actions.push(action);
    }
}

fn reconcile_failed_item_action(receipt: &mut FileOperationReceipt, item_index: usize) {
    let Some(position) = receipt
        .undo_actions
        .iter()
        .position(|action| action.item_index == item_index as u64)
    else {
        return;
    };
    if !action_target_matches(&receipt.undo_actions[position]) {
        receipt.undo_actions.remove(position);
        return;
    }
    let action = &mut receipt.undo_actions[position];
    if action.kind == UndoActionKind::MoveBack
        && action
            .destination
            .as_deref()
            .is_some_and(|path| Path::new(path).exists())
    {
        action.kind = UndoActionKind::RemoveCreated;
        action.destination = None;
    }
}

fn finish_operation_failure<S>(
    mut receipt: FileOperationReceipt,
    failure: OperationFailure,
    persist: &mut S,
) -> SearchResult<FileOperationReceipt>
where
    S: FnMut(&FileOperationReceipt) -> SearchResult<()>,
{
    receipt.state = if failure.code == "operation_cancelled" {
        FileOperationState::Cancelled
    } else {
        FileOperationState::Failed
    };
    receipt.completed_at = Some(Utc::now());
    receipt.error_code = Some(failure.code.to_string());
    receipt.message = Some(failure.message);
    receipt.progress.phase = state_phase(receipt.state).to_string();
    receipt.progress.current_path = None;
    if let Err(error) = persist(&receipt) {
        receipt.message = Some(format!(
            "{}; final receipt persistence failed: {error}",
            receipt.message.as_deref().unwrap_or("operation failed")
        ));
    }
    Ok(receipt)
}

fn execute_undo<P, S>(
    mut receipt: FileOperationReceipt,
    cancellation: Arc<AtomicBool>,
    mut on_progress: P,
    mut persist: S,
) -> SearchResult<FileOperationReceipt>
where
    P: FnMut(&FileOperationProgress),
    S: FnMut(&FileOperationReceipt) -> SearchResult<()>,
{
    for index in (0..receipt.undo_actions.len()).rev() {
        if receipt.undo_actions[index].undone {
            continue;
        }
        if cancellation.load(Ordering::Acquire) {
            return finish_operation_failure(receipt, OperationFailure::cancelled(), &mut persist);
        }
        receipt.progress.current_path = Some(receipt.undo_actions[index].source.clone());
        on_progress(&receipt.progress);
        let action = receipt.undo_actions[index].clone();
        let result = {
            let mut bytes = |count: u64| {
                receipt.progress.completed_bytes =
                    receipt.progress.completed_bytes.saturating_add(count);
                on_progress(&receipt.progress);
            };
            execute_undo_action(
                &action,
                receipt.operation_id,
                index,
                &cancellation,
                &mut bytes,
            )
        };
        if let Err(error) = result {
            return finish_operation_failure(receipt, error, &mut persist);
        }
        receipt.undo_actions[index].undone = true;
        receipt.progress.completed_items = receipt.progress.completed_items.saturating_add(1);
        receipt.progress.current_path = None;
        if let Err(error) = persist(&receipt) {
            return Ok(receipt_persistence_failure(receipt, error));
        }
        on_progress(&receipt.progress);
    }
    receipt.state = FileOperationState::Undone;
    receipt.completed_at = Some(Utc::now());
    receipt.error_code = None;
    receipt.message = None;
    receipt.progress.phase = "undone".to_string();
    receipt.progress.current_path = None;
    if let Err(error) = persist(&receipt) {
        return Ok(receipt_persistence_failure(receipt, error));
    }
    on_progress(&receipt.progress);
    Ok(receipt)
}

fn receipt_persistence_failure(
    mut receipt: FileOperationReceipt,
    error: SearchError,
) -> FileOperationReceipt {
    receipt.state = FileOperationState::Failed;
    receipt.completed_at = Some(Utc::now());
    receipt.error_code = Some("receipt_persist_failed".to_string());
    receipt.message = Some(format!(
        "the filesystem action completed, but its recovery receipt could not be persisted: {error}"
    ));
    receipt.progress.phase = "failed".to_string();
    receipt.progress.current_path = None;
    receipt
}

fn validate_planned_item(item: &PlannedItem) -> OperationResult<()> {
    let metadata = fs::symlink_metadata(&item.source)
        .map_err(|error| OperationFailure::io("source revalidation", &item.source, error))?;
    let expected_type_matches = match item.item_kind {
        FileOperationItemKind::File => metadata.is_file(),
        FileOperationItemKind::Directory => metadata.is_dir(),
    };
    if metadata.file_type().is_symlink()
        || !expected_type_matches
        || (metadata.is_file() && metadata.len() != item.size)
        || metadata_modified_nanos(&metadata) != item.source_modified_nanos
    {
        return Err(OperationFailure::new(
            "source_changed",
            format!("source changed after preview: {}", item.source.display()),
        ));
    }
    let current_identity = StableFileIdentity::from_path(&item.source)
        .map_err(|error| OperationFailure::io("source identity", &item.source, error))?;
    if current_identity != item.source_identity {
        return Err(OperationFailure::new(
            "source_changed",
            format!(
                "source identity changed after preview: {}",
                item.source.display()
            ),
        ));
    }
    if let (Some(destination), Some(expected_parent)) = (
        item.destination.as_deref(),
        item.destination_parent_identity.as_ref(),
    ) {
        let parent = destination.parent().ok_or_else(|| {
            OperationFailure::new("invalid_destination", "destination has no parent directory")
        })?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|error| OperationFailure::io("destination revalidation", parent, error))?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(OperationFailure::new(
                "destination_changed",
                format!(
                    "destination parent changed after preview: {}",
                    parent.display()
                ),
            ));
        }
        let current_parent = StableFileIdentity::from_path(parent)
            .map_err(|error| OperationFailure::io("destination identity", parent, error))?;
        if &current_parent != expected_parent {
            return Err(OperationFailure::new(
                "destination_changed",
                format!(
                    "destination parent identity changed after preview: {}",
                    parent.display()
                ),
            ));
        }
    }
    Ok(())
}

fn metadata_modified_nanos(metadata: &fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

fn execute_undo_action(
    action: &UndoAction,
    operation_id: Uuid,
    index: usize,
    cancellation: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
) -> OperationResult<()> {
    match action.kind {
        UndoActionKind::MoveBack => {
            let source = Path::new(&action.source);
            validate_action_identity(source, action)?;
            let destination = action.destination.as_deref().ok_or_else(|| {
                OperationFailure::new("invalid_undo_receipt", "move undo destination is missing")
            })?;
            let destination = Path::new(destination);
            if destination.exists() {
                return Err(OperationFailure::new(
                    "undo_conflict",
                    format!(
                        "undo refused to overwrite a newly created item at {}",
                        destination.display()
                    ),
                ));
            }
            move_entry(
                source,
                destination,
                operation_id,
                index,
                cancellation,
                on_bytes,
                None,
            )?;
            Ok(())
        }
        UndoActionKind::RemoveCreated => {
            let source = Path::new(&action.source);
            validate_action_identity(source, action)?;
            if cancellation.load(Ordering::Acquire) {
                return Err(OperationFailure::cancelled());
            }
            trash::delete(source).map_err(|error| {
                OperationFailure::new(
                    "trash_failed",
                    format!("could not move undo target to Trash: {error}"),
                )
            })
        }
        UndoActionKind::RestoreTrash => restore_trash_action(action),
    }
}

fn copy_entry_atomic(
    source: &Path,
    destination: &Path,
    operation_id: Uuid,
    index: usize,
    cancellation: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
    before_commit: &mut dyn FnMut(&StableFileIdentity, u64) -> OperationResult<()>,
) -> OperationResult<(StableFileIdentity, u64)> {
    if destination.exists() {
        return Err(OperationFailure::new(
            "destination_conflict",
            format!("destination already exists: {}", destination.display()),
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        OperationFailure::new("invalid_destination", "destination has no parent directory")
    })?;
    if !parent.is_dir() {
        return Err(OperationFailure::new(
            "invalid_destination",
            format!("destination parent is unavailable: {}", parent.display()),
        ));
    }
    let stage = parent.join(format!(".spiffy-search-{operation_id}-{index}.partial"));
    if stage.exists() {
        return Err(OperationFailure::new(
            "staging_conflict",
            format!("owned staging path already exists: {}", stage.display()),
        ));
    }
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| OperationFailure::io("source inspection", source, error))?;
    if metadata.file_type().is_symlink() {
        return Err(OperationFailure::new(
            "symlink_unsupported",
            "file operations do not follow symbolic links",
        ));
    }
    let result = if metadata.is_file() {
        copy_file_verified(source, &stage, cancellation, on_bytes)
    } else if metadata.is_dir() {
        copy_directory_verified(source, &stage, cancellation, on_bytes)
    } else {
        Err(OperationFailure::new(
            "unsupported_file_type",
            "only normal files and directories are supported",
        ))
    };
    let copied_bytes = match result {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = remove_owned_stage(&stage, operation_id, index);
            return Err(error);
        }
    };
    if cancellation.load(Ordering::Acquire) {
        let _ = remove_owned_stage(&stage, operation_id, index);
        return Err(OperationFailure::cancelled());
    }
    let identity = StableFileIdentity::from_path(&stage)
        .map_err(|error| OperationFailure::io("staging identity", &stage, error))?;
    if let Err(error) = before_commit(&identity, copied_bytes) {
        let _ = remove_owned_stage(&stage, operation_id, index);
        return Err(error);
    }
    if let Err(error) = rename_no_replace(&stage, destination) {
        let _ = remove_owned_stage(&stage, operation_id, index);
        return Err(OperationFailure::io(
            "atomic copy finalization",
            destination,
            error,
        ));
    }
    Ok((identity, copied_bytes))
}

fn move_entry(
    source: &Path,
    destination: &Path,
    operation_id: Uuid,
    index: usize,
    cancellation: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
    mut journal: Option<&mut UndoJournal<'_>>,
) -> OperationResult<UndoAction> {
    if destination.exists() {
        return Err(OperationFailure::new(
            "destination_conflict",
            format!("destination already exists: {}", destination.display()),
        ));
    }
    if cancellation.load(Ordering::Acquire) {
        return Err(OperationFailure::cancelled());
    }
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| OperationFailure::io("source inspection", source, error))?;
    if source_metadata.file_type().is_symlink()
        || (!source_metadata.is_file() && !source_metadata.is_dir())
    {
        return Err(OperationFailure::new(
            "unsupported_file_type",
            "move requires a normal file or directory and does not follow symbolic links",
        ));
    }
    let source_size = if source_metadata.is_file() {
        source_metadata.len()
    } else {
        0
    };
    let source_identity = StableFileIdentity::from_path(source)
        .map_err(|error| OperationFailure::io("source identity", source, error))?;
    let mut action = UndoAction {
        kind: UndoActionKind::MoveBack,
        item_index: index as u64,
        source: destination.to_string_lossy().to_string(),
        destination: Some(source.to_string_lossy().to_string()),
        expected_identity: Some(source_identity.clone()),
        expected_size: Some(source_size),
        trash_item_id: None,
        trash_deleted_at: None,
        undone: false,
    };
    if let Some(journal) = journal.as_deref_mut() {
        journal(&action)?;
    }
    let destination_identity = match rename_no_replace(source, destination) {
        Ok(()) => source_identity,
        Err(error) if is_cross_device(&error) => {
            let mut before_commit = |identity: &StableFileIdentity, _size: u64| {
                action.expected_identity = Some(identity.clone());
                if let Some(journal) = journal.as_deref_mut() {
                    journal(&action)?;
                }
                Ok(())
            };
            let (identity, _copied_bytes) = copy_entry_atomic(
                source,
                destination,
                operation_id,
                index,
                cancellation,
                on_bytes,
                &mut before_commit,
            )?;
            if cancellation.load(Ordering::Acquire) {
                let _ = remove_if_identity(destination, &identity);
                return Err(OperationFailure::cancelled());
            }
            if let Err(remove_error) = remove_entry_permanent(source) {
                let cleanup = remove_if_identity(destination, &identity);
                let cleanup_note = cleanup
                    .err()
                    .map(|cleanup_error| {
                        format!(
                            "; destination cleanup also failed: {}",
                            cleanup_error.message
                        )
                    })
                    .unwrap_or_default();
                return Err(OperationFailure::new(
                    "source_remove_failed",
                    format!(
                        "verified cross-volume copy completed but source removal failed: {}{cleanup_note}",
                        remove_error.message
                    ),
                ));
            }
            identity
        }
        Err(error) => {
            return Err(OperationFailure::io("native move", destination, error));
        }
    };
    action.expected_identity = Some(destination_identity);
    Ok(action)
}

fn copy_file_verified(
    source: &Path,
    destination: &Path,
    cancellation: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
) -> OperationResult<u64> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| OperationFailure::io("source inspection", source, error))?;
    if !source_metadata.is_file() || source_metadata.file_type().is_symlink() {
        return Err(OperationFailure::new(
            "source_changed",
            "copy source changed type before it could be read",
        ));
    }
    let source_identity = StableFileIdentity::from_path(source)
        .map_err(|error| OperationFailure::io("source identity", source, error))?;
    let mut input =
        File::open(source).map_err(|error| OperationFailure::io("source open", source, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| OperationFailure::io("staging create", destination, error))?;
    let mut source_digest = blake3::Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut copied = 0_u64;
    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(OperationFailure::cancelled());
        }
        let read = input
            .read(&mut buffer)
            .map_err(|error| OperationFailure::io("source read", source, error))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| OperationFailure::io("staging write", destination, error))?;
        source_digest.update(&buffer[..read]);
        copied = copied.saturating_add(read as u64);
        on_bytes(read as u64);
    }
    output
        .sync_all()
        .map_err(|error| OperationFailure::io("staging sync", destination, error))?;
    let source_after = fs::symlink_metadata(source)
        .map_err(|error| OperationFailure::io("source revalidation", source, error))?;
    if copied != source_metadata.len()
        || source_after.len() != source_metadata.len()
        || source_after.modified().ok() != source_metadata.modified().ok()
        || StableFileIdentity::from_path(source).ok().as_ref() != Some(&source_identity)
    {
        return Err(OperationFailure::new(
            "source_changed",
            "copy source changed while the operation was running",
        ));
    }
    apply_metadata(&source_metadata, destination)?;
    let destination_digest = digest_file(destination, cancellation)?;
    if destination_digest != source_digest.finalize() {
        return Err(OperationFailure::new(
            "checksum_mismatch",
            "copied file failed BLAKE3 verification",
        ));
    }
    Ok(copied)
}

fn copy_directory_verified(
    source: &Path,
    destination: &Path,
    cancellation: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
) -> OperationResult<u64> {
    fs::create_dir(destination)
        .map_err(|error| OperationFailure::io("staging directory create", destination, error))?;
    let mut stack = vec![(source.to_path_buf(), destination.to_path_buf(), 0_usize)];
    let mut directories = Vec::new();
    let mut entries = 0_usize;
    let mut copied_bytes = 0_u64;
    while let Some((source_dir, destination_dir, depth)) = stack.pop() {
        if cancellation.load(Ordering::Acquire) {
            return Err(OperationFailure::cancelled());
        }
        if depth > MAX_DIRECTORY_DEPTH {
            return Err(OperationFailure::new(
                "directory_too_deep",
                format!("directory copy exceeds depth {MAX_DIRECTORY_DEPTH}"),
            ));
        }
        let metadata = fs::symlink_metadata(&source_dir)
            .map_err(|error| OperationFailure::io("directory inspection", &source_dir, error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(OperationFailure::new(
                "source_changed",
                "directory source changed type during copy",
            ));
        }
        directories.push((source_dir.clone(), destination_dir.clone()));
        let iterator = fs::read_dir(&source_dir)
            .map_err(|error| OperationFailure::io("directory read", &source_dir, error))?;
        for entry in iterator {
            if cancellation.load(Ordering::Acquire) {
                return Err(OperationFailure::cancelled());
            }
            entries = entries.saturating_add(1);
            if entries > MAX_DIRECTORY_ENTRIES {
                return Err(OperationFailure::new(
                    "directory_too_large",
                    format!("directory copy exceeds {MAX_DIRECTORY_ENTRIES} entries"),
                ));
            }
            let entry = entry.map_err(|error| {
                OperationFailure::io("directory entry read", &source_dir, error)
            })?;
            let source_child = entry.path();
            let destination_child = destination_dir.join(entry.file_name());
            let child_metadata = fs::symlink_metadata(&source_child).map_err(|error| {
                OperationFailure::io("directory entry inspection", &source_child, error)
            })?;
            if child_metadata.file_type().is_symlink() {
                return Err(OperationFailure::new(
                    "symlink_unsupported",
                    format!(
                        "directory copy refuses symbolic link {}",
                        source_child.display()
                    ),
                ));
            }
            if child_metadata.is_dir() {
                fs::create_dir(&destination_child).map_err(|error| {
                    OperationFailure::io("staging directory create", &destination_child, error)
                })?;
                stack.push((source_child, destination_child, depth.saturating_add(1)));
            } else if child_metadata.is_file() {
                copied_bytes = copied_bytes.saturating_add(copy_file_verified(
                    &source_child,
                    &destination_child,
                    cancellation,
                    on_bytes,
                )?);
            } else {
                return Err(OperationFailure::new(
                    "unsupported_file_type",
                    format!(
                        "directory contains unsupported entry {}",
                        source_child.display()
                    ),
                ));
            }
        }
    }
    for (source_dir, destination_dir) in directories.into_iter().rev() {
        let metadata = fs::metadata(&source_dir)
            .map_err(|error| OperationFailure::io("directory metadata", &source_dir, error))?;
        apply_metadata(&metadata, &destination_dir)?;
    }
    Ok(copied_bytes)
}

fn apply_metadata(metadata: &fs::Metadata, destination: &Path) -> OperationResult<()> {
    match (metadata.accessed(), metadata.modified()) {
        (Ok(accessed), Ok(modified)) => filetime::set_file_times(
            destination,
            FileTime::from_system_time(accessed),
            FileTime::from_system_time(modified),
        )
        .map_err(|error| OperationFailure::io("timestamp copy", destination, error)),
        (_, Ok(modified)) => {
            filetime::set_file_mtime(destination, FileTime::from_system_time(modified)).map_err(
                |error| OperationFailure::io("modified timestamp copy", destination, error),
            )
        }
        (Ok(accessed), _) => {
            filetime::set_file_atime(destination, FileTime::from_system_time(accessed))
                .map_err(|error| OperationFailure::io("access timestamp copy", destination, error))
        }
        (Err(_), Err(_)) => Ok(()),
    }?;
    fs::set_permissions(destination, metadata.permissions())
        .map_err(|error| OperationFailure::io("permission copy", destination, error))
}

fn digest_file(path: &Path, cancellation: &AtomicBool) -> OperationResult<blake3::Hash> {
    let mut file =
        File::open(path).map_err(|error| OperationFailure::io("verification open", path, error))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        if cancellation.load(Ordering::Acquire) {
            return Err(OperationFailure::cancelled());
        }
        let read = file
            .read(&mut buffer)
            .map_err(|error| OperationFailure::io("verification read", path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}

#[cfg(windows)]
fn trash_item_matches_source(
    item: &trash::TrashItem,
    source: &Path,
    source_identity: &StableFileIdentity,
    source_metadata: &fs::Metadata,
) -> bool {
    if source
        .parent()
        .is_none_or(|parent| normalize_path(&item.original_parent) != normalize_path(parent))
    {
        return false;
    }
    let recycled_path = Path::new(item.id.as_os_str());
    if StableFileIdentity::from_path(recycled_path)
        .is_ok_and(|identity| &identity == source_identity)
    {
        return true;
    }
    let expected_name = source
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase());
    let expected_stem = source
        .file_stem()
        .map(|name| name.to_string_lossy().to_lowercase());
    let displayed_name = item.name.to_string_lossy().to_lowercase();
    let name_matches = expected_name.as_deref() == Some(&displayed_name)
        || expected_stem.as_deref() == Some(&displayed_name);
    let extension_matches = recycled_path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase())
        == source
            .extension()
            .map(|extension| extension.to_string_lossy().to_lowercase());
    let size_matches = if source_metadata.is_file() {
        matches!(
            trash::os_limited::metadata(item),
            Ok(trash::TrashItemMetadata {
                size: trash::TrashItemSize::Bytes(size)
            }) if size == source_metadata.len()
        )
    } else {
        source_metadata.is_dir()
    };
    name_matches && extension_matches && size_matches
}

#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
fn trash_item_matches_source(
    item: &trash::TrashItem,
    source: &Path,
    _source_identity: &StableFileIdentity,
    _source_metadata: &fs::Metadata,
) -> bool {
    normalize_path(&item.original_path()) == normalize_path(source)
}

fn trash_entry(source: &Path, item_index: usize) -> OperationResult<Option<UndoAction>> {
    #[cfg(any(
        target_os = "windows",
        all(
            unix,
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "android")
        )
    ))]
    {
        let source_metadata = fs::symlink_metadata(source)
            .map_err(|error| OperationFailure::io("trash source inspection", source, error))?;
        let source_identity = StableFileIdentity::from_path(source)
            .map_err(|error| OperationFailure::io("trash source identity", source, error))?;
        let before = trash::os_limited::list().map_err(|error| {
            OperationFailure::new(
                "trash_inventory_failed",
                format!("could not inspect Trash before deletion: {error}"),
            )
        })?;
        let before_ids = before
            .iter()
            .map(|item| encode_os_string(&item.id))
            .collect::<HashSet<_>>();
        trash::delete(source).map_err(|error| {
            OperationFailure::new(
                "trash_failed",
                format!("could not move item to Trash: {error}"),
            )
        })?;
        let deadline = Instant::now() + TRASH_RECEIPT_TIMEOUT;
        let item = loop {
            let inventory = trash::os_limited::list().map_err(|error| {
                OperationFailure::new(
                    "trash_inventory_failed",
                    format!("item was trashed but its restore receipt could not be read: {error}"),
                )
            })?;
            let mut candidates = inventory
                .into_iter()
                .filter(|item| !before_ids.contains(&encode_os_string(&item.id)))
                .filter(|item| {
                    trash_item_matches_source(item, source, &source_identity, &source_metadata)
                })
                .collect::<Vec<_>>();
            if candidates.len() == 1 {
                break candidates.pop().expect("one candidate");
            }
            if candidates.len() > 1 {
                return Err(OperationFailure::new(
                    "trash_receipt_ambiguous",
                    "item was trashed but multiple new restore records matched it",
                ));
            }
            if Instant::now() >= deadline {
                return Err(OperationFailure::new(
                    "trash_receipt_missing",
                    "item was trashed but no unique restore record appeared before the timeout",
                ));
            }
            std::thread::sleep(TRASH_RECEIPT_POLL);
        };
        Ok(Some(UndoAction {
            kind: UndoActionKind::RestoreTrash,
            item_index: item_index as u64,
            source: source.to_string_lossy().to_string(),
            destination: None,
            expected_identity: Some(source_identity),
            expected_size: source_metadata.is_file().then_some(source_metadata.len()),
            trash_item_id: Some(encode_os_string(&item.id)),
            trash_deleted_at: Some(item.time_deleted),
            undone: false,
        }))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = item_index;
        trash::delete(source).map_err(|error| {
            OperationFailure::new(
                "trash_failed",
                format!("could not move item to Trash: {error}"),
            )
        })?;
        Ok(None)
    }
}

fn restore_trash_action(action: &UndoAction) -> OperationResult<()> {
    #[cfg(any(
        target_os = "windows",
        all(
            unix,
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "android")
        )
    ))]
    {
        let expected_id = action.trash_item_id.as_deref().ok_or_else(|| {
            OperationFailure::new(
                "invalid_undo_receipt",
                "trash undo receipt is missing its platform item ID",
            )
        })?;
        let expected_time = action.trash_deleted_at.ok_or_else(|| {
            OperationFailure::new(
                "invalid_undo_receipt",
                "trash undo receipt is missing its deletion time",
            )
        })?;
        let original = Path::new(&action.source);
        if original.exists() {
            return Err(OperationFailure::new(
                "undo_conflict",
                format!(
                    "trash restore refused to overwrite a new item at {}",
                    original.display()
                ),
            ));
        }
        let item = trash::os_limited::list()
            .map_err(|error| {
                OperationFailure::new(
                    "trash_inventory_failed",
                    format!("could not inspect Trash for restore: {error}"),
                )
            })?
            .into_iter()
            .find(|item| {
                encode_os_string(&item.id) == expected_id && item.time_deleted == expected_time
            })
            .ok_or_else(|| {
                OperationFailure::new(
                    "trash_item_missing",
                    "the exact Trash item recorded for undo is no longer available",
                )
            })?;
        #[cfg(windows)]
        restore_windows_trash_item(&item, original)?;
        #[cfg(all(
            unix,
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "android")
        ))]
        trash::os_limited::restore_all([item]).map_err(|error| {
            OperationFailure::new(
                "trash_restore_failed",
                format!("Trash restore failed: {error}"),
            )
        })?;
        validate_action_identity(original, action)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = action;
        Err(OperationFailure::new(
            "trash_restore_unsupported",
            "programmatic Trash restore is unavailable on macOS; use Finder Put Back",
        ))
    }
}

fn validate_action_identity(path: &Path, action: &UndoAction) -> OperationResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| OperationFailure::io("undo target inspection", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(OperationFailure::new(
            "identity_mismatch",
            "undo target became a symbolic link",
        ));
    }
    let expected = action.expected_identity.as_ref().ok_or_else(|| {
        OperationFailure::new(
            "identity_unavailable",
            "undo receipt has no stable identity and cannot be reversed safely",
        )
    })?;
    let actual = StableFileIdentity::from_path(path)
        .map_err(|error| OperationFailure::io("undo identity", path, error))?;
    if &actual != expected
        || action
            .expected_size
            .is_some_and(|size| metadata.is_file() && metadata.len() != size)
    {
        return Err(OperationFailure::new(
            "identity_mismatch",
            format!(
                "undo refused because the item at {} is no longer the recorded item",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn action_target_matches(action: &UndoAction) -> bool {
    validate_action_identity(Path::new(&action.source), action).is_ok()
}

fn canonical_source(path: &Path) -> SearchResult<PathBuf> {
    if !path.is_absolute() {
        return Err(SearchError::FileOperation(
            "file operation source paths must be absolute".to_string(),
        ));
    }
    let absolute = std::path::absolute(path).map_err(|error| io_error(path, error))?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| io_error(&absolute, error))?;
    if metadata.file_type().is_symlink() {
        return Err(SearchError::FileOperation(format!(
            "file operations do not follow symbolic links: {}",
            absolute.display()
        )));
    }
    let canonical = fs::canonicalize(&absolute).map_err(|error| io_error(&absolute, error))?;
    if canonical.parent().is_none() {
        return Err(SearchError::FileOperation(
            "filesystem roots cannot be file-operation sources".to_string(),
        ));
    }
    Ok(canonical)
}

fn canonical_destination_directory(path: &Path) -> SearchResult<PathBuf> {
    if !path.is_absolute() {
        return Err(SearchError::FileOperation(
            "copy and move destination paths must be absolute".to_string(),
        ));
    }
    let absolute = std::path::absolute(path).map_err(|error| io_error(path, error))?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| io_error(&absolute, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SearchError::FileOperation(format!(
            "destination is not a normal directory: {}",
            absolute.display()
        )));
    }
    fs::canonicalize(&absolute).map_err(|error| io_error(&absolute, error))
}

fn rename_destination(source: &Path, raw_destination: &str) -> SearchResult<PathBuf> {
    if raw_destination.is_empty() || raw_destination.len() > 32_768 {
        return Err(SearchError::FileOperation(
            "rename destination is invalid".to_string(),
        ));
    }
    let raw = Path::new(raw_destination);
    let candidate = if !raw.is_absolute() && raw.components().count() == 1 {
        source
            .parent()
            .ok_or_else(|| SearchError::FileOperation("rename source has no parent".to_string()))?
            .join(raw)
    } else {
        std::path::absolute(raw).map_err(|error| io_error(raw, error))?
    };
    let file_name = candidate.file_name().ok_or_else(|| {
        SearchError::FileOperation("rename destination has no file name".to_string())
    })?;
    let parent = candidate.parent().ok_or_else(|| {
        SearchError::FileOperation("rename destination has no parent".to_string())
    })?;
    let parent = canonical_destination_directory(parent)?;
    let source_parent = source
        .parent()
        .ok_or_else(|| SearchError::FileOperation("rename source has no parent".to_string()))?;
    if normalize_path(&parent) != normalize_path(source_parent) {
        return Err(SearchError::FileOperation(
            "rename must stay in the source directory; use move for another folder".to_string(),
        ));
    }
    Ok(parent.join(file_name))
}

fn reject_nested_sources(sources: &[(PathBuf, fs::Metadata)]) -> SearchResult<()> {
    for (index, (candidate, _)) in sources.iter().enumerate() {
        let candidate_normalized = normalize_path(candidate);
        for (other_index, (other, metadata)) in sources.iter().enumerate() {
            if index != other_index
                && metadata.is_dir()
                && normalized_is_within(&candidate_normalized, &normalize_path(other))
            {
                return Err(SearchError::FileOperation(format!(
                    "nested source {} is already covered by selected directory {}",
                    candidate.display(),
                    other.display()
                )));
            }
        }
    }
    Ok(())
}

fn normalized_is_within(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| parent.ends_with('/') || suffix.starts_with('/'))
}

fn keep_both_path(
    proposed: &Path,
    item_kind: FileOperationItemKind,
    reserved: &HashSet<String>,
) -> SearchResult<PathBuf> {
    let parent = proposed.parent().ok_or_else(|| {
        SearchError::FileOperation("destination has no parent directory".to_string())
    })?;
    let filename = proposed
        .file_name()
        .ok_or_else(|| SearchError::FileOperation("destination has no file name".to_string()))?;
    let filename = filename.to_string_lossy();
    let (stem, extension) = if item_kind == FileOperationItemKind::File {
        let stem = proposed
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| filename.to_string());
        let extension = proposed
            .extension()
            .map(|value| value.to_string_lossy().to_string());
        (stem, extension)
    } else {
        (filename.to_string(), None)
    };
    for suffix in 2..=MAX_KEEP_BOTH_ATTEMPTS {
        let name = extension.as_ref().map_or_else(
            || format!("{stem} ({suffix})"),
            |extension| format!("{stem} ({suffix}).{extension}"),
        );
        let candidate = parent.join(name);
        if !candidate.exists() && !reserved.contains(&normalize_path(&candidate)) {
            return Ok(candidate);
        }
    }
    Err(SearchError::FileOperation(format!(
        "could not resolve a unique destination after {MAX_KEEP_BOTH_ATTEMPTS} attempts"
    )))
}

pub(crate) fn is_operation_staging_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(owner) = name
        .strip_prefix(".spiffy-search-")
        .and_then(|name| name.strip_suffix(".partial"))
    else {
        return false;
    };
    let Some((operation_id, item_index)) = owner.rsplit_once('-') else {
        return false;
    };
    Uuid::parse_str(operation_id).is_ok()
        && !item_index.is_empty()
        && item_index.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn cleanup_interrupted_staging(receipt: &FileOperationReceipt) -> SearchResult<u64> {
    if receipt.request_fingerprint.is_empty() {
        return Ok(0);
    }
    let mut stages = Vec::new();
    if receipt.state == FileOperationState::Running
        && matches!(
            receipt.kind,
            FileOperationKind::Copy | FileOperationKind::Move
        )
    {
        if let Some(destination) = receipt.destination.as_deref() {
            let parent = Path::new(destination);
            if parent.is_absolute() {
                for index in 0..receipt.sources.len() {
                    stages.push((
                        parent.join(format!(
                            ".spiffy-search-{}-{index}.partial",
                            receipt.operation_id
                        )),
                        index,
                    ));
                }
            }
        }
    } else if receipt.state == FileOperationState::Undoing {
        for (index, action) in receipt.undo_actions.iter().enumerate() {
            if action.undone || action.kind != UndoActionKind::MoveBack {
                continue;
            }
            if let Some(parent) = action
                .destination
                .as_deref()
                .map(Path::new)
                .filter(|path| path.is_absolute())
                .and_then(Path::parent)
            {
                stages.push((
                    parent.join(format!(
                        ".spiffy-search-{}-{index}.partial",
                        receipt.operation_id
                    )),
                    index,
                ));
            }
        }
    }
    let mut removed = 0_u64;
    for (stage, index) in stages {
        if !stage.exists() {
            continue;
        }
        remove_owned_stage(&stage, receipt.operation_id, index).map_err(|failure| {
            SearchError::FileOperation(format!("{}: {}", failure.code, failure.message))
        })?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

pub(crate) fn reconcile_interrupted_actions(receipt: &mut FileOperationReceipt) {
    match receipt.state {
        FileOperationState::Running => {
            let pending_indexes = receipt
                .undo_actions
                .iter()
                .filter(|action| action.item_index >= receipt.progress.completed_items)
                .map(|action| action.item_index as usize)
                .collect::<Vec<_>>();
            for item_index in pending_indexes {
                reconcile_failed_item_action(receipt, item_index);
            }
        }
        FileOperationState::Undoing => {
            for action in &mut receipt.undo_actions {
                if action.undone {
                    continue;
                }
                match action.kind {
                    UndoActionKind::MoveBack => {
                        if action_target_matches(action) {
                            continue;
                        }
                        if action.destination.as_deref().is_some_and(|destination| {
                            validate_action_identity(Path::new(destination), action).is_ok()
                        }) {
                            action.undone = true;
                        }
                    }
                    UndoActionKind::RemoveCreated => {
                        if fs::symlink_metadata(&action.source)
                            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                        {
                            action.undone = true;
                        }
                    }
                    UndoActionKind::RestoreTrash => {
                        if Path::new(&action.source).exists() && !trash_action_is_available(action)
                        {
                            action.undone = true;
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
fn trash_action_is_available(action: &UndoAction) -> bool {
    let (Some(expected_id), Some(expected_time)) =
        (action.trash_item_id.as_deref(), action.trash_deleted_at)
    else {
        return true;
    };
    trash::os_limited::list().map_or(true, |items| {
        items.into_iter().any(|item| {
            encode_os_string(&item.id) == expected_id && item.time_deleted == expected_time
        })
    })
}

#[cfg(target_os = "macos")]
fn trash_action_is_available(_action: &UndoAction) -> bool {
    true
}

fn remove_owned_stage(path: &Path, operation_id: Uuid, index: usize) -> OperationResult<()> {
    let expected = format!(".spiffy-search-{operation_id}-{index}.partial");
    if path.file_name().and_then(|name| name.to_str()) != Some(&expected) {
        return Err(OperationFailure::new(
            "unsafe_cleanup_refused",
            "staging cleanup path is outside the operation owner",
        ));
    }
    if !path.exists() {
        return Ok(());
    }
    match remove_entry_permanent(path) {
        Ok(()) => Ok(()),
        Err(first_error) => {
            clear_owned_stage_readonly(path)?;
            remove_entry_permanent(path).map_err(|retry_error| {
                OperationFailure::new(
                    retry_error.code,
                    format!(
                        "{}; retry after clearing owned staging attributes failed: {}",
                        first_error.message, retry_error.message
                    ),
                )
            })
        }
    }
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn clear_owned_stage_readonly(path: &Path) -> OperationResult<()> {
    let mut stack = vec![(path.to_path_buf(), 0_usize)];
    let mut entries = 0_usize;
    while let Some((entry, depth)) = stack.pop() {
        if depth > MAX_DIRECTORY_DEPTH {
            return Err(OperationFailure::new(
                "unsafe_cleanup_refused",
                "owned staging cleanup exceeded the directory depth limit",
            ));
        }
        entries = entries.saturating_add(1);
        if entries > MAX_DIRECTORY_ENTRIES {
            return Err(OperationFailure::new(
                "unsafe_cleanup_refused",
                "owned staging cleanup exceeded the entry limit",
            ));
        }
        let metadata = fs::symlink_metadata(&entry)
            .map_err(|error| OperationFailure::io("staging cleanup inspection", &entry, error))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let children = fs::read_dir(&entry)
                .map_err(|error| OperationFailure::io("staging cleanup read", &entry, error))?;
            for child in children {
                let child = child.map_err(|error| {
                    OperationFailure::io("staging cleanup entry read", &entry, error)
                })?;
                stack.push((child.path(), depth.saturating_add(1)));
            }
        }
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            fs::set_permissions(&entry, permissions).map_err(|error| {
                OperationFailure::io("staging cleanup permission reset", &entry, error)
            })?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn clear_owned_stage_readonly(_path: &Path) -> OperationResult<()> {
    Ok(())
}

fn remove_if_identity(path: &Path, expected: &StableFileIdentity) -> OperationResult<()> {
    let actual = StableFileIdentity::from_path(path)
        .map_err(|error| OperationFailure::io("cleanup identity", path, error))?;
    if &actual != expected {
        return Err(OperationFailure::new(
            "identity_mismatch",
            "cleanup refused because destination identity changed",
        ));
    }
    remove_entry_permanent(path)
}

fn remove_entry_permanent(path: &Path) -> OperationResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| OperationFailure::io("remove inspection", path, error))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
            .map_err(|error| OperationFailure::io("directory remove", path, error))
    } else {
        fs::remove_file(path).map_err(|error| OperationFailure::io("file remove", path, error))
    }
}

fn state_phase(state: FileOperationState) -> &'static str {
    match state {
        FileOperationState::Running => "running",
        FileOperationState::Complete => "complete",
        FileOperationState::Failed => "failed",
        FileOperationState::Cancelled => "cancelled",
        FileOperationState::Undoing => "undoing",
        FileOperationState::Undone => "undone",
    }
}

fn trash_restore_supported() -> bool {
    cfg!(any(
        target_os = "windows",
        all(
            unix,
            not(target_os = "macos"),
            not(target_os = "ios"),
            not(target_os = "android")
        )
    ))
}

#[cfg(windows)]
fn encode_os_string(value: &std::ffi::OsStr) -> String {
    use std::os::windows::ffi::OsStrExt;
    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
fn encode_os_string(value: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn is_cross_device(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::CrossesDevices
        || matches!(error.raw_os_error(), Some(17) | Some(18))
}

#[cfg(windows)]
fn windows_shell_path_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    const VERBATIM_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const UNC_PREFIX: &[u16] = &[b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];

    let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut shell_path = if let Some(remainder) = encoded.strip_prefix(VERBATIM_PREFIX) {
        if remainder.len() >= UNC_PREFIX.len()
            && remainder[..UNC_PREFIX.len()]
                .iter()
                .zip(UNC_PREFIX)
                .all(|(actual, expected)| {
                    actual == expected
                        || (*expected >= b'A' as u16
                            && *expected <= b'Z' as u16
                            && *actual == *expected + u16::from(b'a' - b'A'))
                })
        {
            let mut unc = vec![b'\\' as u16, b'\\' as u16];
            unc.extend_from_slice(&remainder[UNC_PREFIX.len()..]);
            unc
        } else {
            remainder.to_vec()
        }
    } else {
        encoded
    };
    shell_path.push(0);
    shell_path
}

#[cfg(windows)]
fn restore_windows_trash_item(item: &trash::TrashItem, original: &Path) -> OperationResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};
    use windows::Win32::UI::Shell::{
        FileOperation, IFileOperation, IShellItem, SHCreateItemFromParsingName, FOFX_EARLYFAILURE,
        FOF_NO_UI,
    };

    let parent = original.parent().ok_or_else(|| {
        OperationFailure::new("invalid_undo_receipt", "trash restore path has no parent")
    })?;
    let filename = original.file_name().ok_or_else(|| {
        OperationFailure::new(
            "invalid_undo_receipt",
            "trash restore path has no file name",
        )
    })?;
    let recycled = windows_shell_path_wide(Path::new(&item.id));
    let parent = windows_shell_path_wide(parent);
    let filename = filename
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        let operation: IFileOperation = CoCreateInstance(&FileOperation, None, CLSCTX_ALL)
            .map_err(|error| {
                OperationFailure::new(
                    "trash_restore_failed",
                    format!("could not create the Windows restore operation: {error}"),
                )
            })?;
        operation
            .SetOperationFlags(FOF_NO_UI | FOFX_EARLYFAILURE)
            .map_err(|error| {
                OperationFailure::new(
                    "trash_restore_failed",
                    format!("could not configure the Windows restore operation: {error}"),
                )
            })?;
        let recycled_item: IShellItem =
            SHCreateItemFromParsingName(PCWSTR(recycled.as_ptr()), None).map_err(|error| {
                OperationFailure::new(
                    "trash_restore_failed",
                    format!("could not open the recorded Recycle Bin item: {error}"),
                )
            })?;
        let destination: IShellItem = SHCreateItemFromParsingName(PCWSTR(parent.as_ptr()), None)
            .map_err(|error| {
                OperationFailure::new(
                    "trash_restore_failed",
                    format!("could not open the recorded restore directory: {error}"),
                )
            })?;
        operation
            .MoveItem(
                &recycled_item,
                &destination,
                PCWSTR(filename.as_ptr()),
                None,
            )
            .map_err(|error| {
                OperationFailure::new(
                    "trash_restore_failed",
                    format!("could not queue the Windows restore operation: {error}"),
                )
            })?;
        operation.PerformOperations().map_err(|error| {
            OperationFailure::new(
                "trash_restore_failed",
                format!("Windows Recycle Bin restore failed: {error}"),
            )
        })?;
        if operation
            .GetAnyOperationsAborted()
            .map_err(|error| {
                OperationFailure::new(
                    "trash_restore_failed",
                    format!("could not verify the Windows restore operation: {error}"),
                )
            })?
            .as_bool()
        {
            return Err(OperationFailure::new(
                "trash_restore_failed",
                "Windows aborted the Recycle Bin restore operation",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn rename_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVE_FILE_FLAGS};

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVE_FILE_FLAGS(0),
        )
    };
    result.map_err(|_| std::io::Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn rename_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn renamex_np(
            from: *const libc::c_char,
            to: *const libc::c_char,
            flags: libc::c_uint,
        ) -> libc::c_int;
    }
    const RENAME_EXCL: libc::c_uint = 0x0000_0004;
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "source contains NUL")
    })?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "destination contains NUL")
    })?;
    let result = unsafe { renamex_np(source.as_ptr(), destination.as_ptr(), RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn rename_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    if destination.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination exists",
        ));
    }
    fs::rename(source, destination)
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> SearchResult<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| SearchError::State(format!("{name} lock was poisoned")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn shell_paths_strip_verbatim_prefixes_without_losing_unicode() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let cases = [
            (
                Path::new("\\\\?\\C:\\tmp\\caf\u{00e9}"),
                OsString::from("C:\\tmp\\caf\u{00e9}"),
            ),
            (
                Path::new("\\\\?\\UNC\\server\\share\\caf\u{00e9}"),
                OsString::from("\\\\server\\share\\caf\u{00e9}"),
            ),
            (
                Path::new("C:\\tmp\\plain"),
                OsString::from("C:\\tmp\\plain"),
            ),
        ];
        for (input, expected) in cases {
            let encoded = windows_shell_path_wide(input);
            assert_eq!(encoded.last(), Some(&0));
            assert_eq!(OsString::from_wide(&encoded[..encoded.len() - 1]), expected);
        }
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    fn make_writable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn make_writable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn request(
        operation_id: Uuid,
        kind: FileOperationKind,
        sources: Vec<PathBuf>,
        destination: Option<PathBuf>,
        conflict_policy: FileConflictPolicy,
    ) -> FileOperationRequest {
        FileOperationRequest {
            operation_id,
            kind,
            sources: sources
                .into_iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect(),
            destination: destination.map(|path| path.to_string_lossy().to_string()),
            conflict_policy,
            confirmation_token: None,
            confirmed: true,
        }
    }

    fn run(plan: OperationPlan) -> FileOperationReceipt {
        let receipt = new_receipt(&plan, FileOperationState::Running, "running");
        execute_plan(
            plan,
            receipt,
            Arc::new(AtomicBool::new(false)),
            |_| {},
            |_| Ok(()),
        )
        .unwrap()
    }

    #[test]
    fn copy_uses_verified_staging_and_keep_both_without_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination_dir = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination_dir).unwrap();
        let source = source_dir.join("Résumé.txt");
        fs::write(&source, b"verified copy payload").unwrap();
        fs::write(destination_dir.join("Résumé.txt"), b"existing payload").unwrap();
        let request = request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source],
            Some(destination_dir.clone()),
            FileConflictPolicy::KeepBoth,
        );
        let plan = plan_operation(&request).unwrap();
        assert!(plan.items[0].conflict && plan.items[0].conflict_resolved);
        let receipt = run(plan);

        assert_eq!(receipt.state, FileOperationState::Complete);
        assert_eq!(
            fs::read(destination_dir.join("Résumé.txt")).unwrap(),
            b"existing payload"
        );
        assert_eq!(
            fs::read(destination_dir.join("Résumé (2).txt")).unwrap(),
            b"verified copy payload"
        );
        assert_eq!(receipt.undo_actions[0].kind, UndoActionKind::RemoveCreated);
    }

    #[test]
    fn move_undo_validates_identity_and_never_overwrites_a_new_source() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination_dir = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination_dir).unwrap();
        let source = source_dir.join("Clip.mov");
        fs::write(&source, b"move payload").unwrap();
        let operation_id = Uuid::new_v4();
        let receipt = run(plan_operation(&request(
            operation_id,
            FileOperationKind::Move,
            vec![source.clone()],
            Some(destination_dir.clone()),
            FileConflictPolicy::Fail,
        ))
        .unwrap());
        assert!(!source.exists());
        assert!(destination_dir.join("Clip.mov").exists());

        fs::write(&source, b"new source occupant").unwrap();
        let undone = execute_undo(
            FileOperationReceipt {
                state: FileOperationState::Undoing,
                progress: FileOperationProgress {
                    phase: "undoing".to_string(),
                    total_items: 1,
                    ..FileOperationProgress::default()
                },
                ..receipt
            },
            Arc::new(AtomicBool::new(false)),
            |_| {},
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(undone.state, FileOperationState::Failed);
        assert_eq!(undone.error_code.as_deref(), Some("undo_conflict"));
        assert_eq!(fs::read(&source).unwrap(), b"new source occupant");
        assert!(destination_dir.join("Clip.mov").exists());
    }

    #[test]
    fn pre_cancelled_copy_leaves_no_destination_or_staging_file() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination_dir = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination_dir).unwrap();
        let source = source_dir.join("Large.bin");
        fs::write(&source, vec![7_u8; 2 * COPY_BUFFER_BYTES]).unwrap();
        let plan = plan_operation(&request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source],
            Some(destination_dir.clone()),
            FileConflictPolicy::Fail,
        ))
        .unwrap();
        let receipt = new_receipt(&plan, FileOperationState::Running, "running");
        let cancellation = Arc::new(AtomicBool::new(true));
        let result = execute_plan(plan, receipt, cancellation, |_| {}, |_| Ok(())).unwrap();
        assert_eq!(result.state, FileOperationState::Cancelled);
        assert!(fs::read_dir(&destination_dir).unwrap().next().is_none());
    }

    #[test]
    fn nested_sources_and_unresolved_conflicts_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("Source");
        let child = source.join("Child.txt");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(&child, b"child").unwrap();
        let nested = request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source.clone(), child],
            Some(destination.clone()),
            FileConflictPolicy::Fail,
        );
        assert!(plan_operation(&nested).is_err());

        fs::create_dir(destination.join("Source")).unwrap();
        let conflict = request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source],
            Some(destination),
            FileConflictPolicy::Fail,
        );
        let plan = plan_operation(&conflict).unwrap();
        assert!(plan.public_preview().items[0].conflict);
        assert!(ensure_plan_can_execute(&plan).is_err());
    }

    #[test]
    fn rename_and_undo_complete_without_overwriting() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("Original.txt");
        let renamed = temp.path().join("Renamed.txt");
        fs::write(&source, b"rename payload").unwrap();
        let receipt = run(plan_operation(&request(
            Uuid::new_v4(),
            FileOperationKind::Rename,
            vec![source.clone()],
            Some(PathBuf::from("Renamed.txt")),
            FileConflictPolicy::Fail,
        ))
        .unwrap());
        assert!(!source.exists());
        assert_eq!(fs::read(&renamed).unwrap(), b"rename payload");

        let undone = execute_undo(
            FileOperationReceipt {
                state: FileOperationState::Undoing,
                completed_at: None,
                progress: FileOperationProgress {
                    phase: "undoing".to_string(),
                    total_items: 1,
                    ..FileOperationProgress::default()
                },
                ..receipt
            },
            Arc::new(AtomicBool::new(false)),
            |_| {},
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(undone.state, FileOperationState::Undone);
        assert_eq!(fs::read(&source).unwrap(), b"rename payload");
        assert!(!renamed.exists());
    }

    #[test]
    fn directory_copy_preserves_unicode_content_and_readonly_files() {
        let temp = tempfile::tempdir().unwrap();
        let source_parent = temp.path().join("Source");
        let source = source_parent.join("Folder");
        let destination = temp.path().join("Destination");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let name = "R\u{00e9}sum\u{00e9}.txt";
        let source_file = source.join(name);
        fs::write(&source_file, b"readonly unicode payload").unwrap();
        let mut permissions = fs::metadata(&source_file).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&source_file, permissions).unwrap();

        let receipt = run(plan_operation(&request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source.clone()],
            Some(destination.clone()),
            FileConflictPolicy::Fail,
        ))
        .unwrap());
        let copied_file = destination.join("Folder").join(name);
        assert_eq!(fs::read(&copied_file).unwrap(), b"readonly unicode payload");
        assert!(fs::metadata(&copied_file).unwrap().permissions().readonly());
        assert_eq!(receipt.state, FileOperationState::Complete);

        for path in [&source_file, &copied_file] {
            make_writable(path);
        }
    }

    #[test]
    fn changed_source_after_preview_fails_before_destination_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination).unwrap();
        let source = source_dir.join("Mutable.txt");
        fs::write(&source, b"before").unwrap();
        let plan = plan_operation(&request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source.clone()],
            Some(destination.clone()),
            FileConflictPolicy::Fail,
        ))
        .unwrap();
        fs::write(&source, b"changed and longer").unwrap();

        let receipt = run(plan);
        assert_eq!(receipt.state, FileOperationState::Failed);
        assert_eq!(receipt.error_code.as_deref(), Some("source_changed"));
        assert!(!destination.join("Mutable.txt").exists());
    }

    #[test]
    fn interrupted_owned_staging_is_removed_without_touching_other_files() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("Destination");
        fs::create_dir(&destination).unwrap();
        let operation_id = Uuid::new_v4();
        let stage = destination.join(format!(".spiffy-search-{operation_id}-0.partial"));
        let unrelated = destination.join("keep.partial");
        fs::write(&stage, b"owned partial").unwrap();
        fs::write(&unrelated, b"unrelated").unwrap();
        let receipt = FileOperationReceipt {
            operation_id,
            request_fingerprint: "b".repeat(64),
            kind: FileOperationKind::Copy,
            sources: vec![temp.path().join("Source.txt").to_string_lossy().to_string()],
            destination: Some(destination.to_string_lossy().to_string()),
            state: FileOperationState::Running,
            undo_actions: Vec::new(),
            progress: FileOperationProgress::default(),
            started_at: Utc::now(),
            completed_at: None,
            error_code: None,
            message: None,
        };
        assert_eq!(cleanup_interrupted_staging(&receipt).unwrap(), 1);
        assert!(!stage.exists());
        assert_eq!(fs::read(unrelated).unwrap(), b"unrelated");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manager_retries_completed_move_idempotently_and_rejects_id_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination).unwrap();
        let source = source_dir.join("Clip.mov");
        fs::write(&source, b"manager move payload").unwrap();
        let engine = crate::engine::SearchEngine::open_for_test(
            &temp.path().join("Runtime"),
            crate::config::SearchConfig::default(),
        )
        .unwrap();
        let runtime = Arc::new(engine.search_runtime().unwrap());
        let manager = Arc::new(FileOperationManager::default());
        let operation_id = Uuid::new_v4();
        let mut request = request(
            operation_id,
            FileOperationKind::Move,
            vec![source.clone()],
            Some(destination.clone()),
            FileConflictPolicy::Fail,
        );
        request.confirmation_token = Some(manager.preview(&request).unwrap().confirmation_token);
        manager
            .start(request.clone(), Arc::clone(&runtime))
            .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while manager.is_active() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!source.exists());
        assert!(destination.join("Clip.mov").exists());

        let retry = manager
            .start(request.clone(), Arc::clone(&runtime))
            .unwrap();
        assert!(!retry.active);
        assert_eq!(retry.receipt.state, FileOperationState::Complete);
        let mut reused = request;
        reused.kind = FileOperationKind::Copy;
        assert!(manager.start(reused, runtime).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manager_refuses_a_confirmation_after_the_source_changes() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination).unwrap();
        let source = source_dir.join("Preview.txt");
        fs::write(&source, b"preview version").unwrap();
        let engine = crate::engine::SearchEngine::open_for_test(
            &temp.path().join("Runtime"),
            crate::config::SearchConfig::default(),
        )
        .unwrap();
        let runtime = Arc::new(engine.search_runtime().unwrap());
        let manager = Arc::new(FileOperationManager::default());
        let mut request = request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source.clone()],
            Some(destination.clone()),
            FileConflictPolicy::Fail,
        );
        request.confirmation_token = Some(manager.preview(&request).unwrap().confirmation_token);
        fs::write(&source, b"replacement version with a different size").unwrap();

        let error = manager.start(request, runtime).unwrap_err();
        assert!(error.to_string().contains("confirmation token"));
        assert!(!destination.join("Preview.txt").exists());
    }

    #[test]
    fn staging_name_detection_requires_the_exact_owned_shape() {
        let operation_id = Uuid::new_v4();
        assert!(is_operation_staging_path(Path::new(&format!(
            ".spiffy-search-{operation_id}-12.partial"
        ))));
        assert!(!is_operation_staging_path(Path::new(
            ".spiffy-search-not-a-uuid-0.partial"
        )));
        assert!(!is_operation_staging_path(Path::new("keep.partial")));
    }

    #[test]
    fn receipt_intent_is_persisted_before_copy_commit() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination).unwrap();
        let source = source_dir.join("Journal.txt");
        let copied = destination.join("Journal.txt");
        fs::write(&source, b"journal payload").unwrap();
        let plan = plan_operation(&request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source],
            Some(destination),
            FileConflictPolicy::Fail,
        ))
        .unwrap();
        let receipt = new_receipt(&plan, FileOperationState::Running, "running");
        let intent_before_commit = Cell::new(false);
        let result = execute_plan(
            plan,
            receipt,
            Arc::new(AtomicBool::new(false)),
            |_| {},
            |receipt| {
                if !receipt.undo_actions.is_empty() && !copied.exists() {
                    intent_before_commit.set(true);
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result.state, FileOperationState::Complete);
        assert!(intent_before_commit.get());
        assert!(copied.exists());
    }

    #[test]
    fn failed_intent_persistence_prevents_filesystem_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("Source");
        let destination = temp.path().join("Destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination).unwrap();
        let source = source_dir.join("Blocked.txt");
        let copied = destination.join("Blocked.txt");
        fs::write(&source, b"must remain only at source").unwrap();
        let plan = plan_operation(&request(
            Uuid::new_v4(),
            FileOperationKind::Copy,
            vec![source.clone()],
            Some(destination.clone()),
            FileConflictPolicy::Fail,
        ))
        .unwrap();
        let receipt = new_receipt(&plan, FileOperationState::Running, "running");
        let result = execute_plan(
            plan,
            receipt,
            Arc::new(AtomicBool::new(false)),
            |_| {},
            |receipt| {
                if receipt.undo_actions.is_empty() {
                    Ok(())
                } else {
                    Err(SearchError::State("injected receipt outage".to_string()))
                }
            },
        )
        .unwrap();
        assert_eq!(result.state, FileOperationState::Failed);
        assert_eq!(result.error_code.as_deref(), Some("receipt_persist_failed"));
        assert!(source.exists());
        assert!(!copied.exists());
        assert!(fs::read_dir(destination).unwrap().next().is_none());
    }

    #[test]
    fn restart_reconciliation_keeps_committed_intent_and_drops_uncommitted_intent() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("Original.txt");
        let moved = temp.path().join("Moved.txt");
        fs::write(&original, b"move identity").unwrap();
        let identity = StableFileIdentity::from_path(&original).unwrap();
        rename_no_replace(&original, &moved).unwrap();
        let mut committed = FileOperationReceipt {
            operation_id: Uuid::new_v4(),
            request_fingerprint: "d".repeat(64),
            kind: FileOperationKind::Move,
            sources: vec![original.to_string_lossy().to_string()],
            destination: Some(temp.path().to_string_lossy().to_string()),
            state: FileOperationState::Running,
            undo_actions: vec![UndoAction {
                kind: UndoActionKind::MoveBack,
                item_index: 0,
                source: moved.to_string_lossy().to_string(),
                destination: Some(original.to_string_lossy().to_string()),
                expected_identity: Some(identity.clone()),
                expected_size: Some(13),
                trash_item_id: None,
                trash_deleted_at: None,
                undone: false,
            }],
            progress: FileOperationProgress {
                phase: "running".to_string(),
                total_items: 1,
                ..FileOperationProgress::default()
            },
            started_at: Utc::now(),
            completed_at: None,
            error_code: None,
            message: None,
        };
        reconcile_interrupted_actions(&mut committed);
        assert_eq!(committed.undo_actions.len(), 1);
        assert_eq!(committed.undo_actions[0].kind, UndoActionKind::MoveBack);

        let never_moved = temp.path().join("NeverMoved.txt");
        fs::write(&never_moved, b"still original").unwrap();
        let mut uncommitted = committed.clone();
        uncommitted.operation_id = Uuid::new_v4();
        uncommitted.sources = vec![never_moved.to_string_lossy().to_string()];
        uncommitted.undo_actions[0].source = temp
            .path()
            .join("MissingDestination.txt")
            .to_string_lossy()
            .to_string();
        uncommitted.undo_actions[0].destination = Some(never_moved.to_string_lossy().to_string());
        uncommitted.undo_actions[0].expected_identity =
            Some(StableFileIdentity::from_path(&never_moved).unwrap());
        uncommitted.undo_actions[0].expected_size = Some(14);
        reconcile_interrupted_actions(&mut uncommitted);
        assert!(uncommitted.undo_actions.is_empty());
        assert_eq!(fs::read(never_moved).unwrap(), b"still original");
    }
}
