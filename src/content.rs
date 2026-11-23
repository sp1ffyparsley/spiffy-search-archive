use crate::config::ContentConfig;
use crate::content_extractor::{
    supported_extension, ContentWorkerClient, ExtractedContent, ExtractionErrorCode,
    ExtractionFailure,
};
use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{
    ContentHighlight, ContentMatch, FileCategory, FileRecord, ItemKind, PreviewText,
};
use crate::query::{ParsedQuery, SearchMode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Write;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::Instant;
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{
    AllQuery, BooleanQuery, Occur, PhraseQuery, Query, RangeQuery, TermQuery, TermSetQuery,
};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TantivyDocument, Value, FAST, INDEXED, STORED, STRING, TEXT,
};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};
use tempfile::NamedTempFile;
use uuid::Uuid;

const CONTENT_INDEX_FORMAT_VERSION: u16 = 1;
const CONTENT_EXTRACTOR_VERSION: u16 = 1;
const OWNER_FILENAME: &str = ".spiffy-search-index-owner.json";
const MAX_CONTENT_BATCH_RECORDS: usize = 4096;
const MAX_CONTENT_CANDIDATES: usize = 10_000;
const MAX_CONTENT_REPORT_ITEMS: usize = 256;
const MAX_SNIPPET_CHARS: usize = 240;
const MAX_HIGHLIGHTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContentOwnerMarker {
    product: String,
    index: String,
    format_version: u16,
}

impl Default for ContentOwnerMarker {
    fn default() -> Self {
        Self {
            product: "spiffy-search".to_string(),
            index: "content".to_string(),
            format_version: CONTENT_INDEX_FORMAT_VERSION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentItemState {
    Indexed,
    Empty,
    Cached,
    Failed,
    Oversized,
    Excluded,
    Deleted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIndexItemReport {
    pub path: String,
    pub state: ContentItemState,
    pub extracted_bytes: u64,
    pub source_truncated: bool,
    pub error_code: Option<ExtractionErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIndexReport {
    pub requested: u64,
    pub indexed: u64,
    pub cached: u64,
    pub failed: u64,
    pub excluded: u64,
    pub deleted: u64,
    pub cancelled: u64,
    pub indexed_documents: u64,
    pub commit_opstamp: Option<u64>,
    pub elapsed_millis: u64,
    pub items: Vec<ContentIndexItemReport>,
}

impl ContentIndexReport {
    pub(crate) fn empty() -> Self {
        Self {
            requested: 0,
            indexed: 0,
            cached: 0,
            failed: 0,
            excluded: 0,
            deleted: 0,
            cancelled: 0,
            indexed_documents: 0,
            commit_opstamp: None,
            elapsed_millis: 0,
            items: Vec::new(),
        }
    }

    pub fn merge(&mut self, mut other: Self) {
        self.requested = self.requested.saturating_add(other.requested);
        self.indexed = self.indexed.saturating_add(other.indexed);
        self.cached = self.cached.saturating_add(other.cached);
        self.failed = self.failed.saturating_add(other.failed);
        self.excluded = self.excluded.saturating_add(other.excluded);
        self.deleted = self.deleted.saturating_add(other.deleted);
        self.cancelled = self.cancelled.saturating_add(other.cancelled);
        self.indexed_documents = other.indexed_documents;
        self.commit_opstamp = other.commit_opstamp.or(self.commit_opstamp);
        self.elapsed_millis = self.elapsed_millis.saturating_add(other.elapsed_millis);
        let remaining = MAX_CONTENT_REPORT_ITEMS.saturating_sub(self.items.len());
        self.items.extend(other.items.drain(..).take(remaining));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentCandidate {
    pub record: FileRecord,
    pub relevance: f64,
    pub content_match: ContentMatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentCandidateSearch {
    pub candidates: Vec<ContentCandidate>,
    pub total_candidates: u64,
    pub indexed_documents: u64,
    pub elapsed_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContentMetadata {
    extractor_version: u16,
    stable_key: String,
    normalized_path: String,
    source_size: u64,
    modified_time_millis: Option<i64>,
    digest: Option<String>,
    state: ContentItemState,
    source_truncated: bool,
    mime_type: String,
    error_code: Option<ExtractionErrorCode>,
    indexed_at_millis: i64,
}

#[derive(Clone)]
struct ContentFields {
    stable_key: Field,
    root_id: Field,
    normalized_path: Field,
    extension: Field,
    item_kind: Field,
    category: Field,
    size: Field,
    modified_time: Field,
    state: Field,
    content: Field,
    record_json: Field,
    metadata_json: Field,
}

struct ContentIndex {
    reader: IndexReader,
    writer: IndexWriter,
    fields: ContentFields,
}

#[derive(Clone)]
pub struct ContentSearchReader {
    reader: IndexReader,
    fields: ContentFields,
}

pub struct ContentService {
    config: ContentConfig,
    worker: ContentWorkerClient,
    path: PathBuf,
    index: Mutex<ContentIndex>,
    reader: ContentSearchReader,
}

impl ContentService {
    pub fn open_default(config: ContentConfig, writer_memory_mb: u16) -> SearchResult<Self> {
        let worker = ContentWorkerClient::discover()?;
        Self::open_internal(
            config,
            worker,
            &crate::config::content_index_path(),
            writer_memory_mb,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        path: &Path,
        config: ContentConfig,
        writer_memory_mb: u16,
    ) -> SearchResult<Self> {
        Self::open_internal(
            config,
            ContentWorkerClient::in_process(),
            path,
            writer_memory_mb,
        )
    }

    fn open_internal(
        config: ContentConfig,
        worker: ContentWorkerClient,
        path: &Path,
        writer_memory_mb: u16,
    ) -> SearchResult<Self> {
        config.validate()?;
        let index = ContentIndex::open(path, writer_memory_mb)?;
        let reader = index.search_reader();
        Ok(Self {
            config,
            worker,
            path: path.to_path_buf(),
            index: Mutex::new(index),
            reader,
        })
    }

    pub fn search_reader(&self) -> ContentSearchReader {
        self.reader.clone()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn document_count(&self) -> u64 {
        self.reader.document_count()
    }

    pub fn verify(&self) -> SearchResult<u64> {
        self.reader.verify()
    }

    pub fn delete_normalized_path(&self, normalized_path: &str) -> SearchResult<bool> {
        self.delete_normalized_paths(std::slice::from_ref(&normalized_path.to_string()))?;
        Ok(true)
    }

    pub fn delete_normalized_paths(&self, normalized_paths: &[String]) -> SearchResult<u64> {
        if normalized_paths.is_empty() {
            return Ok(self.document_count());
        }
        let mut index = lock(&self.index, "content index")?;
        for normalized_path in normalized_paths {
            index.delete_normalized_path(normalized_path)?;
        }
        Ok(index.commit()?.indexed_documents)
    }

    pub fn delete_root(&self, root_id: Uuid) -> SearchResult<u64> {
        let mut index = lock(&self.index, "content index")?;
        index.delete_root(root_id);
        Ok(index.commit()?.indexed_documents)
    }

    pub(crate) fn reconcile_root_paths(
        &self,
        root_id: Uuid,
        seen_paths: &HashSet<String>,
    ) -> SearchResult<ContentIndexReport> {
        let started = Instant::now();
        let mut report = ContentIndexReport::empty();
        let mut index = lock(&self.index, "content index")?;
        let stale_paths = index.stale_paths_for_root(root_id, seen_paths)?;
        if stale_paths.is_empty() {
            report.indexed_documents = index.reader.searcher().num_docs();
            report.elapsed_millis = elapsed_millis(started);
            return Ok(report);
        }
        for path in &stale_paths {
            if let Err(error) = index.delete_normalized_path(path) {
                let _ = index.rollback();
                return Err(error);
            }
        }
        let commit = index.commit()?;
        report.deleted = stale_paths.len() as u64;
        report.indexed_documents = commit.indexed_documents;
        report.commit_opstamp = Some(commit.opstamp);
        report.elapsed_millis = elapsed_millis(started);
        Ok(report)
    }

    pub(crate) fn tracks_record(&self, record: &FileRecord) -> bool {
        record.file && self.extension_enabled(&record.extension)
    }

    pub fn index_records(
        &self,
        records: Vec<FileRecord>,
        cancellation: Arc<AtomicBool>,
    ) -> SearchResult<ContentIndexReport> {
        let started = Instant::now();
        if records.len() > MAX_CONTENT_BATCH_RECORDS {
            return Err(SearchError::Content(format!(
                "content batch exceeds the {MAX_CONTENT_BATCH_RECORDS} record limit"
            )));
        }
        let mut unique = BTreeMap::new();
        for record in records {
            unique.insert(record.normalized_path.clone(), record);
        }
        let records = unique.into_values().collect::<Vec<_>>();
        let mut report = ContentIndexReport::empty();
        report.requested = records.len() as u64;
        if records.is_empty() {
            report.indexed_documents = self.document_count();
            return Ok(report);
        }

        let cached = lock(&self.index, "content index")?.cached_metadata(&records)?;
        let mut tasks = Vec::new();
        let mut item_reports = BTreeMap::new();
        let mut touched_index = false;
        for (sequence, record) in records.into_iter().enumerate() {
            if cancellation.load(Ordering::Acquire) {
                report.cancelled = report.cancelled.saturating_add(1);
                item_reports.insert(
                    sequence,
                    item_report(
                        &record,
                        ContentItemState::Cancelled,
                        0,
                        false,
                        Some(ExtractionErrorCode::Cancelled),
                    ),
                );
                continue;
            }
            if !record.file
                || record.missing
                || record.tombstone
                || !Path::new(&record.canonical_path).is_file()
            {
                let mut index = lock(&self.index, "content index")?;
                index.delete_normalized_path(&record.normalized_path)?;
                touched_index = true;
                report.deleted = report.deleted.saturating_add(1);
                item_reports.insert(
                    sequence,
                    item_report(&record, ContentItemState::Deleted, 0, false, None),
                );
                continue;
            }
            if !self.extension_enabled(&record.extension) {
                let mut index = lock(&self.index, "content index")?;
                index.delete_normalized_path(&record.normalized_path)?;
                touched_index = true;
                report.excluded = report.excluded.saturating_add(1);
                item_reports.insert(
                    sequence,
                    item_report(&record, ContentItemState::Excluded, 0, false, None),
                );
                continue;
            }
            if record.size > self.config.max_file_bytes {
                let failure = ExtractionFailure {
                    code: ExtractionErrorCode::Oversized,
                    message: "content source exceeds the configured file-size limit".to_string(),
                };
                lock(&self.index, "content index")?.upsert_failure(&record, &failure)?;
                touched_index = true;
                report.failed = report.failed.saturating_add(1);
                item_reports.insert(
                    sequence,
                    item_report(
                        &record,
                        ContentItemState::Oversized,
                        0,
                        false,
                        Some(ExtractionErrorCode::Oversized),
                    ),
                );
                continue;
            }
            if cached
                .get(&record.normalized_path)
                .is_some_and(|metadata| cache_matches(metadata, &record))
            {
                let metadata = &cached[&record.normalized_path];
                report.cached = report.cached.saturating_add(1);
                item_reports.insert(
                    sequence,
                    item_report(
                        &record,
                        ContentItemState::Cached,
                        0,
                        metadata.source_truncated,
                        metadata.error_code.clone(),
                    ),
                );
                continue;
            }
            tasks.push((sequence, record));
        }

        if !tasks.is_empty() {
            let task_count = tasks.len();
            let tasks = Arc::new(tasks);
            let next = Arc::new(AtomicUsize::new(0));
            let channel_capacity = usize::from(self.config.workers).saturating_mul(2).max(2);
            let (sender, receiver) = mpsc::sync_channel(channel_capacity);
            let worker_count = usize::from(self.config.workers).min(task_count).max(1);
            let mut processing_error = None;
            std::thread::scope(|scope| {
                for _ in 0..worker_count {
                    let sender = sender.clone();
                    let tasks = Arc::clone(&tasks);
                    let next = Arc::clone(&next);
                    let cancellation = Arc::clone(&cancellation);
                    let worker = self.worker.clone();
                    let config = self.config.clone();
                    scope.spawn(move || loop {
                        let index = next.fetch_add(1, Ordering::AcqRel);
                        let Some((sequence, record)) = tasks.get(index) else {
                            break;
                        };
                        let result = worker.extract(
                            Path::new(&record.canonical_path),
                            &config,
                            Arc::clone(&cancellation),
                        );
                        if sender.send((*sequence, record.clone(), result)).is_err() {
                            break;
                        }
                    });
                }
                drop(sender);
                let mut received = 0_usize;
                while let Ok((sequence, record, result)) = receiver.recv() {
                    received = received.saturating_add(1);
                    if processing_error.is_none() {
                        match self.apply_extraction_result(&record, result) {
                            Ok((item, indexed, failed, cancelled)) => {
                                touched_index |= indexed || failed;
                                report.indexed = report.indexed.saturating_add(u64::from(indexed));
                                report.failed = report.failed.saturating_add(u64::from(failed));
                                report.cancelled =
                                    report.cancelled.saturating_add(u64::from(cancelled));
                                item_reports.insert(sequence, item);
                            }
                            Err(error) => processing_error = Some(error),
                        }
                    }
                }
                if received != task_count && processing_error.is_none() {
                    processing_error = Some(SearchError::State(
                        "content worker pool ended before every task returned".to_string(),
                    ));
                }
            });
            if let Some(error) = processing_error {
                lock(&self.index, "content index")?.rollback()?;
                return Err(error);
            }
        }

        if touched_index {
            let commit = lock(&self.index, "content index")?.commit()?;
            report.indexed_documents = commit.indexed_documents;
            report.commit_opstamp = Some(commit.opstamp);
        } else {
            report.indexed_documents = self.document_count();
        }
        report.items = item_reports
            .into_values()
            .take(MAX_CONTENT_REPORT_ITEMS)
            .collect();
        report.elapsed_millis = elapsed_millis(started);
        Ok(report)
    }

    fn extension_enabled(&self, extension: &str) -> bool {
        supported_extension(extension)
            && self
                .config
                .extensions
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(extension))
    }

    fn apply_extraction_result(
        &self,
        record: &FileRecord,
        result: Result<ExtractedContent, ExtractionFailure>,
    ) -> SearchResult<(ContentIndexItemReport, bool, bool, bool)> {
        match result {
            Ok(extracted) => {
                let state = if extracted.text.is_empty() {
                    ContentItemState::Empty
                } else {
                    ContentItemState::Indexed
                };
                lock(&self.index, "content index")?.upsert_success(record, &extracted, state)?;
                Ok((
                    item_report(
                        record,
                        state,
                        extracted.text.len() as u64,
                        extracted.truncated,
                        None,
                    ),
                    true,
                    false,
                    false,
                ))
            }
            Err(failure) if failure.code == ExtractionErrorCode::Cancelled => Ok((
                item_report(
                    record,
                    ContentItemState::Cancelled,
                    0,
                    false,
                    Some(ExtractionErrorCode::Cancelled),
                ),
                false,
                false,
                true,
            )),
            Err(failure) if failure.code == ExtractionErrorCode::Missing => {
                lock(&self.index, "content index")?
                    .delete_normalized_path(&record.normalized_path)?;
                Ok((
                    item_report(record, ContentItemState::Deleted, 0, false, None),
                    true,
                    false,
                    false,
                ))
            }
            Err(failure) if systemic_worker_failure(&failure.code) => Err(SearchError::Content(
                format!("isolated content worker failed: {}", failure.message),
            )),
            Err(failure) => {
                let state = if failure.code == ExtractionErrorCode::Oversized {
                    ContentItemState::Oversized
                } else {
                    ContentItemState::Failed
                };
                lock(&self.index, "content index")?.upsert_failure(record, &failure)?;
                Ok((
                    item_report(record, state, 0, false, Some(failure.code)),
                    false,
                    true,
                    false,
                ))
            }
        }
    }
}

impl ContentIndex {
    fn open(path: &Path, writer_memory_mb: u16) -> SearchResult<Self> {
        if !(32..=1024).contains(&writer_memory_mb) {
            return Err(SearchError::Config(
                "content index writer memory must be between 32 and 1024 MiB".to_string(),
            ));
        }
        let schema = build_schema();
        let index = open_or_create_owned(path, &schema)?;
        if index.schema() != schema {
            return Self::finish_open(
                path,
                repair_owned_index(path, &schema, "schema_mismatch")?,
                writer_memory_mb,
            );
        }
        Self::finish_open(path, index, writer_memory_mb)
    }

    fn finish_open(_path: &Path, index: Index, writer_memory_mb: u16) -> SearchResult<Self> {
        let fields = fields_from_schema(&index.schema())?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        let memory_bytes = usize::from(writer_memory_mb)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| SearchError::Config("content writer memory overflowed".to_string()))?;
        let writer = index.writer_with_num_threads(1, memory_bytes)?;
        Ok(Self {
            reader,
            writer,
            fields,
        })
    }

    fn search_reader(&self) -> ContentSearchReader {
        ContentSearchReader {
            reader: self.reader.clone(),
            fields: self.fields.clone(),
        }
    }

    fn cached_metadata(
        &self,
        records: &[FileRecord],
    ) -> SearchResult<BTreeMap<String, ContentMetadata>> {
        self.reader.reload()?;
        let searcher = self.reader.searcher();
        let mut output = BTreeMap::new();
        for record in records {
            let query = TermQuery::new(
                Term::from_field_text(self.fields.normalized_path, &record.normalized_path),
                IndexRecordOption::Basic,
            );
            if let Some((_score, address)) = searcher
                .search(&query, &TopDocs::with_limit(1).order_by_score())?
                .into_iter()
                .next()
            {
                let document: TantivyDocument = searcher.doc(address)?;
                let metadata = stored_json::<ContentMetadata>(
                    &document,
                    self.fields.metadata_json,
                    "content metadata",
                )?;
                output.insert(record.normalized_path.clone(), metadata);
            }
        }
        Ok(output)
    }

    fn stale_paths_for_root(
        &mut self,
        root_id: Uuid,
        seen_paths: &HashSet<String>,
    ) -> SearchResult<Vec<String>> {
        self.reader.reload()?;
        let searcher = self.reader.searcher();
        let query = TermQuery::new(
            Term::from_field_text(self.fields.root_id, &root_id.to_string()),
            IndexRecordOption::Basic,
        );
        let total = searcher.search(&query, &Count)?;
        if total == 0 {
            return Ok(Vec::new());
        }
        let documents = searcher.search(&query, &TopDocs::with_limit(total).order_by_score())?;
        let mut stale_paths = Vec::new();
        for (_score, address) in documents {
            let document: TantivyDocument = searcher.doc(address)?;
            let record = stored_json::<FileRecord>(
                &document,
                self.fields.record_json,
                "content file record",
            )?;
            if record.root_id != root_id {
                return Err(SearchError::Index(format!(
                    "content root term disagrees with stored record for {}",
                    record.display_path
                )));
            }
            if !seen_paths.contains(&record.normalized_path) {
                stale_paths.push(record.normalized_path);
            }
        }
        Ok(stale_paths)
    }

    fn upsert_success(
        &mut self,
        record: &FileRecord,
        extracted: &ExtractedContent,
        state: ContentItemState,
    ) -> SearchResult<()> {
        let metadata = ContentMetadata {
            extractor_version: CONTENT_EXTRACTOR_VERSION,
            stable_key: record.stable_key.clone(),
            normalized_path: record.normalized_path.clone(),
            source_size: extracted.source_size,
            modified_time_millis: extracted.modified_time_millis,
            digest: Some(extracted.digest.clone()),
            state,
            source_truncated: extracted.truncated,
            mime_type: extracted.mime_type.clone(),
            error_code: None,
            indexed_at_millis: Utc::now().timestamp_millis(),
        };
        self.upsert(record, &metadata, &extracted.text)
    }

    fn upsert_failure(
        &mut self,
        record: &FileRecord,
        failure: &ExtractionFailure,
    ) -> SearchResult<()> {
        let state = if failure.code == ExtractionErrorCode::Oversized {
            ContentItemState::Oversized
        } else {
            ContentItemState::Failed
        };
        let metadata = ContentMetadata {
            extractor_version: CONTENT_EXTRACTOR_VERSION,
            stable_key: record.stable_key.clone(),
            normalized_path: record.normalized_path.clone(),
            source_size: record.size,
            modified_time_millis: record.modified_time.map(|value| value.timestamp_millis()),
            digest: None,
            state,
            source_truncated: false,
            mime_type: record.mime_type.clone(),
            error_code: Some(failure.code.clone()),
            indexed_at_millis: Utc::now().timestamp_millis(),
        };
        self.upsert(record, &metadata, "")
    }

    fn upsert(
        &mut self,
        record: &FileRecord,
        metadata: &ContentMetadata,
        content: &str,
    ) -> SearchResult<()> {
        self.delete_normalized_path(&record.normalized_path)?;
        self.writer.delete_term(Term::from_field_text(
            self.fields.stable_key,
            &record.stable_key,
        ));
        let mut stored_record = record.clone();
        stored_record.content_index_state = content_state_name(metadata.state).to_string();
        let mut document = TantivyDocument::new();
        document.add_text(self.fields.stable_key, &stored_record.stable_key);
        document.add_text(self.fields.root_id, stored_record.root_id.to_string());
        document.add_text(self.fields.normalized_path, &stored_record.normalized_path);
        document.add_text(self.fields.extension, &stored_record.extension);
        document.add_text(
            self.fields.item_kind,
            item_kind_name(stored_record.item_kind),
        );
        document.add_text(self.fields.category, category_name(stored_record.category));
        document.add_u64(self.fields.size, stored_record.size);
        document.add_i64(
            self.fields.modified_time,
            stored_record
                .modified_time
                .map(|value| value.timestamp_millis())
                .unwrap_or(i64::MIN),
        );
        document.add_text(self.fields.state, content_state_name(metadata.state));
        document.add_text(self.fields.content, content);
        document.add_text(
            self.fields.record_json,
            serde_json::to_string(&stored_record)?,
        );
        document.add_text(self.fields.metadata_json, serde_json::to_string(metadata)?);
        self.writer.add_document(document)?;
        Ok(())
    }

    fn delete_normalized_path(&mut self, normalized_path: &str) -> SearchResult<()> {
        if normalized_path.is_empty() || normalized_path.len() > 32_768 {
            return Err(SearchError::Index(
                "content normalized path is invalid".to_string(),
            ));
        }
        self.writer.delete_term(Term::from_field_text(
            self.fields.normalized_path,
            normalized_path,
        ));
        Ok(())
    }

    fn delete_root(&mut self, root_id: Uuid) {
        self.writer.delete_term(Term::from_field_text(
            self.fields.root_id,
            &root_id.to_string(),
        ));
    }

    fn commit(&mut self) -> SearchResult<ContentCommit> {
        let opstamp = self.writer.commit()?;
        self.reader.reload()?;
        Ok(ContentCommit {
            opstamp,
            indexed_documents: self.reader.searcher().num_docs(),
        })
    }

    fn rollback(&mut self) -> SearchResult<()> {
        self.writer.rollback()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ContentCommit {
    opstamp: u64,
    indexed_documents: u64,
}

impl ContentSearchReader {
    pub fn document_count(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    pub fn verify(&self) -> SearchResult<u64> {
        self.reader.reload()?;
        let count = self.reader.searcher().search(&AllQuery, &Count)?;
        u64::try_from(count)
            .map_err(|_| SearchError::Index("content document count exceeds u64".to_string()))
    }

    pub fn preview_text(
        &self,
        stable_key: &str,
        max_chars: u32,
    ) -> SearchResult<Option<PreviewText>> {
        if stable_key.is_empty()
            || stable_key.len() > 512
            || stable_key.contains('\0')
            || !(1..=65_536).contains(&max_chars)
        {
            return Err(SearchError::Content(
                "preview stable key or character limit is invalid".to_string(),
            ));
        }
        self.reader.reload()?;
        let query = TermQuery::new(
            Term::from_field_text(self.fields.stable_key, stable_key),
            IndexRecordOption::Basic,
        );
        let searcher = self.reader.searcher();
        let documents = searcher.search(&query, &TopDocs::with_limit(2).order_by_score())?;
        if documents.len() > 1 {
            return Err(SearchError::Index(format!(
                "stable key resolves to multiple content records: {stable_key}"
            )));
        }
        let Some((_, address)) = documents.into_iter().next() else {
            return Ok(None);
        };
        let document: TantivyDocument = searcher.doc(address)?;
        let metadata = stored_json::<ContentMetadata>(
            &document,
            self.fields.metadata_json,
            "content metadata",
        )?;
        if metadata.state != ContentItemState::Indexed {
            return Ok(None);
        }
        let content = document
            .get_first(self.fields.content)
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                SearchError::Index("content record is missing stored text".to_string())
            })?;
        let boundary = content
            .char_indices()
            .nth(max_chars as usize)
            .map(|(index, _)| index);
        Ok(Some(PreviewText {
            stable_key: stable_key.to_string(),
            text: boundary
                .map_or(content, |index| &content[..index])
                .to_string(),
            truncated: boundary.is_some(),
        }))
    }

    pub fn search(
        &self,
        query: &ParsedQuery,
        limit: usize,
    ) -> SearchResult<ContentCandidateSearch> {
        self.search_in_roots(query, limit, None)
    }

    pub fn search_in_roots(
        &self,
        query: &ParsedQuery,
        limit: usize,
        allowed_root_ids: Option<&BTreeSet<Uuid>>,
    ) -> SearchResult<ContentCandidateSearch> {
        let started = Instant::now();
        self.reader.reload()?;
        let indexed_documents = self.document_count();
        if query.mode != SearchMode::Content {
            return Ok(ContentCandidateSearch {
                candidates: Vec::new(),
                total_candidates: 0,
                indexed_documents,
                elapsed_micros: elapsed_micros(started),
            });
        }
        let limit = limit.clamp(1, MAX_CONTENT_CANDIDATES);
        let tantivy_query = build_content_query(&self.fields, query, allowed_root_ids);
        let searcher = self.reader.searcher();
        let total = searcher.search(tantivy_query.as_ref(), &Count)?;
        let top_docs = searcher.search(
            tantivy_query.as_ref(),
            &TopDocs::with_limit(limit.saturating_mul(2).min(MAX_CONTENT_CANDIDATES))
                .order_by_score(),
        )?;
        let mut candidates = Vec::with_capacity(limit.min(top_docs.len()));
        for (score, address) in top_docs {
            let document: TantivyDocument = searcher.doc(address)?;
            let record = stored_json::<FileRecord>(
                &document,
                self.fields.record_json,
                "content file record",
            )?;
            if !Path::new(&record.canonical_path).is_file()
                || !record_matches_metadata(&record, query)
            {
                continue;
            }
            let metadata = stored_json::<ContentMetadata>(
                &document,
                self.fields.metadata_json,
                "content metadata",
            )?;
            let content = document
                .get_first(self.fields.content)
                .and_then(|value| value.as_str())
                .ok_or_else(|| SearchError::Index("content text is missing".to_string()))?;
            candidates.push(ContentCandidate {
                record,
                relevance: f64::from(score),
                content_match: build_content_match(content, query, metadata.source_truncated),
            });
            if candidates.len() >= limit {
                break;
            }
        }
        Ok(ContentCandidateSearch {
            candidates,
            total_candidates: u64::try_from(total).map_err(|_| {
                SearchError::Index("content candidate count exceeds u64".to_string())
            })?,
            indexed_documents,
            elapsed_micros: elapsed_micros(started),
        })
    }
}

fn build_schema() -> Schema {
    let mut builder = Schema::builder();
    builder.add_text_field("stable_key", STRING);
    builder.add_text_field("root_id", STRING);
    builder.add_text_field("normalized_path", STRING);
    builder.add_text_field("extension", STRING);
    builder.add_text_field("item_kind", STRING);
    builder.add_text_field("category", STRING);
    builder.add_u64_field("size", INDEXED | FAST);
    builder.add_i64_field("modified_time", INDEXED | FAST);
    builder.add_text_field("state", STRING);
    builder.add_text_field("content", TEXT | STORED);
    builder.add_text_field("record_json", STORED);
    builder.add_text_field("metadata_json", STORED);
    builder.build()
}

fn fields_from_schema(schema: &Schema) -> SearchResult<ContentFields> {
    Ok(ContentFields {
        stable_key: field(schema, "stable_key")?,
        root_id: field(schema, "root_id")?,
        normalized_path: field(schema, "normalized_path")?,
        extension: field(schema, "extension")?,
        item_kind: field(schema, "item_kind")?,
        category: field(schema, "category")?,
        size: field(schema, "size")?,
        modified_time: field(schema, "modified_time")?,
        state: field(schema, "state")?,
        content: field(schema, "content")?,
        record_json: field(schema, "record_json")?,
        metadata_json: field(schema, "metadata_json")?,
    })
}

fn field(schema: &Schema, name: &str) -> SearchResult<Field> {
    schema
        .get_field(name)
        .map_err(|_| SearchError::Index(format!("content index is missing field '{name}'")))
}

fn build_content_query(
    fields: &ContentFields,
    parsed: &ParsedQuery,
    allowed_root_ids: Option<&BTreeSet<Uuid>>,
) -> Box<dyn Query> {
    let mut clauses: Vec<(Occur, Box<dyn Query>)> = vec![(
        Occur::Must,
        Box::new(TermQuery::new(
            Term::from_field_text(fields.state, "indexed"),
            IndexRecordOption::Basic,
        )),
    )];
    if let Some(root_ids) = allowed_root_ids {
        let terms: Vec<Term> = root_ids
            .iter()
            .map(|root_id| Term::from_field_text(fields.root_id, &root_id.to_string()))
            .collect();
        clauses.push((Occur::Must, Box::new(TermSetQuery::new(terms))));
    }
    for term in &parsed.terms {
        for token in analyzed_tokens(term) {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_text(fields.content, &token),
                    IndexRecordOption::WithFreqsAndPositions,
                )),
            ));
        }
    }
    for phrase in &parsed.exact_phrases {
        let terms = analyzed_tokens(phrase)
            .into_iter()
            .map(|token| Term::from_field_text(fields.content, &token))
            .collect::<Vec<_>>();
        if terms.len() == 1 {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    terms[0].clone(),
                    IndexRecordOption::WithFreqsAndPositions,
                )),
            ));
        } else if !terms.is_empty() {
            clauses.push((Occur::Must, Box::new(PhraseQuery::new(terms))));
        }
    }
    for excluded in &parsed.excluded_terms {
        for token in analyzed_tokens(excluded) {
            clauses.push((
                Occur::MustNot,
                Box::new(TermQuery::new(
                    Term::from_field_text(fields.content, &token),
                    IndexRecordOption::Basic,
                )),
            ));
        }
    }
    add_term_set_filter(
        &mut clauses,
        fields.extension,
        parsed.extensions.iter().cloned(),
        Occur::Must,
    );
    add_term_set_filter(
        &mut clauses,
        fields.extension,
        parsed.excluded_extensions.iter().cloned(),
        Occur::MustNot,
    );
    add_term_set_filter(
        &mut clauses,
        fields.item_kind,
        parsed
            .kinds
            .iter()
            .map(|kind| item_kind_name(*kind).to_string()),
        Occur::Must,
    );
    add_term_set_filter(
        &mut clauses,
        fields.category,
        parsed
            .categories
            .iter()
            .map(|category| category_name(*category).to_string()),
        Occur::Must,
    );
    if let Some(range) = &parsed.size_range {
        clauses.push((
            Occur::Must,
            Box::new(RangeQuery::new(
                range
                    .min_inclusive
                    .map(|value| Bound::Included(Term::from_field_u64(fields.size, value)))
                    .unwrap_or(Bound::Unbounded),
                range
                    .max_exclusive
                    .map(|value| Bound::Excluded(Term::from_field_u64(fields.size, value)))
                    .unwrap_or(Bound::Unbounded),
            )),
        ));
    }
    if let Some(range) = &parsed.date_range {
        clauses.push((
            Occur::Must,
            Box::new(RangeQuery::new(
                range
                    .start
                    .map(|value| {
                        Bound::Included(Term::from_field_i64(
                            fields.modified_time,
                            value.timestamp_millis(),
                        ))
                    })
                    .unwrap_or(Bound::Unbounded),
                range
                    .end_exclusive
                    .map(|value| {
                        Bound::Excluded(Term::from_field_i64(
                            fields.modified_time,
                            value.timestamp_millis(),
                        ))
                    })
                    .unwrap_or(Bound::Unbounded),
            )),
        ));
    }
    Box::new(BooleanQuery::new(clauses))
}

fn analyzed_tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn add_term_set_filter(
    clauses: &mut Vec<(Occur, Box<dyn Query>)>,
    field: Field,
    values: impl IntoIterator<Item = String>,
    occur: Occur,
) {
    let terms = values
        .into_iter()
        .map(|value| Term::from_field_text(field, &value))
        .collect::<Vec<_>>();
    if !terms.is_empty() {
        clauses.push((occur, Box::new(TermSetQuery::new(terms))));
    }
}

fn record_matches_metadata(record: &FileRecord, query: &ParsedQuery) -> bool {
    if record.missing
        || record.tombstone
        || (!query.extensions.is_empty() && !query.extensions.contains(&record.extension))
        || query.excluded_extensions.contains(&record.extension)
        || (!query.kinds.is_empty() && !query.kinds.contains(&record.item_kind))
        || (!query.categories.is_empty() && !query.categories.contains(&record.category))
    {
        return false;
    }
    if query.excluded_folders.iter().any(|folder| {
        record
            .parent_path
            .to_lowercase()
            .contains(&folder.to_lowercase())
    }) {
        return false;
    }
    if !query.paths.is_empty()
        && !query.paths.iter().any(|path| {
            record
                .normalized_path
                .to_lowercase()
                .contains(&path.replace('\\', "/").to_lowercase())
        })
    {
        return false;
    }
    if !query.drives.is_empty() {
        let drive = record
            .normalized_path
            .chars()
            .next()
            .map(|value| value.to_ascii_lowercase().to_string());
        if drive
            .as_ref()
            .is_none_or(|drive| !query.drives.contains(drive))
        {
            return false;
        }
    }
    if !query.devices.is_empty()
        && !query.devices.iter().any(|device| {
            device.eq_ignore_ascii_case(&record.device_id.to_string())
                || record
                    .remote_device
                    .as_ref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(device))
        })
    {
        return false;
    }
    if !query.libraries.is_empty()
        && !query.libraries.iter().any(|library| {
            record
                .tags
                .iter()
                .any(|tag| tag.eq_ignore_ascii_case(library))
        })
    {
        return false;
    }
    if let Some(range) = &query.size_range {
        if range
            .min_inclusive
            .is_some_and(|minimum| record.size < minimum)
            || range
                .max_exclusive
                .is_some_and(|maximum| record.size >= maximum)
        {
            return false;
        }
    }
    if let Some(range) = &query.date_range {
        let Some(modified) = record.modified_time else {
            return false;
        };
        if range.start.is_some_and(|start| modified < start)
            || range.end_exclusive.is_some_and(|end| modified >= end)
        {
            return false;
        }
    }
    !query.remote_only || record.remote_device.is_some()
}

fn build_content_match(content: &str, query: &ParsedQuery, source_truncated: bool) -> ContentMatch {
    let mut needles = query
        .exact_phrases
        .iter()
        .chain(query.terms.iter())
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    needles.sort_by_key(|value| std::cmp::Reverse(value.chars().count()));
    needles.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    let lowered = content.to_ascii_lowercase();
    let first_match = needles
        .iter()
        .filter_map(|needle| lowered.find(&needle.to_ascii_lowercase()))
        .min()
        .unwrap_or(0);
    let boundaries = content
        .char_indices()
        .map(|(byte, _)| byte)
        .chain(std::iter::once(content.len()))
        .collect::<Vec<_>>();
    let match_char = boundaries.partition_point(|byte| *byte < first_match);
    let start_char = match_char.saturating_sub(MAX_SNIPPET_CHARS / 3);
    let end_char = (start_char + MAX_SNIPPET_CHARS).min(boundaries.len().saturating_sub(1));
    let start_byte = boundaries[start_char];
    let end_byte = boundaries[end_char];
    let snippet = content[start_byte..end_byte].to_string();
    let snippet_lower = snippet.to_ascii_lowercase();
    let mut ranges = BTreeSet::new();
    for needle in needles {
        let needle_lower = needle.to_ascii_lowercase();
        let mut offset = 0_usize;
        while offset < snippet_lower.len() && ranges.len() < MAX_HIGHLIGHTS {
            let Some(found) = snippet_lower[offset..].find(&needle_lower) else {
                break;
            };
            let byte_start = offset + found;
            let byte_end = byte_start + needle_lower.len();
            if snippet.is_char_boundary(byte_start) && snippet.is_char_boundary(byte_end) {
                ranges.insert((
                    snippet[..byte_start].chars().count(),
                    snippet[..byte_end].chars().count(),
                ));
            }
            offset = byte_end.max(offset + 1);
        }
    }
    ContentMatch {
        snippet,
        highlights: ranges
            .into_iter()
            .take(MAX_HIGHLIGHTS)
            .map(|(start, end)| ContentHighlight {
                start: u32::try_from(start).unwrap_or(u32::MAX),
                end: u32::try_from(end).unwrap_or(u32::MAX),
            })
            .collect(),
        source_truncated,
    }
}

fn cache_matches(metadata: &ContentMetadata, record: &FileRecord) -> bool {
    metadata.extractor_version == CONTENT_EXTRACTOR_VERSION
        && metadata.stable_key == record.stable_key
        && metadata.normalized_path == record.normalized_path
        && metadata.source_size == record.size
        && metadata.modified_time_millis
            == record.modified_time.map(|value| value.timestamp_millis())
        && metadata
            .error_code
            .as_ref()
            .is_none_or(|code| !transient_item_failure(code))
}

fn systemic_worker_failure(code: &ExtractionErrorCode) -> bool {
    matches!(
        code,
        ExtractionErrorCode::WorkerUnavailable
            | ExtractionErrorCode::WorkerProtocol
            | ExtractionErrorCode::WorkerCrashed
    )
}

fn transient_item_failure(code: &ExtractionErrorCode) -> bool {
    systemic_worker_failure(code)
        || matches!(
            code,
            ExtractionErrorCode::Io
                | ExtractionErrorCode::Timeout
                | ExtractionErrorCode::Missing
                | ExtractionErrorCode::Cancelled
        )
}

fn item_report(
    record: &FileRecord,
    state: ContentItemState,
    extracted_bytes: u64,
    source_truncated: bool,
    error_code: Option<ExtractionErrorCode>,
) -> ContentIndexItemReport {
    ContentIndexItemReport {
        path: record.display_path.clone(),
        state,
        extracted_bytes,
        source_truncated,
        error_code,
    }
}

fn stored_json<T: for<'de> Deserialize<'de>>(
    document: &TantivyDocument,
    field: Field,
    label: &str,
) -> SearchResult<T> {
    let encoded = document
        .get_first(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| SearchError::Index(format!("{label} is missing")))?;
    serde_json::from_str(encoded)
        .map_err(|error| SearchError::Index(format!("{label} is invalid: {error}")))
}

fn content_state_name(state: ContentItemState) -> &'static str {
    match state {
        ContentItemState::Indexed => "indexed",
        ContentItemState::Empty => "empty",
        ContentItemState::Cached => "cached",
        ContentItemState::Failed => "failed",
        ContentItemState::Oversized => "oversized",
        ContentItemState::Excluded => "excluded",
        ContentItemState::Deleted => "deleted",
        ContentItemState::Cancelled => "cancelled",
    }
}

fn item_kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::File => "file",
        ItemKind::Folder => "folder",
        ItemKind::Application => "application",
        ItemKind::Window => "window",
        ItemKind::Content => "content",
        ItemKind::Clipboard => "clipboard",
        ItemKind::Browser => "browser",
        ItemKind::Shelf => "shelf",
    }
}

fn category_name(category: FileCategory) -> &'static str {
    match category {
        FileCategory::Document => "document",
        FileCategory::Image => "image",
        FileCategory::Video => "video",
        FileCategory::Audio => "audio",
        FileCategory::Archive => "archive",
        FileCategory::Code => "code",
        FileCategory::Other => "other",
    }
}

fn open_or_create_owned(path: &Path, schema: &Schema) -> SearchResult<Index> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
        let index = Index::create_in_dir(path, schema.clone())?;
        write_owner_marker(path)?;
        return Ok(index);
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SearchError::Index(format!(
            "content index path is not a normal directory: {}",
            path.display()
        )));
    }
    if path.join("meta.json").is_file() {
        return match Index::open_in_dir(path) {
            Ok(index) => Ok(index),
            Err(error) if valid_owner_marker(path) => {
                repair_owned_index(path, schema, &format!("open_failed:{error}"))
            }
            Err(error) => Err(SearchError::Index(format!(
                "could not open unowned content index at {}: {error}",
                path.display()
            ))),
        };
    }
    if fs::read_dir(path)
        .map_err(|error| io_error(path, error))?
        .next()
        .is_none()
    {
        let index = Index::create_in_dir(path, schema.clone())?;
        write_owner_marker(path)?;
        return Ok(index);
    }
    if valid_owner_marker(path) {
        repair_owned_index(path, schema, "missing_meta")
    } else {
        Err(SearchError::Index(format!(
            "refusing to replace nonempty unowned content index directory: {}",
            path.display()
        )))
    }
}

fn repair_owned_index(path: &Path, schema: &Schema, reason: &str) -> SearchResult<Index> {
    if !valid_owner_marker(path) {
        return Err(SearchError::Index(format!(
            "refusing to rebuild content index without a valid owner marker: {}",
            path.display()
        )));
    }
    #[cfg(not(test))]
    if path != crate::config::content_index_path() {
        return Err(SearchError::Index(format!(
            "refusing to rebuild content index outside the Search data owner: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SearchError::Index(
            "refusing to rebuild a symlink or non-directory content index".to_string(),
        ));
    }
    tracing::warn!(reason, index = %path.display(), "rebuilding reproducible content index");
    fs::remove_dir_all(path).map_err(|error| io_error(path, error))?;
    fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
    let index = Index::create_in_dir(path, schema.clone())?;
    write_owner_marker(path)?;
    Ok(index)
}

fn write_owner_marker(path: &Path) -> SearchResult<()> {
    let encoded = serde_json::to_vec_pretty(&ContentOwnerMarker::default())?;
    let mut temporary = NamedTempFile::new_in(path).map_err(|error| io_error(path, error))?;
    temporary
        .write_all(&encoded)
        .map_err(|error| io_error(temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error(temporary.path(), error))?;
    temporary
        .persist(path.join(OWNER_FILENAME))
        .map_err(|error| io_error(path.join(OWNER_FILENAME), error.error))?;
    Ok(())
}

fn valid_owner_marker(path: &Path) -> bool {
    fs::read(path.join(OWNER_FILENAME))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ContentOwnerMarker>(&bytes).ok())
        .is_some_and(|marker| marker == ContentOwnerMarker::default())
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> SearchResult<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| SearchError::State(format!("{name} lock was poisoned")))
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn elapsed_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform;

    fn enabled_config() -> ContentConfig {
        ContentConfig {
            enabled: true,
            max_file_bytes: 64 * 1024,
            max_extracted_bytes: 4096,
            timeout_seconds: 5,
            workers: 2,
            extensions: vec!["txt".to_string(), "json".to_string()],
            exclusions: Vec::new(),
        }
    }

    #[test]
    fn indexes_searches_snippets_caches_updates_and_deletes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Root");
        fs::create_dir(&root).unwrap();
        let note = root.join("Production Notes.txt");
        fs::write(
            &note,
            b"The hidden hero transcript contains snowfall timing notes.",
        )
        .unwrap();
        let root_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let record = platform::file_record(&note, root_id, device_id).unwrap();
        let service =
            ContentService::open_for_test(&temp.path().join("content-index"), enabled_config(), 32)
                .unwrap();

        let report = service
            .index_records(vec![record.clone()], Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.indexed, 1);
        let query = ParsedQuery::parse("content: snowfall timing").unwrap();
        let search = service.search_reader().search(&query, 20).unwrap();
        assert_eq!(search.candidates.len(), 1);
        assert!(search.candidates[0]
            .content_match
            .snippet
            .contains("snowfall timing"));
        assert!(!search.candidates[0].content_match.highlights.is_empty());

        let cached = service
            .index_records(vec![record.clone()], Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(cached.cached, 1);
        assert_eq!(cached.indexed, 0);

        fs::write(&note, b"Replacement transcript contains avalanche timing.").unwrap();
        let updated_record = platform::file_record(&note, root_id, device_id).unwrap();
        let updated = service
            .index_records(vec![updated_record], Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(updated.indexed, 1);
        assert!(service
            .search_reader()
            .search(&ParsedQuery::parse("content: snowfall").unwrap(), 20)
            .unwrap()
            .candidates
            .is_empty());

        fs::remove_file(&note).unwrap();
        service
            .delete_normalized_path(&crate::model::normalize_path(&note))
            .unwrap();
        assert!(service
            .search_reader()
            .search(&ParsedQuery::parse("content: avalanche").unwrap(), 20)
            .unwrap()
            .candidates
            .is_empty());
        assert_eq!(service.verify().unwrap(), 0);
    }

    #[test]
    fn corrupt_oversized_excluded_and_cancelled_inputs_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Root");
        fs::create_dir(&root).unwrap();
        let bad_json = root.join("bad.json");
        let excluded = root.join("excluded.md");
        let oversized = root.join("oversized.txt");
        fs::write(&bad_json, b"{").unwrap();
        fs::write(&excluded, b"excluded text").unwrap();
        fs::write(&oversized, vec![b'x'; 64 * 1024 + 1]).unwrap();
        let root_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let records = [&bad_json, &excluded, &oversized]
            .into_iter()
            .map(|path| platform::file_record(path, root_id, device_id).unwrap())
            .collect::<Vec<_>>();
        let service =
            ContentService::open_for_test(&temp.path().join("content-index"), enabled_config(), 32)
                .unwrap();
        let report = service
            .index_records(records, Arc::new(AtomicBool::new(false)))
            .unwrap();
        assert_eq!(report.failed, 2);
        assert_eq!(report.excluded, 1);

        let cancelled_file = root.join("cancelled.txt");
        fs::write(&cancelled_file, b"cancelled").unwrap();
        let cancelled_record = platform::file_record(&cancelled_file, root_id, device_id).unwrap();
        let cancellation = Arc::new(AtomicBool::new(true));
        let report = service
            .index_records(vec![cancelled_record], cancellation)
            .unwrap();
        assert_eq!(report.cancelled, 1);
    }

    #[test]
    fn root_reconciliation_prunes_only_unseen_records_from_that_root() {
        let temp = tempfile::tempdir().unwrap();
        let first_root = temp.path().join("First");
        let second_root = temp.path().join("Second");
        fs::create_dir(&first_root).unwrap();
        fs::create_dir(&second_root).unwrap();
        let retained = first_root.join("Retained.txt");
        let stale = first_root.join("Stale.txt");
        let unrelated = second_root.join("Unrelated.txt");
        fs::write(&retained, b"retained reconciliation phrase").unwrap();
        fs::write(&stale, b"stale reconciliation phrase").unwrap();
        fs::write(&unrelated, b"unrelated reconciliation phrase").unwrap();
        let first_root_id = Uuid::new_v4();
        let second_root_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let retained_record = platform::file_record(&retained, first_root_id, device_id).unwrap();
        let records = vec![
            retained_record.clone(),
            platform::file_record(&stale, first_root_id, device_id).unwrap(),
            platform::file_record(&unrelated, second_root_id, device_id).unwrap(),
        ];
        let service =
            ContentService::open_for_test(&temp.path().join("content-index"), enabled_config(), 32)
                .unwrap();
        service
            .index_records(records, Arc::new(AtomicBool::new(false)))
            .unwrap();

        let report = service
            .reconcile_root_paths(
                first_root_id,
                &HashSet::from([retained_record.normalized_path]),
            )
            .unwrap();

        assert_eq!(report.deleted, 1);
        assert_eq!(report.indexed_documents, 2);
        assert_eq!(service.verify().unwrap(), 2);
        assert!(service
            .search_reader()
            .search(&ParsedQuery::parse("content: stale").unwrap(), 20)
            .unwrap()
            .candidates
            .is_empty());
        assert_eq!(
            service
                .search_reader()
                .search(&ParsedQuery::parse("content: retained").unwrap(), 20)
                .unwrap()
                .candidates
                .len(),
            1
        );
        assert_eq!(
            service
                .search_reader()
                .search(&ParsedQuery::parse("content: unrelated").unwrap(), 20)
                .unwrap()
                .candidates
                .len(),
            1
        );
    }

    #[test]
    fn systemic_worker_failures_abort_the_batch_and_transient_failures_are_not_cached() {
        let temp = tempfile::tempdir().unwrap();
        let note = temp.path().join("Note.txt");
        fs::write(&note, b"worker failure test").unwrap();
        let record = platform::file_record(&note, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        let service =
            ContentService::open_for_test(&temp.path().join("content-index"), enabled_config(), 32)
                .unwrap();

        let error = service
            .apply_extraction_result(
                &record,
                Err(ExtractionFailure {
                    code: ExtractionErrorCode::WorkerUnavailable,
                    message: "worker missing".to_string(),
                }),
            )
            .unwrap_err();
        assert!(error.to_string().contains("worker missing"));
        assert_eq!(service.document_count(), 0);

        let metadata = ContentMetadata {
            extractor_version: CONTENT_EXTRACTOR_VERSION,
            stable_key: record.stable_key.clone(),
            normalized_path: record.normalized_path.clone(),
            source_size: record.size,
            modified_time_millis: record.modified_time.map(|value| value.timestamp_millis()),
            digest: None,
            state: ContentItemState::Failed,
            source_truncated: false,
            mime_type: record.mime_type.clone(),
            error_code: Some(ExtractionErrorCode::Timeout),
            indexed_at_millis: Utc::now().timestamp_millis(),
        };
        assert!(!cache_matches(&metadata, &record));
    }

    #[test]
    fn nonempty_unowned_content_directories_are_never_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("content-index");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("unrelated.txt"), b"keep").unwrap();
        assert!(ContentService::open_for_test(&path, enabled_config(), 32).is_err());
        assert_eq!(fs::read(path.join("unrelated.txt")).unwrap(), b"keep");
    }
}
