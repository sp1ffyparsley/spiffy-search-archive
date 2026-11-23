use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{FileCategory, FileRecord, ItemKind};
use crate::query::{ParsedQuery, SearchMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tantivy::collector::{Count, MultiCollector, TopDocs};
use tantivy::query::{
    AllQuery, BooleanQuery, FuzzyTermQuery, Occur, Query, RangeQuery, TermQuery, TermSetQuery,
};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TantivyDocument, Value, FAST, INDEXED, STORED, STRING, TEXT,
};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};
use tempfile::NamedTempFile;
use uuid::Uuid;

const INDEX_FORMAT_VERSION: u16 = 1;
const OWNER_FILENAME: &str = ".spiffy-search-index-owner.json";
const MAX_CANDIDATES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IndexOwnerMarker {
    product: String,
    index: String,
    format_version: u16,
}

impl Default for IndexOwnerMarker {
    fn default() -> Self {
        Self {
            product: "spiffy-search".to_string(),
            index: "filename".to_string(),
            format_version: INDEX_FORMAT_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexCommit {
    pub opstamp: u64,
    pub indexed_documents: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSearch {
    pub records: Vec<FileRecord>,
    pub total_candidates: u64,
    pub indexed_documents: u64,
    pub elapsed_micros: u64,
}

#[derive(Clone)]
struct Fields {
    stable_key: Field,
    root_id: Field,
    device_id: Field,
    normalized_path: Field,
    filename: Field,
    filename_stem: Field,
    parent_tokens: Field,
    extension: Field,
    item_kind: Field,
    category: Field,
    size: Field,
    created_time: Field,
    modified_time: Field,
    remote: Field,
    missing: Field,
    tombstone: Field,
    record_json: Field,
}

pub struct FilenameIndex {
    path: PathBuf,
    reader: IndexReader,
    writer: IndexWriter,
    fields: Fields,
}

#[derive(Clone)]
pub struct FilenameSearchReader {
    reader: IndexReader,
    fields: Fields,
}

impl FilenameIndex {
    pub fn open_default(writer_memory_mb: u16) -> SearchResult<Self> {
        Self::open_internal(&crate::config::filename_index_path(), writer_memory_mb)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path, writer_memory_mb: u16) -> SearchResult<Self> {
        Self::open_internal(path, writer_memory_mb)
    }

    fn open_internal(path: &Path, writer_memory_mb: u16) -> SearchResult<Self> {
        if !(32..=1024).contains(&writer_memory_mb) {
            return Err(SearchError::Config(
                "index writer memory must be between 32 and 1024 MiB".to_string(),
            ));
        }
        let schema = build_schema();
        let index = open_or_create_owned(path, &schema)?;
        let actual_schema = index.schema();
        if actual_schema != schema {
            let index = repair_owned_index(path, &schema, "schema_mismatch")?;
            return Self::finish_open(path, index, writer_memory_mb);
        }
        Self::finish_open(path, index, writer_memory_mb)
    }

    fn finish_open(path: &Path, index: Index, writer_memory_mb: u16) -> SearchResult<Self> {
        let schema = index.schema();
        let fields = fields_from_schema(&schema)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        let memory_bytes = usize::from(writer_memory_mb)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| SearchError::Config("index writer memory overflowed".to_string()))?;
        let writer: IndexWriter = index.writer_with_num_threads(1, memory_bytes)?;
        Ok(Self {
            path: path.to_path_buf(),
            reader,
            writer,
            fields,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn begin_root_replace(&mut self, root_id: Uuid) {
        self.writer.delete_term(Term::from_field_text(
            self.fields.root_id,
            &root_id.to_string(),
        ));
    }

    pub fn add_batch(&mut self, records: &[FileRecord]) -> SearchResult<()> {
        for record in records {
            validate_record(record)?;
            self.writer.delete_term(Term::from_field_text(
                self.fields.stable_key,
                &record.stable_key,
            ));
            self.writer.add_document(self.document(record)?)?;
        }
        Ok(())
    }

    pub fn delete_stable_key(&mut self, stable_key: &str) -> SearchResult<()> {
        validate_stable_key(stable_key)?;
        self.writer
            .delete_term(Term::from_field_text(self.fields.stable_key, stable_key));
        Ok(())
    }

    pub fn delete_normalized_path(&mut self, normalized_path: &str) -> SearchResult<()> {
        if normalized_path.is_empty() || normalized_path.len() > 32_768 {
            return Err(SearchError::Index("normalized path is invalid".to_string()));
        }
        self.writer.delete_term(Term::from_field_text(
            self.fields.normalized_path,
            normalized_path,
        ));
        Ok(())
    }

    pub fn commit(&mut self) -> SearchResult<IndexCommit> {
        let opstamp = self.writer.commit()?;
        self.reader.reload()?;
        Ok(IndexCommit {
            opstamp,
            indexed_documents: self.document_count(),
        })
    }

    pub fn rollback(&mut self) -> SearchResult<u64> {
        Ok(self.writer.rollback()?)
    }

    pub fn search_reader(&self) -> FilenameSearchReader {
        FilenameSearchReader {
            reader: self.reader.clone(),
            fields: self.fields.clone(),
        }
    }

    pub fn document_count(&self) -> u64 {
        self.search_reader().document_count()
    }

    pub fn kind_document_count(&self, kind: ItemKind) -> SearchResult<u64> {
        self.search_reader().kind_document_count(kind)
    }

    pub fn verify(&self) -> SearchResult<u64> {
        self.search_reader().verify()
    }

    pub fn search(&self, query: &ParsedQuery, limit: usize) -> SearchResult<CandidateSearch> {
        self.search_reader().search(query, limit)
    }

    fn document(&self, record: &FileRecord) -> SearchResult<TantivyDocument> {
        let mut document = TantivyDocument::new();
        document.add_text(self.fields.stable_key, &record.stable_key);
        document.add_text(self.fields.root_id, record.root_id.to_string());
        document.add_text(self.fields.device_id, record.device_id.to_string());
        document.add_text(self.fields.normalized_path, &record.normalized_path);
        document.add_text(self.fields.filename, &record.filename);
        document.add_text(self.fields.filename_stem, &record.filename_stem);
        document.add_text(self.fields.parent_tokens, &record.parent_tokens);
        document.add_text(self.fields.extension, &record.extension);
        document.add_text(self.fields.item_kind, item_kind_name(record.item_kind));
        document.add_text(self.fields.category, category_name(record.category));
        document.add_u64(self.fields.size, record.size);
        document.add_i64(
            self.fields.created_time,
            record
                .created_time
                .map(|value| value.timestamp_millis())
                .unwrap_or(i64::MIN),
        );
        document.add_i64(
            self.fields.modified_time,
            record
                .modified_time
                .map(|value| value.timestamp_millis())
                .unwrap_or(i64::MIN),
        );
        document.add_u64(
            self.fields.remote,
            u64::from(record.remote_device.is_some()),
        );
        document.add_u64(self.fields.missing, u64::from(record.missing));
        document.add_u64(self.fields.tombstone, u64::from(record.tombstone));
        document.add_text(self.fields.record_json, serde_json::to_string(record)?);
        Ok(document)
    }

    fn build_query(
        fields: &Fields,
        parsed: &ParsedQuery,
        allowed_root_ids: Option<&BTreeSet<Uuid>>,
    ) -> Box<dyn Query> {
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        if let Some(root_ids) = allowed_root_ids {
            let terms: Vec<Term> = root_ids
                .iter()
                .map(|root_id| Term::from_field_text(fields.root_id, &root_id.to_string()))
                .collect();
            clauses.push((Occur::Must, Box::new(TermSetQuery::new(terms))));
        }
        let tokens = candidate_tokens(parsed);
        if tokens.is_empty() {
            clauses.push((Occur::Must, Box::new(AllQuery)));
        } else {
            let mut text_clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
            for token in tokens {
                let distance = if token.chars().count() <= 2 { 0 } else { 1 };
                for field in [fields.filename, fields.filename_stem, fields.parent_tokens] {
                    text_clauses.push((
                        Occur::Should,
                        Box::new(FuzzyTermQuery::new_prefix(
                            Term::from_field_text(field, &token),
                            distance,
                            true,
                        )),
                    ));
                }
            }
            clauses.push((Occur::Must, Box::new(BooleanQuery::new(text_clauses))));
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
        match parsed.mode {
            SearchMode::Filename => add_term_set_filter(
                &mut clauses,
                fields.item_kind,
                [
                    ItemKind::Browser,
                    ItemKind::Clipboard,
                    ItemKind::Shelf,
                    ItemKind::Window,
                ]
                .into_iter()
                .map(|kind| item_kind_name(kind).to_string()),
                Occur::MustNot,
            ),
            SearchMode::Browser => add_term_set_filter(
                &mut clauses,
                fields.item_kind,
                [item_kind_name(ItemKind::Browser).to_string()],
                Occur::Must,
            ),
            _ => {}
        }
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
        if parsed.remote_only {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_u64(fields.remote, 1),
                    IndexRecordOption::Basic,
                )),
            ));
        }
        for (field, value) in [(fields.missing, 0), (fields.tombstone, 0)] {
            clauses.push((
                Occur::Must,
                Box::new(TermQuery::new(
                    Term::from_field_u64(field, value),
                    IndexRecordOption::Basic,
                )),
            ));
        }
        Box::new(BooleanQuery::new(clauses))
    }
}

impl FilenameSearchReader {
    pub fn document_count(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    pub fn verify(&self) -> SearchResult<u64> {
        self.reader.reload()?;
        let searcher = self.reader.searcher();
        let count = searcher.search(&AllQuery, &Count)?;
        u64::try_from(count)
            .map_err(|_| SearchError::Index("document count exceeds u64".to_string()))
    }

    pub fn record_by_stable_key(&self, stable_key: &str) -> SearchResult<Option<FileRecord>> {
        validate_stable_key(stable_key)?;
        self.reader.reload()?;
        let query = TermQuery::new(
            Term::from_field_text(self.fields.stable_key, stable_key),
            IndexRecordOption::Basic,
        );
        let searcher = self.reader.searcher();
        let documents = searcher.search(&query, &TopDocs::with_limit(2).order_by_score())?;
        if documents.len() > 1 {
            return Err(SearchError::Index(format!(
                "stable key resolves to multiple filename records: {stable_key}"
            )));
        }
        documents
            .into_iter()
            .next()
            .map(|(_, address)| {
                let document: TantivyDocument = searcher.doc(address)?;
                let json = document
                    .get_first(self.fields.record_json)
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        SearchError::Index("indexed record is missing stored JSON".to_string())
                    })?;
                Ok(serde_json::from_str(json)?)
            })
            .transpose()
    }

    pub fn kind_document_count(&self, kind: ItemKind) -> SearchResult<u64> {
        self.reader.reload()?;
        let query = TermQuery::new(
            Term::from_field_text(self.fields.item_kind, item_kind_name(kind)),
            IndexRecordOption::Basic,
        );
        let count = self.reader.searcher().search(&query, &Count)?;
        u64::try_from(count)
            .map_err(|_| SearchError::Index("document count exceeds u64".to_string()))
    }

    pub fn search(&self, query: &ParsedQuery, limit: usize) -> SearchResult<CandidateSearch> {
        self.search_in_roots(query, limit, None)
    }

    pub fn search_in_roots(
        &self,
        query: &ParsedQuery,
        limit: usize,
        allowed_root_ids: Option<&BTreeSet<Uuid>>,
    ) -> SearchResult<CandidateSearch> {
        let started = Instant::now();
        self.reader.reload()?;
        let indexed_documents = self.document_count();
        if !matches!(query.mode, SearchMode::Filename | SearchMode::Browser) {
            return Ok(CandidateSearch {
                records: Vec::new(),
                total_candidates: 0,
                indexed_documents,
                elapsed_micros: elapsed_micros(started),
            });
        }
        let limit = limit.clamp(1, MAX_CANDIDATES);
        let tantivy_query = FilenameIndex::build_query(&self.fields, query, allowed_root_ids);
        let searcher = self.reader.searcher();
        let mut collectors = MultiCollector::new();
        let total_handle = collectors.add_collector(Count);
        let top_docs_handle = collectors.add_collector(TopDocs::with_limit(limit).order_by_score());
        let mut fruits = searcher.search(tantivy_query.as_ref(), &collectors)?;
        let total = total_handle.extract(&mut fruits);
        let top_docs = top_docs_handle.extract(&mut fruits);
        let mut records = Vec::with_capacity(top_docs.len());
        for (_score, address) in top_docs {
            let document: TantivyDocument = searcher.doc(address)?;
            let json = document
                .get_first(self.fields.record_json)
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    SearchError::Index("indexed record is missing stored JSON".to_string())
                })?;
            let record: FileRecord = serde_json::from_str(json).map_err(|error| {
                SearchError::Index(format!("indexed record JSON is invalid: {error}"))
            })?;
            if record_matches_query(&record, query) {
                records.push(record);
            }
        }
        Ok(CandidateSearch {
            records,
            total_candidates: u64::try_from(total)
                .map_err(|_| SearchError::Index("candidate count exceeds u64".to_string()))?,
            indexed_documents,
            elapsed_micros: elapsed_micros(started),
        })
    }
}

fn build_schema() -> Schema {
    let mut builder = Schema::builder();
    builder.add_text_field("stable_key", STRING);
    builder.add_text_field("root_id", STRING);
    builder.add_text_field("device_id", STRING);
    builder.add_text_field("normalized_path", STRING);
    builder.add_text_field("filename", TEXT);
    builder.add_text_field("filename_stem", TEXT);
    builder.add_text_field("parent_tokens", TEXT);
    builder.add_text_field("extension", STRING);
    builder.add_text_field("item_kind", STRING);
    builder.add_text_field("category", STRING);
    builder.add_u64_field("size", INDEXED | FAST);
    builder.add_i64_field("created_time", INDEXED | FAST);
    builder.add_i64_field("modified_time", INDEXED | FAST);
    builder.add_u64_field("remote", INDEXED | FAST);
    builder.add_u64_field("missing", INDEXED);
    builder.add_u64_field("tombstone", INDEXED);
    builder.add_text_field("record_json", STORED);
    builder.build()
}

fn fields_from_schema(schema: &Schema) -> SearchResult<Fields> {
    Ok(Fields {
        stable_key: field(schema, "stable_key")?,
        root_id: field(schema, "root_id")?,
        device_id: field(schema, "device_id")?,
        normalized_path: field(schema, "normalized_path")?,
        filename: field(schema, "filename")?,
        filename_stem: field(schema, "filename_stem")?,
        parent_tokens: field(schema, "parent_tokens")?,
        extension: field(schema, "extension")?,
        item_kind: field(schema, "item_kind")?,
        category: field(schema, "category")?,
        size: field(schema, "size")?,
        created_time: field(schema, "created_time")?,
        modified_time: field(schema, "modified_time")?,
        remote: field(schema, "remote")?,
        missing: field(schema, "missing")?,
        tombstone: field(schema, "tombstone")?,
        record_json: field(schema, "record_json")?,
    })
}

fn field(schema: &Schema, name: &str) -> SearchResult<Field> {
    schema
        .get_field(name)
        .map_err(|_| SearchError::Index(format!("filename index is missing field '{name}'")))
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
            "filename index path is not a normal directory: {}",
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
                "could not open unowned filename index at {}: {error}",
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
            "refusing to replace nonempty unowned index directory: {}",
            path.display()
        )))
    }
}

fn repair_owned_index(path: &Path, schema: &Schema, reason: &str) -> SearchResult<Index> {
    if !valid_owner_marker(path) {
        return Err(SearchError::Index(format!(
            "refusing to rebuild an index without a valid owner marker: {}",
            path.display()
        )));
    }
    #[cfg(not(test))]
    if path != crate::config::filename_index_path() {
        return Err(SearchError::Index(format!(
            "refusing to rebuild an index outside the Search data owner: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SearchError::Index(
            "refusing to rebuild a symlink or non-directory index path".to_string(),
        ));
    }
    tracing::warn!(reason, index = %path.display(), "rebuilding reproducible filename index");
    fs::remove_dir_all(path).map_err(|error| io_error(path, error))?;
    fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
    let index = Index::create_in_dir(path, schema.clone())?;
    write_owner_marker(path)?;
    Ok(index)
}

fn write_owner_marker(path: &Path) -> SearchResult<()> {
    let encoded = serde_json::to_vec_pretty(&IndexOwnerMarker::default())?;
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
        .and_then(|bytes| serde_json::from_slice::<IndexOwnerMarker>(&bytes).ok())
        .is_some_and(|marker| marker == IndexOwnerMarker::default())
}

fn validate_record(record: &FileRecord) -> SearchResult<()> {
    if record.stable_key.is_empty()
        || record.stable_key.len() > 512
        || record.normalized_path.is_empty()
        || record.normalized_path.len() > 32_768
        || record.filename.chars().count() > 1024
    {
        return Err(SearchError::Index(
            "file record is outside supported index limits".to_string(),
        ));
    }
    Ok(())
}

fn validate_stable_key(stable_key: &str) -> SearchResult<()> {
    if stable_key.is_empty() || stable_key.len() > 512 || stable_key.contains('\0') {
        return Err(SearchError::Index("stable key is invalid".to_string()));
    }
    Ok(())
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

fn candidate_tokens(query: &ParsedQuery) -> Vec<String> {
    query
        .terms
        .iter()
        .chain(query.exact_phrases.iter())
        .flat_map(|value| value.split(|character: char| !character.is_alphanumeric()))
        .filter(|value| !value.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn record_matches_query(record: &FileRecord, query: &ParsedQuery) -> bool {
    if record.missing || record.tombstone {
        return false;
    }
    match query.mode {
        SearchMode::Filename
            if matches!(
                record.item_kind,
                ItemKind::Browser | ItemKind::Clipboard | ItemKind::Shelf | ItemKind::Window
            ) =>
        {
            return false;
        }
        SearchMode::Browser if record.item_kind != ItemKind::Browser => return false,
        _ => {}
    }
    if !query.extensions.is_empty() && !query.extensions.contains(&record.extension) {
        return false;
    }
    if query.excluded_extensions.contains(&record.extension)
        || (!query.kinds.is_empty() && !query.kinds.contains(&record.item_kind))
        || (!query.categories.is_empty() && !query.categories.contains(&record.category))
    {
        return false;
    }
    if !query.exact_phrases.is_empty() || !query.excluded_terms.is_empty() {
        let searchable = format!(
            "{} {} {}",
            record.filename.to_lowercase(),
            record.parent_path.to_lowercase(),
            record.normalized_path.to_lowercase()
        );
        if query
            .exact_phrases
            .iter()
            .any(|phrase| !searchable.contains(&phrase.to_lowercase()))
            || query
                .excluded_terms
                .iter()
                .any(|term| searchable.contains(&term.to_lowercase()))
        {
            return false;
        }
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
            .strip_prefix("//?/")
            .unwrap_or(&record.normalized_path)
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
    if query.remote_only && record.remote_device.is_none() {
        return false;
    }
    true
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

fn elapsed_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform;
    use std::fs;

    fn index(temp: &tempfile::TempDir) -> FilenameIndex {
        FilenameIndex::open_for_test(&temp.path().join("index"), 32).unwrap()
    }

    #[test]
    fn real_tantivy_index_supports_filters_upserts_and_deletes() {
        let temp = tempfile::tempdir().unwrap();
        let files = temp.path().join("files");
        fs::create_dir(&files).unwrap();
        let hero = files.join("Hero Clip.mov");
        let notes = files.join("Production Notes.txt");
        fs::write(&hero, vec![1_u8; 128]).unwrap();
        fs::write(&notes, b"notes").unwrap();
        let root_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut hero_record = platform::file_record(&hero, root_id, device_id).unwrap();
        let notes_record = platform::file_record(&notes, root_id, device_id).unwrap();
        let mut index = index(&temp);
        index.begin_root_replace(root_id);
        index
            .add_batch(&[hero_record.clone(), notes_record])
            .unwrap();
        let commit = index.commit().unwrap();
        assert_eq!(commit.indexed_documents, 2);

        let query = ParsedQuery::parse("hero ext:mov size:>100b").unwrap();
        let results = index.search(&query, 50).unwrap();
        assert_eq!(results.records.len(), 1);
        assert_eq!(results.records[0].filename, "Hero Clip.mov");

        hero_record.filename = "Opening Hero.mov".to_string();
        hero_record.filename_stem = "Opening Hero".to_string();
        index.add_batch(&[hero_record.clone()]).unwrap();
        index.commit().unwrap();
        assert!(index
            .search(&ParsedQuery::parse("opening").unwrap(), 50)
            .unwrap()
            .records
            .iter()
            .any(|record| record.stable_key == hero_record.stable_key));

        index.delete_stable_key(&hero_record.stable_key).unwrap();
        index.commit().unwrap();
        assert_eq!(index.document_count(), 1);
        assert_eq!(index.verify().unwrap(), 1);
    }

    #[test]
    fn record_matching_preserves_phrase_and_excluded_term_filters() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("Project Alpha");
        fs::create_dir(&folder).unwrap();
        let path = folder.join("Hero Clip.mov");
        fs::write(&path, b"clip").unwrap();
        let record = platform::file_record(&path, Uuid::new_v4(), Uuid::new_v4()).unwrap();

        assert!(record_matches_query(
            &record,
            &ParsedQuery::parse("hero").unwrap()
        ));
        assert!(record_matches_query(
            &record,
            &ParsedQuery::parse("\"project alpha\"").unwrap()
        ));
        assert!(!record_matches_query(
            &record,
            &ParsedQuery::parse("hero -project").unwrap()
        ));
    }

    #[test]
    fn root_replacement_removes_stale_documents_without_touching_other_roots() {
        let temp = tempfile::tempdir().unwrap();
        let files = temp.path().join("files");
        fs::create_dir(&files).unwrap();
        let first = files.join("First.mov");
        let second = files.join("Second.mov");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let root_a = Uuid::new_v4();
        let root_b = Uuid::new_v4();
        let device = Uuid::new_v4();
        let first_record = platform::file_record(&first, root_a, device).unwrap();
        let second_record = platform::file_record(&second, root_b, device).unwrap();
        let mut index = index(&temp);
        index.add_batch(&[first_record, second_record]).unwrap();
        index.commit().unwrap();
        index.begin_root_replace(root_a);
        index.commit().unwrap();
        let all = index.search(&ParsedQuery::parse("").unwrap(), 50).unwrap();
        assert_eq!(all.records.len(), 1);
        assert_eq!(all.records[0].root_id, root_b);
    }

    #[test]
    fn nonempty_unowned_directories_are_never_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("index");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("unrelated.txt"), b"keep").unwrap();
        assert!(FilenameIndex::open_for_test(&path, 32).is_err());
        assert_eq!(fs::read(path.join("unrelated.txt")).unwrap(), b"keep");
    }

    #[test]
    #[ignore = "performance witness; run explicitly in --release"]
    fn large_corpus_filename_query_latency_witness() {
        let document_count = std::env::var("SPIFFY_SEARCH_BENCH_DOCS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(100_000)
            .clamp(10_000, 500_000);
        let temp = tempfile::tempdir().unwrap();
        let mut index = FilenameIndex::open_for_test(&temp.path().join("index"), 64).unwrap();
        let root_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let started = Instant::now();
        index.begin_root_replace(root_id);
        for batch_start in (0..document_count).step_by(1_000) {
            let batch_end = (batch_start + 1_000).min(document_count);
            let records = (batch_start..batch_end)
                .map(|number| synthetic_record(number, root_id, device_id))
                .collect::<Vec<_>>();
            index.add_batch(&records).unwrap();
        }
        index.commit().unwrap();
        let index_millis = started.elapsed().as_millis();
        assert_eq!(index.document_count(), document_count as u64);

        let queries = [
            ParsedQuery::parse("hero").unwrap(),
            ParsedQuery::parse("asset 099").unwrap(),
            ParsedQuery::parse("ext:mov project 42").unwrap(),
        ];
        for query in &queries {
            for _ in 0..10 {
                let _ = index.search(query, 1_600).unwrap();
            }
        }

        let mut samples = Vec::with_capacity(150);
        for iteration in 0..150 {
            let query = &queries[iteration % queries.len()];
            let started = Instant::now();
            let result = index.search(query, 1_600).unwrap();
            samples.push(started.elapsed().as_micros() as u64);
            assert!(result.total_candidates > 0);
        }
        samples.sort_unstable();
        let p50 = samples[samples.len() / 2];
        let p95 = samples[samples.len() * 95 / 100];
        let p99 = samples[samples.len() * 99 / 100];
        println!(
            "spiffy-search filename witness: documents={document_count} index_ms={index_millis} p50_us={p50} p95_us={p95} p99_us={p99}"
        );
    }

    fn synthetic_record(number: usize, root_id: Uuid, device_id: Uuid) -> FileRecord {
        let project = number % 100;
        let hero = if number % 10 == 0 { " Hero" } else { "" };
        let filename = format!("Asset {number:06} Project {project:02}{hero}.mov");
        let path = format!("C:/Synthetic/Project {project:02}/{filename}");
        FileRecord {
            stable_key: format!("synthetic:{number}"),
            stable_file_id: None,
            root_id,
            device_id,
            canonical_path: path.clone(),
            display_path: path.clone(),
            normalized_path: path.to_ascii_lowercase(),
            filename: filename.clone(),
            filename_stem: filename.trim_end_matches(".mov").to_string(),
            extension: "mov".to_string(),
            parent_path: format!("C:/Synthetic/Project {project:02}"),
            parent_tokens: format!("synthetic project {project:02}"),
            item_kind: ItemKind::File,
            category: FileCategory::Video,
            content_type: "video".to_string(),
            mime_type: "video/quicktime".to_string(),
            size: 1_048_576 + number as u64,
            created_time: None,
            modified_time: None,
            last_seen_time: chrono::Utc::now(),
            hidden: false,
            system: false,
            package: false,
            application: false,
            folder: false,
            file: true,
            cloud_placeholder: false,
            offline: false,
            missing: false,
            tombstone: false,
            source_provider: "performance_fixture".to_string(),
            remote_device: None,
            content_index_state: "disabled".to_string(),
            preview_state: "not_applicable".to_string(),
            tags: Vec::new(),
        }
    }
}
