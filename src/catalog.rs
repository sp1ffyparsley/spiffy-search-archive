use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{normalize_path, FavoriteItem, ItemOverlay};
use crate::protocol::{FileOperationProgress, FileOperationReceipt};
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

pub const CATALOG_SCHEMA_VERSION: i64 = 2;
const MAX_ROOT_EXCLUSIONS: usize = 128;
const MAX_ALIASES: usize = 64;
const QUERY_CHUNK_SIZE: usize = 400;

type RawOperationReceiptRow = (
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    String,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoot {
    pub id: Uuid,
    pub canonical_path: String,
    pub normalized_path: String,
    pub enabled: bool,
    pub remote_searchable: bool,
    pub exclusions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_scan_started_at: Option<DateTime<Utc>>,
    pub last_scan_completed_at: Option<DateTime<Utc>>,
    pub last_scan_generation: u64,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexState {
    pub generation: u64,
    pub indexed_documents: u64,
    pub pending_reconciliation: bool,
    pub last_commit_at: Option<DateTime<Utc>>,
    pub last_reconciliation_at: Option<DateTime<Utc>>,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSearch {
    pub id: Uuid,
    pub name: String,
    pub query: String,
    pub pinned: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDoctor {
    pub healthy: bool,
    pub schema_version: i64,
    pub quick_check: String,
    pub root_count: u64,
    pub overlay_count: u64,
    pub saved_search_count: u64,
    pub receipt_count: u64,
}

pub struct SearchCatalog {
    connection: Connection,
    database_path: PathBuf,
}

impl SearchCatalog {
    pub fn open_default() -> SearchResult<Self> {
        Self::open(crate::config::database_path())
    }

    pub fn open(path: PathBuf) -> SearchResult<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
        }
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        let mut catalog = Self {
            connection,
            database_path: path,
        };
        catalog.migrate()?;
        Ok(catalog)
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn local_device_id(&mut self) -> SearchResult<Uuid> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM metadata WHERE key = 'local_device_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(value) = existing {
            return parse_uuid(&value, "local device");
        }
        let id = Uuid::new_v4();
        self.connection.execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES ('local_device_id', ?1)",
            [id.to_string()],
        )?;
        let stored: String = self.connection.query_row(
            "SELECT value FROM metadata WHERE key = 'local_device_id'",
            [],
            |row| row.get(0),
        )?;
        parse_uuid(&stored, "local device")
    }

    fn migrate(&mut self) -> SearchResult<()> {
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0 => {
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                transaction.execute_batch(
                    "CREATE TABLE source_roots (
                        root_id TEXT PRIMARY KEY NOT NULL,
                        canonical_path TEXT NOT NULL,
                        normalized_path TEXT NOT NULL UNIQUE,
                        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                        remote_searchable INTEGER NOT NULL DEFAULT 0 CHECK (remote_searchable IN (0, 1)),
                        exclusions_json TEXT NOT NULL DEFAULT '[]',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_scan_started_at TEXT,
                        last_scan_completed_at TEXT,
                        last_scan_generation INTEGER NOT NULL DEFAULT 0 CHECK (last_scan_generation >= 0),
                        last_error_code TEXT
                    );
                    CREATE INDEX source_roots_enabled ON source_roots(enabled, normalized_path);

                    CREATE TABLE metadata (
                        key TEXT PRIMARY KEY NOT NULL,
                        value TEXT NOT NULL
                    );

                    CREATE TABLE index_state (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                        generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
                        indexed_documents INTEGER NOT NULL DEFAULT 0 CHECK (indexed_documents >= 0),
                        pending_reconciliation INTEGER NOT NULL DEFAULT 0 CHECK (pending_reconciliation IN (0, 1)),
                        last_commit_at TEXT,
                        last_reconciliation_at TEXT,
                        last_error_code TEXT
                    );
                    INSERT INTO index_state(singleton) VALUES (1);

                    CREATE TABLE item_overlays (
                        stable_key TEXT PRIMARY KEY NOT NULL,
                        display_name TEXT NOT NULL DEFAULT '',
                        last_known_path TEXT NOT NULL DEFAULT '',
                        favorite INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
                        pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
                        usage_count INTEGER NOT NULL DEFAULT 0 CHECK (usage_count >= 0),
                        last_opened TEXT,
                        last_selected TEXT,
                        custom_priority INTEGER NOT NULL DEFAULT 0 CHECK (custom_priority BETWEEN -100 AND 100),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE INDEX item_overlays_favorite ON item_overlays(favorite, pinned, updated_at DESC);

                    CREATE TABLE aliases (
                        stable_key TEXT NOT NULL,
                        alias TEXT NOT NULL,
                        alias_normalized TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (stable_key, alias_normalized),
                        FOREIGN KEY (stable_key) REFERENCES item_overlays(stable_key) ON DELETE CASCADE
                    );
                    CREATE INDEX aliases_lookup ON aliases(alias_normalized);

                    CREATE TABLE saved_searches (
                        search_id TEXT PRIMARY KEY NOT NULL,
                        name TEXT NOT NULL,
                        query TEXT NOT NULL,
                        pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE UNIQUE INDEX saved_searches_name ON saved_searches(name COLLATE NOCASE);

                    CREATE TABLE file_operation_receipts (
                        operation_id TEXT PRIMARY KEY NOT NULL,
                        kind TEXT NOT NULL,
                        sources_json TEXT NOT NULL,
                        destination TEXT,
                        state TEXT NOT NULL,
                        undo_actions_json TEXT NOT NULL DEFAULT '[]',
                        progress_json TEXT NOT NULL DEFAULT '{}',
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        error_code TEXT,
                        message TEXT,
                        request_fingerprint TEXT NOT NULL DEFAULT ''
                    );
                    CREATE INDEX file_operation_receipts_started ON file_operation_receipts(started_at DESC);
                    PRAGMA user_version = 2;",
                )?;
                transaction.commit()?;
            }
            1 => {
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                transaction.execute_batch(
                    "ALTER TABLE file_operation_receipts
                         ADD COLUMN progress_json TEXT NOT NULL DEFAULT '{}';
                     ALTER TABLE file_operation_receipts ADD COLUMN message TEXT;
                     ALTER TABLE file_operation_receipts
                         ADD COLUMN request_fingerprint TEXT NOT NULL DEFAULT '';
                     PRAGMA user_version = 2;",
                )?;
                transaction.commit()?;
            }
            CATALOG_SCHEMA_VERSION => {}
            newer if newer > CATALOG_SCHEMA_VERSION => {
                return Err(SearchError::State(format!(
                    "search database schema {newer} is newer than supported schema {CATALOG_SCHEMA_VERSION}"
                )));
            }
            other => {
                return Err(SearchError::State(format!(
                    "search database schema {other} has no supported migration path"
                )));
            }
        }
        Ok(())
    }

    pub fn add_root(
        &mut self,
        path: &Path,
        remote_searchable: bool,
        exclusions: Vec<String>,
    ) -> SearchResult<SourceRoot> {
        if !path.is_dir() {
            return Err(SearchError::Config(format!(
                "search root is not an accessible directory: {}",
                path.display()
            )));
        }
        let canonical = fs::canonicalize(path).map_err(|error| io_error(path, error))?;
        let canonical_path = canonical.to_string_lossy().to_string();
        let normalized_path = normalize_path(&canonical);
        let exclusions = validate_exclusions(exclusions)?;
        let exclusions_json = serde_json::to_string(&exclusions)?;
        let now = Utc::now();
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT root_id FROM source_roots WHERE normalized_path = ?1",
                [&normalized_path],
                |row| row.get(0),
            )
            .optional()?;
        let id = existing
            .as_deref()
            .map(|value| parse_uuid(value, "source root"))
            .transpose()?
            .unwrap_or_else(Uuid::new_v4);
        self.connection.execute(
            "INSERT INTO source_roots(
                root_id, canonical_path, normalized_path, enabled, remote_searchable,
                exclusions_json, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?6)
             ON CONFLICT(normalized_path) DO UPDATE SET
                canonical_path = excluded.canonical_path,
                enabled = 1,
                remote_searchable = excluded.remote_searchable,
                exclusions_json = excluded.exclusions_json,
                updated_at = excluded.updated_at,
                last_error_code = NULL",
            params![
                id.to_string(),
                canonical_path,
                normalized_path,
                remote_searchable,
                exclusions_json,
                now.to_rfc3339(),
            ],
        )?;
        self.root(id)?.ok_or_else(|| {
            SearchError::State("source root disappeared after database write".to_string())
        })
    }

    pub fn root(&self, id: Uuid) -> SearchResult<Option<SourceRoot>> {
        self.connection
            .query_row(ROOT_SELECT_BY_ID, [id.to_string()], raw_root_row)
            .optional()?
            .map(RawRoot::into_root)
            .transpose()
    }

    pub fn roots(&self, enabled_only: bool) -> SearchResult<Vec<SourceRoot>> {
        let sql = if enabled_only {
            ROOT_SELECT_ENABLED
        } else {
            ROOT_SELECT_ALL
        };
        let mut statement = self.connection.prepare(sql)?;
        let rows = statement.query_map([], raw_root_row)?;
        let mut roots = Vec::new();
        for row in rows {
            roots.push(row?.into_root()?);
        }
        Ok(roots)
    }

    pub fn remove_root(&mut self, id: Uuid) -> SearchResult<bool> {
        Ok(self.connection.execute(
            "DELETE FROM source_roots WHERE root_id = ?1",
            [id.to_string()],
        )? == 1)
    }

    pub fn mark_root_scan_started(&mut self, id: Uuid) -> SearchResult<()> {
        let changed = self.connection.execute(
            "UPDATE source_roots SET last_scan_started_at = ?2,
                last_error_code = NULL, updated_at = ?2 WHERE root_id = ?1",
            params![id.to_string(), Utc::now().to_rfc3339()],
        )?;
        require_changed(changed, "source root", id)
    }

    pub fn mark_root_scan_failed(&mut self, id: Uuid, error_code: &str) -> SearchResult<()> {
        validate_code(error_code)?;
        let changed = self.connection.execute(
            "UPDATE source_roots SET last_error_code = ?2, updated_at = ?3 WHERE root_id = ?1",
            params![id.to_string(), error_code, Utc::now().to_rfc3339()],
        )?;
        require_changed(changed, "source root", id)
    }

    pub fn mark_root_scan_completed(
        &mut self,
        id: Uuid,
        indexed_documents: u64,
    ) -> SearchResult<IndexState> {
        let documents = checked_i64(indexed_documents, "indexed document count")?;
        let now = Utc::now().to_rfc3339();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE source_roots SET last_scan_completed_at = ?2,
                last_scan_generation = (SELECT generation + 1 FROM index_state WHERE singleton = 1),
                last_error_code = NULL, updated_at = ?2 WHERE root_id = ?1",
            params![id.to_string(), now],
        )?;
        require_changed(changed, "source root", id)?;
        transaction.execute(
            "UPDATE index_state SET generation = generation + 1,
                indexed_documents = ?1, pending_reconciliation = 0,
                last_commit_at = ?2, last_reconciliation_at = ?2,
                last_error_code = NULL WHERE singleton = 1",
            params![documents, now],
        )?;
        transaction.commit()?;
        self.index_state()
    }

    pub fn advance_index_generation(&mut self, indexed_documents: u64) -> SearchResult<IndexState> {
        let documents = checked_i64(indexed_documents, "indexed document count")?;
        self.connection.execute(
            "UPDATE index_state SET generation = generation + 1,
                indexed_documents = ?1, last_commit_at = ?2, last_error_code = NULL
             WHERE singleton = 1",
            params![documents, Utc::now().to_rfc3339()],
        )?;
        self.index_state()
    }

    pub fn set_reconciliation_pending(
        &mut self,
        pending: bool,
        error_code: Option<&str>,
    ) -> SearchResult<()> {
        if let Some(code) = error_code {
            validate_code(code)?;
        }
        self.connection.execute(
            "UPDATE index_state SET pending_reconciliation = ?1,
                last_error_code = ?2 WHERE singleton = 1",
            params![pending, error_code],
        )?;
        Ok(())
    }

    pub fn synchronize_index_snapshot(
        &mut self,
        indexed_documents: u64,
        pending_reconciliation: bool,
        error_code: Option<&str>,
    ) -> SearchResult<IndexState> {
        if let Some(code) = error_code {
            validate_code(code)?;
        }
        let documents = checked_i64(indexed_documents, "indexed document count")?;
        self.connection.execute(
            "UPDATE index_state SET indexed_documents = ?1,
                pending_reconciliation = ?2, last_error_code = ?3 WHERE singleton = 1",
            params![documents, pending_reconciliation, error_code],
        )?;
        self.index_state()
    }

    pub fn index_state(&self) -> SearchResult<IndexState> {
        let raw = self.connection.query_row(
            "SELECT generation, indexed_documents, pending_reconciliation,
                    last_commit_at, last_reconciliation_at, last_error_code
             FROM index_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )?;
        Ok(IndexState {
            generation: checked_u64(raw.0, "index generation")?,
            indexed_documents: checked_u64(raw.1, "indexed document count")?,
            pending_reconciliation: raw.2,
            last_commit_at: parse_optional_datetime(raw.3.as_deref(), "last commit")?,
            last_reconciliation_at: parse_optional_datetime(
                raw.4.as_deref(),
                "last reconciliation",
            )?,
            last_error_code: raw.5,
        })
    }

    pub fn set_favorite(
        &mut self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        favorite: bool,
    ) -> SearchResult<ItemOverlay> {
        self.set_overlay_flag(stable_key, display_name, path, "favorite", favorite)
    }

    pub fn set_pinned(
        &mut self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        pinned: bool,
    ) -> SearchResult<ItemOverlay> {
        self.set_overlay_flag(stable_key, display_name, path, "pinned", pinned)
    }

    fn set_overlay_flag(
        &mut self,
        stable_key: &str,
        display_name: &str,
        path: &str,
        field: &str,
        value: bool,
    ) -> SearchResult<ItemOverlay> {
        validate_overlay_identity(stable_key, display_name, path)?;
        let now = Utc::now().to_rfc3339();
        let sql = match field {
            "favorite" => {
                "INSERT INTO item_overlays(
                    stable_key, display_name, last_known_path, favorite, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(stable_key) DO UPDATE SET
                    display_name = excluded.display_name,
                    last_known_path = excluded.last_known_path,
                    favorite = excluded.favorite,
                    updated_at = excluded.updated_at"
            }
            "pinned" => {
                "INSERT INTO item_overlays(
                    stable_key, display_name, last_known_path, pinned, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(stable_key) DO UPDATE SET
                    display_name = excluded.display_name,
                    last_known_path = excluded.last_known_path,
                    pinned = excluded.pinned,
                    updated_at = excluded.updated_at"
            }
            _ => {
                return Err(SearchError::State(format!(
                    "unsupported overlay field {field}"
                )));
            }
        };
        self.connection
            .execute(sql, params![stable_key, display_name, path, value, now])?;
        self.overlay(stable_key)
    }

    pub fn set_aliases(
        &mut self,
        stable_key: &str,
        aliases: Vec<String>,
    ) -> SearchResult<ItemOverlay> {
        validate_stable_key(stable_key)?;
        let aliases = normalize_aliases(aliases)?;
        let now = Utc::now().to_rfc3339();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO item_overlays(stable_key, created_at, updated_at)
             VALUES (?1, ?2, ?2) ON CONFLICT(stable_key) DO UPDATE SET updated_at = excluded.updated_at",
            params![stable_key, now],
        )?;
        transaction.execute("DELETE FROM aliases WHERE stable_key = ?1", [stable_key])?;
        for (normalized, alias) in aliases {
            transaction.execute(
                "INSERT INTO aliases(stable_key, alias, alias_normalized, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![stable_key, alias, normalized, now],
            )?;
        }
        transaction.commit()?;
        self.overlay(stable_key)
    }

    pub fn record_usage(&mut self, stable_key: &str, selected: bool) -> SearchResult<ItemOverlay> {
        validate_stable_key(stable_key)?;
        let now = Utc::now().to_rfc3339();
        let (opened, selected_at) = if selected {
            (None, Some(now.as_str()))
        } else {
            (Some(now.as_str()), None)
        };
        self.connection.execute(
            "INSERT INTO item_overlays(
                stable_key, usage_count, last_opened, last_selected, created_at, updated_at
             ) VALUES (?1, 1, ?2, ?3, ?4, ?4)
             ON CONFLICT(stable_key) DO UPDATE SET
                usage_count = item_overlays.usage_count + 1,
                last_opened = COALESCE(excluded.last_opened, item_overlays.last_opened),
                last_selected = COALESCE(excluded.last_selected, item_overlays.last_selected),
                updated_at = excluded.updated_at",
            params![stable_key, opened, selected_at, now],
        )?;
        self.overlay(stable_key)
    }

    pub fn overlay(&self, stable_key: &str) -> SearchResult<ItemOverlay> {
        validate_stable_key(stable_key)?;
        Ok(self
            .overlays(&[stable_key.to_string()])?
            .remove(stable_key)
            .unwrap_or_default())
    }

    pub fn overlays(&self, stable_keys: &[String]) -> SearchResult<HashMap<String, ItemOverlay>> {
        let mut result = HashMap::new();
        for stable_key in stable_keys {
            validate_stable_key(stable_key)?;
        }
        for chunk in stable_keys.chunks(QUERY_CHUNK_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = (1..=chunk.len())
                .map(|position| format!("?{position}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT stable_key, favorite, pinned, usage_count, last_opened,
                        last_selected, custom_priority
                 FROM item_overlays WHERE stable_key IN ({placeholders})"
            );
            let mut statement = self.connection.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(chunk.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i16>(6)?,
                ))
            })?;
            for row in rows {
                let row = row?;
                result.insert(
                    row.0,
                    ItemOverlay {
                        favorite: row.1,
                        pinned: row.2,
                        aliases: Vec::new(),
                        usage_count: checked_u64(row.3, "usage count")?,
                        last_opened: parse_optional_datetime(row.4.as_deref(), "last opened")?,
                        last_selected: parse_optional_datetime(row.5.as_deref(), "last selected")?,
                        custom_priority: row.6,
                    },
                );
            }

            let alias_sql = format!(
                "SELECT stable_key, alias FROM aliases
                 WHERE stable_key IN ({placeholders}) ORDER BY alias_normalized"
            );
            let mut statement = self.connection.prepare(&alias_sql)?;
            let rows = statement.query_map(params_from_iter(chunk.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (stable_key, alias) = row?;
                result.entry(stable_key).or_default().aliases.push(alias);
            }
        }
        Ok(result)
    }

    pub fn favorite_items(&self, limit: u16) -> SearchResult<Vec<FavoriteItem>> {
        if limit == 0 || limit > 1000 {
            return Err(SearchError::Config(
                "favorite item limit must be between 1 and 1000".to_string(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT stable_key, display_name, last_known_path
             FROM item_overlays WHERE favorite = 1
             ORDER BY pinned DESC, updated_at DESC, stable_key LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::from(limit)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut identities = Vec::new();
        for row in rows {
            identities.push(row?);
        }
        drop(statement);
        let keys = identities
            .iter()
            .map(|(stable_key, _, _)| stable_key.clone())
            .collect::<Vec<_>>();
        let mut overlays = self.overlays(&keys)?;
        identities
            .into_iter()
            .map(|(stable_key, display_name, last_known_path)| {
                let overlay = overlays.remove(&stable_key).ok_or_else(|| {
                    SearchError::State(format!(
                        "favorite overlay disappeared while reading {stable_key}"
                    ))
                })?;
                Ok(FavoriteItem {
                    stable_key,
                    display_name,
                    last_known_path,
                    overlay,
                })
            })
            .collect()
    }

    pub fn save_search(
        &mut self,
        id: Option<Uuid>,
        name: &str,
        query: &str,
        pinned: bool,
    ) -> SearchResult<SavedSearch> {
        let name = name.trim();
        let query = query.trim();
        if name.is_empty() || name.chars().count() > 120 || query.is_empty() || query.len() > 4096 {
            return Err(SearchError::Config(
                "saved search name or query is outside supported limits".to_string(),
            ));
        }
        crate::query::ParsedQuery::parse(query)?;
        let id = id.unwrap_or_else(Uuid::new_v4);
        let now = Utc::now().to_rfc3339();
        self.connection.execute(
            "INSERT INTO saved_searches(search_id, name, query, pinned, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(search_id) DO UPDATE SET name = excluded.name,
                query = excluded.query, pinned = excluded.pinned, updated_at = excluded.updated_at",
            params![id.to_string(), name, query, pinned, now],
        )?;
        self.saved_search(id)?.ok_or_else(|| {
            SearchError::State("saved search disappeared after database write".to_string())
        })
    }

    pub fn saved_search(&self, id: Uuid) -> SearchResult<Option<SavedSearch>> {
        self.connection
            .query_row(
                "SELECT search_id, name, query, pinned, created_at, updated_at
                 FROM saved_searches WHERE search_id = ?1",
                [id.to_string()],
                raw_saved_search_row,
            )
            .optional()?
            .map(RawSavedSearch::into_saved_search)
            .transpose()
    }

    pub fn saved_searches(&self) -> SearchResult<Vec<SavedSearch>> {
        let mut statement = self.connection.prepare(
            "SELECT search_id, name, query, pinned, created_at, updated_at
             FROM saved_searches ORDER BY pinned DESC, name COLLATE NOCASE",
        )?;
        let rows = statement.query_map([], raw_saved_search_row)?;
        let mut searches = Vec::new();
        for row in rows {
            searches.push(row?.into_saved_search()?);
        }
        Ok(searches)
    }

    pub fn delete_saved_search(&mut self, id: Uuid) -> SearchResult<bool> {
        Ok(self.connection.execute(
            "DELETE FROM saved_searches WHERE search_id = ?1",
            [id.to_string()],
        )? == 1)
    }

    pub fn write_operation_receipt(&mut self, receipt: &FileOperationReceipt) -> SearchResult<()> {
        validate_receipt(receipt)?;
        self.connection.execute(
            "INSERT INTO file_operation_receipts(
                operation_id, kind, sources_json, destination, state, undo_actions_json,
                progress_json, started_at, completed_at, error_code, message
                , request_fingerprint
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(operation_id) DO UPDATE SET
                state = excluded.state,
                undo_actions_json = excluded.undo_actions_json,
                progress_json = excluded.progress_json,
                completed_at = excluded.completed_at,
                error_code = excluded.error_code,
                message = excluded.message,
                request_fingerprint = excluded.request_fingerprint",
            params![
                receipt.operation_id.to_string(),
                enum_name(&receipt.kind)?,
                serde_json::to_string(&receipt.sources)?,
                receipt.destination,
                enum_name(&receipt.state)?,
                serde_json::to_string(&receipt.undo_actions)?,
                serde_json::to_string(&receipt.progress)?,
                receipt.started_at.to_rfc3339(),
                receipt.completed_at.map(|value| value.to_rfc3339()),
                receipt.error_code,
                receipt.message,
                receipt.request_fingerprint,
            ],
        )?;
        Ok(())
    }

    pub fn operation_receipt(&self, id: Uuid) -> SearchResult<Option<FileOperationReceipt>> {
        let raw: Option<RawOperationReceiptRow> = self
            .connection
            .query_row(
                "SELECT kind, sources_json, destination, state, undo_actions_json,
                            started_at, completed_at, error_code, progress_json, message,
                            request_fingerprint
                     FROM file_operation_receipts WHERE operation_id = ?1",
                [id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?;
        raw.map(|raw| {
            Ok(FileOperationReceipt {
                operation_id: id,
                request_fingerprint: raw.10,
                kind: parse_enum(&raw.0, "file operation kind")?,
                sources: serde_json::from_str(&raw.1)?,
                destination: raw.2,
                state: parse_enum(&raw.3, "file operation state")?,
                undo_actions: serde_json::from_str(&raw.4)?,
                progress: serde_json::from_str(&raw.8)
                    .unwrap_or_else(|_| FileOperationProgress::default()),
                started_at: parse_datetime(&raw.5, "operation started")?,
                completed_at: parse_optional_datetime(raw.6.as_deref(), "operation completed")?,
                error_code: raw.7,
                message: raw.9,
            })
        })
        .transpose()
    }

    pub fn interrupted_operation_receipts(&self) -> SearchResult<Vec<FileOperationReceipt>> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id FROM file_operation_receipts
             WHERE state IN ('running', 'undoing') ORDER BY started_at",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut operation_ids = Vec::new();
        for row in rows {
            operation_ids.push(parse_uuid(&row?, "file operation")?);
        }
        drop(statement);
        operation_ids
            .into_iter()
            .map(|operation_id| {
                self.operation_receipt(operation_id)?.ok_or_else(|| {
                    SearchError::State(format!(
                        "interrupted file operation {operation_id} disappeared"
                    ))
                })
            })
            .collect()
    }

    pub fn doctor(&self) -> SearchResult<CatalogDoctor> {
        let quick_check: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        let schema_version = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(CatalogDoctor {
            healthy: quick_check == "ok" && schema_version == CATALOG_SCHEMA_VERSION,
            schema_version,
            quick_check,
            root_count: count(&self.connection, "source_roots")?,
            overlay_count: count(&self.connection, "item_overlays")?,
            saved_search_count: count(&self.connection, "saved_searches")?,
            receipt_count: count(&self.connection, "file_operation_receipts")?,
        })
    }
}

const ROOT_COLUMNS: &str = "root_id, canonical_path, normalized_path, enabled,
    remote_searchable, exclusions_json, created_at, updated_at,
    last_scan_started_at, last_scan_completed_at, last_scan_generation, last_error_code";
const ROOT_SELECT_BY_ID: &str = "SELECT root_id, canonical_path, normalized_path, enabled,
    remote_searchable, exclusions_json, created_at, updated_at,
    last_scan_started_at, last_scan_completed_at, last_scan_generation, last_error_code
    FROM source_roots WHERE root_id = ?1";
const ROOT_SELECT_ALL: &str = "SELECT root_id, canonical_path, normalized_path, enabled,
    remote_searchable, exclusions_json, created_at, updated_at,
    last_scan_started_at, last_scan_completed_at, last_scan_generation, last_error_code
    FROM source_roots ORDER BY normalized_path";
const ROOT_SELECT_ENABLED: &str = "SELECT root_id, canonical_path, normalized_path, enabled,
    remote_searchable, exclusions_json, created_at, updated_at,
    last_scan_started_at, last_scan_completed_at, last_scan_generation, last_error_code
    FROM source_roots WHERE enabled = 1 ORDER BY normalized_path";

#[allow(dead_code)]
fn _root_columns_contract() -> &'static str {
    ROOT_COLUMNS
}

struct RawRoot {
    id: String,
    canonical_path: String,
    normalized_path: String,
    enabled: bool,
    remote_searchable: bool,
    exclusions_json: String,
    created_at: String,
    updated_at: String,
    last_scan_started_at: Option<String>,
    last_scan_completed_at: Option<String>,
    last_scan_generation: i64,
    last_error_code: Option<String>,
}

impl RawRoot {
    fn into_root(self) -> SearchResult<SourceRoot> {
        Ok(SourceRoot {
            id: parse_uuid(&self.id, "source root")?,
            canonical_path: self.canonical_path,
            normalized_path: self.normalized_path,
            enabled: self.enabled,
            remote_searchable: self.remote_searchable,
            exclusions: serde_json::from_str(&self.exclusions_json)?,
            created_at: parse_datetime(&self.created_at, "root created")?,
            updated_at: parse_datetime(&self.updated_at, "root updated")?,
            last_scan_started_at: parse_optional_datetime(
                self.last_scan_started_at.as_deref(),
                "root scan started",
            )?,
            last_scan_completed_at: parse_optional_datetime(
                self.last_scan_completed_at.as_deref(),
                "root scan completed",
            )?,
            last_scan_generation: checked_u64(self.last_scan_generation, "root scan generation")?,
            last_error_code: self.last_error_code,
        })
    }
}

fn raw_root_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRoot> {
    Ok(RawRoot {
        id: row.get(0)?,
        canonical_path: row.get(1)?,
        normalized_path: row.get(2)?,
        enabled: row.get(3)?,
        remote_searchable: row.get(4)?,
        exclusions_json: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        last_scan_started_at: row.get(8)?,
        last_scan_completed_at: row.get(9)?,
        last_scan_generation: row.get(10)?,
        last_error_code: row.get(11)?,
    })
}

struct RawSavedSearch {
    id: String,
    name: String,
    query: String,
    pinned: bool,
    created_at: String,
    updated_at: String,
}

impl RawSavedSearch {
    fn into_saved_search(self) -> SearchResult<SavedSearch> {
        Ok(SavedSearch {
            id: parse_uuid(&self.id, "saved search")?,
            name: self.name,
            query: self.query,
            pinned: self.pinned,
            created_at: parse_datetime(&self.created_at, "saved search created")?,
            updated_at: parse_datetime(&self.updated_at, "saved search updated")?,
        })
    }
}

fn raw_saved_search_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSavedSearch> {
    Ok(RawSavedSearch {
        id: row.get(0)?,
        name: row.get(1)?,
        query: row.get(2)?,
        pinned: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn validate_exclusions(exclusions: Vec<String>) -> SearchResult<Vec<String>> {
    if exclusions.len() > MAX_ROOT_EXCLUSIONS {
        return Err(SearchError::Config(format!(
            "a root supports at most {MAX_ROOT_EXCLUSIONS} exclusions"
        )));
    }
    let mut unique = BTreeMap::new();
    for exclusion in exclusions {
        let exclusion = exclusion.trim().replace('\\', "/");
        if exclusion.is_empty()
            || exclusion.len() > 512
            || exclusion.contains('\0')
            || Path::new(&exclusion).is_absolute()
        {
            return Err(SearchError::Config(format!(
                "invalid root exclusion '{exclusion}'"
            )));
        }
        unique.insert(exclusion.to_ascii_lowercase(), exclusion);
    }
    Ok(unique.into_values().collect())
}

fn validate_overlay_identity(stable_key: &str, display_name: &str, path: &str) -> SearchResult<()> {
    validate_stable_key(stable_key)?;
    if display_name.chars().count() > 512 || path.len() > 32_768 || path.contains('\0') {
        return Err(SearchError::Config(
            "overlay display name or path is outside supported limits".to_string(),
        ));
    }
    Ok(())
}

fn validate_stable_key(stable_key: &str) -> SearchResult<()> {
    if stable_key.is_empty() || stable_key.len() > 512 || stable_key.contains('\0') {
        return Err(SearchError::Config("stable key is invalid".to_string()));
    }
    Ok(())
}

fn normalize_aliases(aliases: Vec<String>) -> SearchResult<BTreeMap<String, String>> {
    if aliases.len() > MAX_ALIASES {
        return Err(SearchError::Config(format!(
            "an item supports at most {MAX_ALIASES} aliases"
        )));
    }
    let mut normalized = BTreeMap::new();
    for alias in aliases {
        let alias = alias.trim().to_string();
        if alias.is_empty() || alias.chars().count() > 160 || alias.chars().any(char::is_control) {
            return Err(SearchError::Config("item alias is invalid".to_string()));
        }
        normalized.insert(alias.to_lowercase(), alias);
    }
    Ok(normalized)
}

fn validate_code(code: &str) -> SearchResult<()> {
    if code.is_empty()
        || code.len() > 80
        || !code
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(SearchError::Config("error code is invalid".to_string()));
    }
    Ok(())
}

fn validate_receipt(receipt: &FileOperationReceipt) -> SearchResult<()> {
    if receipt.sources.is_empty()
        || receipt.sources.len() > 1024
        || receipt
            .sources
            .iter()
            .any(|path| path.is_empty() || path.len() > 32_768)
        || receipt
            .destination
            .as_ref()
            .is_some_and(|path| path.is_empty() || path.len() > 32_768)
        || receipt.undo_actions.len() > 1024
        || receipt.undo_actions.iter().any(|action| {
            action.source.is_empty()
                || action.source.len() > 32_768
                || action
                    .destination
                    .as_ref()
                    .is_some_and(|path| path.is_empty() || path.len() > 32_768)
                || action
                    .trash_item_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id.len() > 65_536)
        })
        || receipt
            .progress
            .current_path
            .as_ref()
            .is_some_and(|path| path.len() > 32_768)
        || receipt
            .message
            .as_ref()
            .is_some_and(|message| message.len() > 4096)
        || (!receipt.request_fingerprint.is_empty()
            && (receipt.request_fingerprint.len() != 64
                || !receipt
                    .request_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())))
    {
        return Err(SearchError::FileOperation(
            "file operation receipt is outside supported limits".to_string(),
        ));
    }
    if let Some(code) = receipt.error_code.as_deref() {
        validate_code(code)?;
    }
    Ok(())
}

fn enum_name<T: Serialize>(value: &T) -> SearchResult<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(name) => Ok(name),
        _ => Err(SearchError::State(
            "enum did not serialize to a database string".to_string(),
        )),
    }
}

fn parse_enum<T: for<'de> Deserialize<'de>>(value: &str, field: &str) -> SearchResult<T> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|error| SearchError::State(format!("stored {field} is invalid: {error}")))
}

fn parse_datetime(value: &str, field: &str) -> SearchResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            SearchError::State(format!("stored {field} timestamp is invalid: {error}"))
        })
}

fn parse_optional_datetime(
    value: Option<&str>,
    field: &str,
) -> SearchResult<Option<DateTime<Utc>>> {
    value.map(|value| parse_datetime(value, field)).transpose()
}

fn parse_uuid(value: &str, field: &str) -> SearchResult<Uuid> {
    Uuid::parse_str(value)
        .map_err(|error| SearchError::State(format!("stored {field} UUID is invalid: {error}")))
}

fn checked_i64(value: u64, field: &str) -> SearchResult<i64> {
    i64::try_from(value).map_err(|_| SearchError::State(format!("{field} exceeds SQLite range")))
}

fn checked_u64(value: i64, field: &str) -> SearchResult<u64> {
    u64::try_from(value).map_err(|_| SearchError::State(format!("stored {field} is negative")))
}

fn require_changed(changed: usize, entity: &str, id: Uuid) -> SearchResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(SearchError::State(format!("{entity} {id} was not found")))
    }
}

fn count(connection: &Connection, table: &str) -> SearchResult<u64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let value: i64 = connection.query_row(&sql, [], |row| row.get(0))?;
    checked_u64(value, table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FileOperationKind, FileOperationState, UndoAction, UndoActionKind};

    fn catalog() -> (tempfile::TempDir, SearchCatalog) {
        let temp = tempfile::tempdir().expect("tempdir");
        let catalog = SearchCatalog::open(temp.path().join("search.db")).expect("catalog");
        (temp, catalog)
    }

    #[test]
    fn schema_is_healthy_and_does_not_duplicate_the_file_index() {
        let (_temp, catalog) = catalog();
        let doctor = catalog.doctor().unwrap();
        assert!(doctor.healthy);
        assert_eq!(doctor.schema_version, CATALOG_SCHEMA_VERSION);
        let mut statement = catalog
            .connection
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .unwrap();
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(!tables
            .iter()
            .any(|table| matches!(table.as_str(), "files" | "documents")));
        assert!(tables.contains(&"source_roots".to_string()));
        assert!(tables.contains(&"item_overlays".to_string()));
    }

    #[test]
    fn roots_are_canonical_idempotent_and_scanned_transactionally() {
        let (temp, mut catalog) = catalog();
        let root_path = temp.path().join("Media");
        fs::create_dir(&root_path).unwrap();
        let root = catalog
            .add_root(&root_path, false, vec!["Cache/**".to_string()])
            .unwrap();
        let updated = catalog
            .add_root(&root_path, true, vec!["Proxy/**".to_string()])
            .unwrap();
        assert_eq!(root.id, updated.id);
        assert!(updated.remote_searchable);
        assert_eq!(updated.exclusions, ["Proxy/**"]);
        catalog.mark_root_scan_started(root.id).unwrap();
        let state = catalog.mark_root_scan_completed(root.id, 42).unwrap();
        assert_eq!(state.generation, 1);
        assert_eq!(state.indexed_documents, 42);
        assert_eq!(
            catalog.root(root.id).unwrap().unwrap().last_scan_generation,
            1
        );
        assert!(catalog.remove_root(root.id).unwrap());
        assert!(!catalog.remove_root(root.id).unwrap());
    }

    #[test]
    fn sparse_overlays_aliases_and_usage_persist() {
        let (temp, mut catalog) = catalog();
        let key = "volume:file";
        catalog
            .set_favorite(key, "Clip.mov", "C:/Media/Clip.mov", true)
            .unwrap();
        catalog
            .set_pinned(key, "Clip.mov", "C:/Media/Clip.mov", true)
            .unwrap();
        let overlay = catalog
            .set_aliases(
                key,
                vec![
                    "Hero Clip".to_string(),
                    "hero clip".to_string(),
                    "Intro".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(overlay.aliases, ["hero clip", "Intro"]);
        let overlay = catalog.record_usage(key, true).unwrap();
        assert_eq!(overlay.usage_count, 1);
        assert!(overlay.last_selected.is_some());
        let path = temp.path().join("search.db");
        let device_id = catalog.local_device_id().unwrap();
        drop(catalog);
        let mut reopened = SearchCatalog::open(path).unwrap();
        assert_eq!(reopened.local_device_id().unwrap(), device_id);
        let overlay = reopened.overlay(key).unwrap();
        assert!(overlay.favorite && overlay.pinned);
        assert_eq!(overlay.usage_count, 1);
        assert_eq!(overlay.aliases.len(), 2);
    }

    #[test]
    fn saved_searches_and_operation_receipts_round_trip() {
        let (_temp, mut catalog) = catalog();
        let saved = catalog
            .save_search(None, "Recent video", "video: date:week", true)
            .unwrap();
        let searches = catalog.saved_searches().unwrap();
        assert_eq!(searches.len(), 1);
        assert_eq!(searches[0], saved);
        let receipt = FileOperationReceipt {
            operation_id: Uuid::new_v4(),
            request_fingerprint: "a".repeat(64),
            kind: FileOperationKind::Move,
            sources: vec!["C:/A.mov".to_string()],
            destination: Some("C:/Archive".to_string()),
            state: FileOperationState::Complete,
            undo_actions: vec![UndoAction {
                kind: UndoActionKind::MoveBack,
                item_index: 0,
                source: "C:/Archive/A.mov".to_string(),
                destination: Some("C:/A.mov".to_string()),
                expected_identity: None,
                expected_size: Some(12),
                trash_item_id: None,
                trash_deleted_at: None,
                undone: false,
            }],
            progress: FileOperationProgress {
                phase: "complete".to_string(),
                completed_items: 1,
                total_items: 1,
                completed_bytes: 12,
                total_bytes: Some(12),
                current_path: None,
            },
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            error_code: None,
            message: None,
        };
        catalog.write_operation_receipt(&receipt).unwrap();
        assert_eq!(
            catalog.operation_receipt(receipt.operation_id).unwrap(),
            Some(receipt)
        );
        assert!(catalog.delete_saved_search(saved.id).unwrap());
    }

    #[test]
    fn schema_one_receipts_migrate_without_losing_legacy_undo_data() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("legacy.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE file_operation_receipts (
                    operation_id TEXT PRIMARY KEY NOT NULL,
                    kind TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    destination TEXT,
                    state TEXT NOT NULL,
                    undo_actions_json TEXT NOT NULL DEFAULT '[]',
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_code TEXT
                 );
                 CREATE INDEX file_operation_receipts_started
                    ON file_operation_receipts(started_at DESC);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        let operation_id = Uuid::new_v4();
        connection
            .execute(
                "INSERT INTO file_operation_receipts(
                    operation_id, kind, sources_json, destination, state,
                    undo_actions_json, started_at
                 ) VALUES (?1, 'move', '[\"C:/A.mov\"]', 'C:/Archive', 'complete',
                    '[{\"source\":\"C:/Archive/A.mov\",\"destination\":\"C:/A.mov\"}]', ?2)",
                params![operation_id.to_string(), Utc::now().to_rfc3339()],
            )
            .unwrap();
        drop(connection);

        let catalog = SearchCatalog::open(path).unwrap();
        let schema_version: i64 = catalog
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, 2);
        let receipt = catalog.operation_receipt(operation_id).unwrap().unwrap();
        assert_eq!(receipt.state, FileOperationState::Complete);
        assert_eq!(receipt.undo_actions.len(), 1);
        assert_eq!(receipt.undo_actions[0].kind, UndoActionKind::MoveBack);
        assert!(receipt.request_fingerprint.is_empty());
        assert_eq!(receipt.progress, FileOperationProgress::default());
    }
}
