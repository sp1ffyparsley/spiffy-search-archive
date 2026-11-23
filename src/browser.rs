use crate::config::BrowserConfig;
use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{FileCategory, FileRecord, ItemKind};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;

const BROWSER_ROOT_NAMESPACE: Uuid = Uuid::from_u128(0xd5bb9a45_60de_4f4d_a232_203b7b73eb85);
const SNAPSHOT_OWNER_FILE: &str = ".spiffy-search-browser-cache";
const SNAPSHOT_OWNER_VALUE: &[u8] = b"spiffy-search-browser-snapshots-v1\n";
const MAX_PROFILE_DATABASES: usize = 64;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
const SNAPSHOT_STEP_PAGES: i32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProvider {
    Chrome,
    Edge,
    Firefox,
    Safari,
}

impl BrowserProvider {
    pub const ALL: [Self; 4] = [Self::Chrome, Self::Edge, Self::Firefox, Self::Safari];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
        }
    }

    pub fn root_id(self) -> Uuid {
        Uuid::new_v5(&BROWSER_ROOT_NAMESPACE, self.as_str().as_bytes())
    }

    pub const fn enabled(self, config: &BrowserConfig) -> bool {
        match self {
            Self::Chrome => config.chrome,
            Self::Edge => config.edge,
            Self::Firefox => config.firefox,
            Self::Safari => config.safari,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserProviderReport {
    pub provider: BrowserProvider,
    pub enabled: bool,
    pub succeeded: bool,
    pub discovered_profiles: u16,
    pub read_profiles: u16,
    pub source_entries: u64,
    pub indexed_records: u64,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserRefreshReport {
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub providers: Vec<BrowserProviderReport>,
    pub indexed_browser_records: u64,
    pub index_generation: u64,
    pub indexed_documents: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserClearReport {
    pub removed_records: u64,
    pub index_generation: u64,
    pub indexed_documents: u64,
}

impl BrowserRefreshReport {
    pub(crate) fn from_collection(collection: &BrowserCollection) -> Self {
        Self {
            started_at: collection.started_at,
            completed_at: Utc::now(),
            providers: collection.reports.clone(),
            indexed_browser_records: 0,
            index_generation: 0,
            indexed_documents: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct BrowserSnapshot {
    pub provider: BrowserProvider,
    pub records: Vec<FileRecord>,
}

#[derive(Debug)]
pub(crate) struct BrowserCollection {
    pub started_at: DateTime<Utc>,
    pub snapshots: Vec<BrowserSnapshot>,
    pub reports: Vec<BrowserProviderReport>,
}

#[derive(Debug, Clone)]
struct RawVisit {
    url: String,
    title: String,
    last_visit: DateTime<Utc>,
    visit_count: u64,
}

pub fn enabled_providers(config: &BrowserConfig) -> Vec<BrowserProvider> {
    BrowserProvider::ALL
        .into_iter()
        .filter(|provider| provider.enabled(config))
        .collect()
}

pub fn any_enabled(config: &BrowserConfig) -> bool {
    BrowserProvider::ALL
        .into_iter()
        .any(|provider| provider.enabled(config))
}

pub(crate) fn collect_enabled(
    config: &BrowserConfig,
    device_id: Uuid,
    cache_dir: &Path,
    cancellation: &AtomicBool,
) -> SearchResult<BrowserCollection> {
    prepare_snapshot_cache(cache_dir)?;
    let started_at = Utc::now();
    let cutoff = started_at - ChronoDuration::days(i64::from(config.retention_days));
    let mut collection = BrowserCollection {
        started_at,
        snapshots: Vec::new(),
        reports: Vec::new(),
    };
    for provider in BrowserProvider::ALL {
        if cancellation.load(Ordering::Acquire) {
            return Err(SearchError::Browser(
                "browser history refresh was cancelled".to_string(),
            ));
        }
        if !provider.enabled(config) {
            collection.snapshots.push(BrowserSnapshot {
                provider,
                records: Vec::new(),
            });
            collection.reports.push(BrowserProviderReport {
                provider,
                enabled: false,
                succeeded: true,
                discovered_profiles: 0,
                read_profiles: 0,
                source_entries: 0,
                indexed_records: 0,
                error_code: None,
                message: None,
            });
            continue;
        }
        let sources = match discover_databases(provider) {
            Ok(sources) => sources,
            Err(error) => {
                collection
                    .reports
                    .push(failed_report(provider, 0, 0, &error));
                continue;
            }
        };
        let discovered_profiles = sources.len().min(usize::from(u16::MAX)) as u16;
        match collect_provider(
            provider,
            &sources,
            device_id,
            cache_dir,
            cutoff,
            config.max_entries_per_browser,
            cancellation,
        ) {
            Ok((records, source_entries)) => {
                let indexed_records = records.len() as u64;
                collection
                    .snapshots
                    .push(BrowserSnapshot { provider, records });
                collection.reports.push(BrowserProviderReport {
                    provider,
                    enabled: true,
                    succeeded: true,
                    discovered_profiles,
                    read_profiles: discovered_profiles,
                    source_entries,
                    indexed_records,
                    error_code: None,
                    message: None,
                });
            }
            Err(error) => {
                collection
                    .reports
                    .push(failed_report(provider, discovered_profiles, 0, &error))
            }
        }
    }
    Ok(collection)
}

fn failed_report(
    provider: BrowserProvider,
    discovered_profiles: u16,
    read_profiles: u16,
    error: &SearchError,
) -> BrowserProviderReport {
    BrowserProviderReport {
        provider,
        enabled: true,
        succeeded: false,
        discovered_profiles,
        read_profiles,
        source_entries: 0,
        indexed_records: 0,
        error_code: Some("browser_source_failed".to_string()),
        message: Some(error.to_string()),
    }
}

fn collect_provider(
    provider: BrowserProvider,
    sources: &[PathBuf],
    device_id: Uuid,
    cache_dir: &Path,
    cutoff: DateTime<Utc>,
    limit: u32,
    cancellation: &AtomicBool,
) -> SearchResult<(Vec<FileRecord>, u64)> {
    let mut visits = HashMap::<String, RawVisit>::new();
    let mut source_entries = 0_u64;
    for source in sources {
        if cancellation.load(Ordering::Acquire) {
            return Err(SearchError::Browser(
                "browser history refresh was cancelled".to_string(),
            ));
        }
        let extracted = with_snapshot(
            source,
            cache_dir,
            cancellation,
            |connection| match provider {
                BrowserProvider::Chrome | BrowserProvider::Edge => {
                    read_chromium(connection, cutoff, limit)
                }
                BrowserProvider::Firefox => read_firefox(connection, cutoff, limit),
                BrowserProvider::Safari => read_safari(connection, cutoff, limit),
            },
        )?;
        source_entries = source_entries.saturating_add(extracted.len() as u64);
        merge_visits(&mut visits, extracted, limit as usize);
    }
    let mut visits = visits.into_values().collect::<Vec<_>>();
    visits.sort_by(|left, right| {
        right
            .last_visit
            .cmp(&left.last_visit)
            .then_with(|| left.url.cmp(&right.url))
    });
    visits.truncate(limit as usize);
    let records = visits
        .into_iter()
        .filter_map(|visit| visit_to_record(provider, device_id, visit))
        .collect::<Vec<_>>();
    Ok((records, source_entries))
}

fn merge_visits(visits: &mut HashMap<String, RawVisit>, incoming: Vec<RawVisit>, limit: usize) {
    for visit in incoming {
        match visits.get_mut(&visit.url) {
            Some(existing) => {
                existing.visit_count = existing.visit_count.saturating_add(visit.visit_count);
                if visit.last_visit > existing.last_visit {
                    existing.last_visit = visit.last_visit;
                    if !visit.title.is_empty() {
                        existing.title = visit.title;
                    }
                }
            }
            None => {
                visits.insert(visit.url.clone(), visit);
            }
        }
    }
    if visits.len() > limit.saturating_mul(2) {
        let mut newest = visits.drain().map(|(_, visit)| visit).collect::<Vec<_>>();
        newest.sort_by_key(|visit| std::cmp::Reverse(visit.last_visit));
        newest.truncate(limit);
        visits.extend(newest.into_iter().map(|visit| (visit.url.clone(), visit)));
    }
}

fn visit_to_record(
    provider: BrowserProvider,
    device_id: Uuid,
    visit: RawVisit,
) -> Option<FileRecord> {
    let mut parsed = Url::parse(&visit.url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_fragment(None);
    let canonical_url = parsed.to_string();
    if canonical_url.len() > 32_768 {
        return None;
    }
    let host = parsed.host_str().unwrap_or_default().to_string();
    let title = bounded_title(if visit.title.trim().is_empty() {
        if host.is_empty() {
            canonical_url.as_str()
        } else {
            host.as_str()
        }
    } else {
        visit.title.trim()
    });
    let path_tokens = parsed
        .path_segments()
        .into_iter()
        .flatten()
        .flat_map(|segment| segment.split(['-', '_', '.', '/']))
        .filter(|segment| !segment.is_empty())
        .take(128)
        .collect::<Vec<_>>()
        .join(" ");
    let parent_tokens = format!("{host} {path_tokens}").trim().to_string();
    let stable_digest = blake3::hash(format!("{}\0{canonical_url}", provider.as_str()).as_bytes());
    Some(FileRecord {
        stable_key: format!("browser:{}:{}", provider.as_str(), stable_digest.to_hex()),
        stable_file_id: None,
        root_id: provider.root_id(),
        device_id,
        canonical_path: canonical_url.clone(),
        display_path: canonical_url.clone(),
        normalized_path: canonical_url.to_lowercase(),
        filename: title.clone(),
        filename_stem: title,
        extension: String::new(),
        parent_path: host.clone(),
        parent_tokens,
        item_kind: ItemKind::Browser,
        category: FileCategory::Other,
        content_type: "browser_history".to_string(),
        mime_type: "text/html".to_string(),
        size: 0,
        created_time: None,
        modified_time: Some(visit.last_visit),
        last_seen_time: Utc::now(),
        hidden: false,
        system: false,
        package: false,
        application: false,
        folder: false,
        file: false,
        cloud_placeholder: false,
        offline: false,
        missing: false,
        tombstone: false,
        source_provider: format!("browser:{}", provider.as_str()),
        remote_device: None,
        content_index_state: "not_applicable".to_string(),
        preview_state: "url".to_string(),
        tags: vec![
            provider.as_str().to_string(),
            host,
            format!("visits:{}", visit.visit_count),
        ],
    })
}

fn bounded_title(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(1024)
        .collect()
}

fn read_chromium(
    connection: &Connection,
    cutoff: DateTime<Utc>,
    limit: u32,
) -> SearchResult<Vec<RawVisit>> {
    const CHROMIUM_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;
    let cutoff = cutoff
        .timestamp_micros()
        .saturating_add(CHROMIUM_EPOCH_OFFSET_MICROS);
    let mut statement = connection.prepare(
        "SELECT url, COALESCE(title, ''), last_visit_time, visit_count
         FROM urls
         WHERE last_visit_time >= ?1 AND (url LIKE 'http://%' OR url LIKE 'https://%')
         ORDER BY last_visit_time DESC, id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![cutoff, i64::from(limit)], |row| {
        let timestamp: i64 = row.get(2)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            timestamp.saturating_sub(CHROMIUM_EPOCH_OFFSET_MICROS),
            row.get::<_, i64>(3).unwrap_or(0).max(0) as u64,
        ))
    })?;
    collect_timestamped_rows(rows)
}

fn read_firefox(
    connection: &Connection,
    cutoff: DateTime<Utc>,
    limit: u32,
) -> SearchResult<Vec<RawVisit>> {
    let mut statement = connection.prepare(
        "SELECT url, COALESCE(title, ''), last_visit_date, visit_count
         FROM moz_places
         WHERE last_visit_date >= ?1 AND (url LIKE 'http://%' OR url LIKE 'https://%')
         ORDER BY last_visit_date DESC, id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![cutoff.timestamp_micros(), i64::from(limit)],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3).unwrap_or(0).max(0) as u64,
            ))
        },
    )?;
    collect_timestamped_rows(rows)
}

fn collect_timestamped_rows(
    rows: rusqlite::MappedRows<
        '_,
        impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<(String, String, i64, u64)>,
    >,
) -> SearchResult<Vec<RawVisit>> {
    let mut visits = Vec::new();
    for row in rows {
        let (url, title, micros, visit_count) = row?;
        if let Some(last_visit) = DateTime::from_timestamp_micros(micros) {
            visits.push(RawVisit {
                url,
                title,
                last_visit,
                visit_count,
            });
        }
    }
    Ok(visits)
}

fn read_safari(
    connection: &Connection,
    cutoff: DateTime<Utc>,
    limit: u32,
) -> SearchResult<Vec<RawVisit>> {
    const SAFARI_EPOCH_OFFSET_SECONDS: f64 = 978_307_200.0;
    let cutoff = cutoff.timestamp_micros() as f64 / 1_000_000.0 - SAFARI_EPOCH_OFFSET_SECONDS;
    let mut statement = connection.prepare(
        "SELECT history_items.url, COALESCE(history_visits.title, ''),
                history_visits.visit_time
         FROM history_visits
         JOIN history_items ON history_items.id = history_visits.history_item
         WHERE history_visits.visit_time >= ?1
           AND (history_items.url LIKE 'http://%' OR history_items.url LIKE 'https://%')
         ORDER BY history_visits.visit_time DESC, history_visits.id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![cutoff, i64::from(limit)], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, f64>(2)?,
        ))
    })?;
    let mut visits = Vec::new();
    for row in rows {
        let (url, title, safari_seconds) = row?;
        let unix_micros = ((safari_seconds + SAFARI_EPOCH_OFFSET_SECONDS) * 1_000_000.0) as i64;
        if let Some(last_visit) = DateTime::from_timestamp_micros(unix_micros) {
            visits.push(RawVisit {
                url,
                title,
                last_visit,
                visit_count: 1,
            });
        }
    }
    Ok(visits)
}

fn with_snapshot<T>(
    source: &Path,
    cache_dir: &Path,
    cancellation: &AtomicBool,
    read: impl FnOnce(&Connection) -> SearchResult<T>,
) -> SearchResult<T> {
    let metadata = fs::symlink_metadata(source).map_err(|error| io_error(source, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SearchError::Browser(format!(
            "history database is not a normal file: {}",
            source.display()
        )));
    }
    let snapshot_dir = tempfile::Builder::new()
        .prefix("snapshot-")
        .tempdir_in(cache_dir)
        .map_err(|error| io_error(cache_dir, error))?;
    let snapshot_path = snapshot_dir.path().join("history.sqlite");
    let source_connection = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    source_connection.busy_timeout(Duration::from_millis(500))?;
    let mut destination = Connection::open(&snapshot_path)?;
    {
        let backup = Backup::new(&source_connection, &mut destination)?;
        let deadline = Instant::now() + SNAPSHOT_TIMEOUT;
        loop {
            if cancellation.load(Ordering::Acquire) {
                return Err(SearchError::Browser(
                    "browser history refresh was cancelled".to_string(),
                ));
            }
            match backup.step(SNAPSHOT_STEP_PAGES)? {
                StepResult::Done => break,
                StepResult::More => std::thread::sleep(Duration::from_millis(1)),
                StepResult::Busy | StepResult::Locked if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                StepResult::Busy | StepResult::Locked => {
                    return Err(SearchError::Browser(
                        "history database snapshot timed out while the browser was writing"
                            .to_string(),
                    ));
                }
                _ => {
                    return Err(SearchError::Browser(
                        "history database snapshot returned an unsupported state".to_string(),
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(SearchError::Browser(
                    "history database snapshot exceeded its time limit".to_string(),
                ));
            }
        }
    }
    drop(destination);
    drop(source_connection);
    let snapshot = Connection::open_with_flags(
        &snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    snapshot.pragma_update(None, "query_only", true)?;
    read(&snapshot)
}

fn prepare_snapshot_cache(path: &Path) -> SearchResult<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(SearchError::Browser(format!(
                "browser snapshot cache is not a normal directory: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
    }
    let marker = path.join(SNAPSHOT_OWNER_FILE);
    if marker.exists() {
        if fs::read(&marker).map_err(|error| io_error(&marker, error))? != SNAPSHOT_OWNER_VALUE {
            return Err(SearchError::Browser(format!(
                "browser snapshot cache owner marker is invalid: {}",
                marker.display()
            )));
        }
    } else {
        if fs::read_dir(path)
            .map_err(|error| io_error(path, error))?
            .next()
            .is_some()
        {
            return Err(SearchError::Browser(format!(
                "refusing to claim nonempty browser snapshot cache: {}",
                path.display()
            )));
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&marker)
            .map_err(|error| io_error(&marker, error))?;
        file.write_all(SNAPSHOT_OWNER_VALUE)
            .map_err(|error| io_error(&marker, error))?;
        file.sync_all().map_err(|error| io_error(&marker, error))?;
    }
    cleanup_stale_snapshots(path)
}

pub(crate) fn clear_snapshot_cache(path: &Path) -> SearchResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SearchError::Browser(format!(
            "refusing to clear a browser snapshot cache that is not a normal directory: {}",
            path.display()
        )));
    }
    let marker = path.join(SNAPSHOT_OWNER_FILE);
    if fs::read(&marker).map_err(|error| io_error(&marker, error))? != SNAPSHOT_OWNER_VALUE {
        return Err(SearchError::Browser(format!(
            "refusing to clear a browser snapshot cache without its valid owner marker: {}",
            path.display()
        )));
    }
    cleanup_stale_snapshots(path)?;
    for entry in fs::read_dir(path).map_err(|error| io_error(path, error))? {
        let entry = entry.map_err(|error| io_error(path, error))?;
        if entry.path() != marker {
            return Err(SearchError::Browser(format!(
                "refusing to clear an unexpected browser snapshot cache entry: {}",
                entry.path().display()
            )));
        }
    }
    fs::remove_file(&marker).map_err(|error| io_error(&marker, error))?;
    fs::remove_dir(path).map_err(|error| io_error(path, error))?;
    Ok(())
}

fn cleanup_stale_snapshots(path: &Path) -> SearchResult<()> {
    for entry in fs::read_dir(path).map_err(|error| io_error(path, error))? {
        let entry = entry.map_err(|error| io_error(path, error))?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("snapshot-") {
            continue;
        }
        let metadata = entry
            .file_type()
            .map_err(|error| io_error(entry.path(), error))?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err(SearchError::Browser(format!(
                "refusing unexpected browser snapshot cache entry: {}",
                entry.path().display()
            )));
        }
        fs::remove_dir_all(entry.path()).map_err(|error| io_error(entry.path(), error))?;
    }
    Ok(())
}

fn discover_databases(provider: BrowserProvider) -> SearchResult<Vec<PathBuf>> {
    let mut databases = match provider {
        BrowserProvider::Chrome => discover_chromium(chrome_user_data_roots()),
        BrowserProvider::Edge => discover_chromium(edge_user_data_roots()),
        BrowserProvider::Firefox => discover_firefox(firefox_profile_roots()),
        BrowserProvider::Safari => safari_history_paths(),
    }?;
    databases.sort();
    databases.dedup();
    databases.truncate(MAX_PROFILE_DATABASES);
    Ok(databases)
}

fn discover_chromium(roots: Vec<PathBuf>) -> SearchResult<Vec<PathBuf>> {
    let mut databases = Vec::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&root).map_err(|error| io_error(&root, error))? {
            let entry = entry.map_err(|error| io_error(&root, error))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "Default" && !name.starts_with("Profile ") {
                continue;
            }
            let history = entry.path().join("History");
            if history.is_file() {
                databases.push(history);
                if databases.len() >= MAX_PROFILE_DATABASES {
                    return Ok(databases);
                }
            }
        }
    }
    Ok(databases)
}

fn discover_firefox(roots: Vec<PathBuf>) -> SearchResult<Vec<PathBuf>> {
    let mut databases = Vec::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&root).map_err(|error| io_error(&root, error))? {
            let entry = entry.map_err(|error| io_error(&root, error))?;
            let places = entry.path().join("places.sqlite");
            if places.is_file() {
                databases.push(places);
                if databases.len() >= MAX_PROFILE_DATABASES {
                    return Ok(databases);
                }
            }
        }
    }
    Ok(databases)
}

#[cfg(windows)]
fn chrome_user_data_roots() -> Vec<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("Google").join("Chrome").join("User Data"))
        .into_iter()
        .collect()
}

#[cfg(target_os = "macos")]
fn chrome_user_data_roots() -> Vec<PathBuf> {
    home_dir()
        .map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("Google")
                .join("Chrome")
        })
        .into_iter()
        .collect()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn chrome_user_data_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn edge_user_data_roots() -> Vec<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("Microsoft").join("Edge").join("User Data"))
        .into_iter()
        .collect()
}

#[cfg(target_os = "macos")]
fn edge_user_data_roots() -> Vec<PathBuf> {
    home_dir()
        .map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("Microsoft Edge")
        })
        .into_iter()
        .collect()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn edge_user_data_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn firefox_profile_roots() -> Vec<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("Mozilla").join("Firefox").join("Profiles"))
        .into_iter()
        .collect()
}

#[cfg(target_os = "macos")]
fn firefox_profile_roots() -> Vec<PathBuf> {
    home_dir()
        .map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("Firefox")
                .join("Profiles")
        })
        .into_iter()
        .collect()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn firefox_profile_roots() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(target_os = "macos")]
fn safari_history_paths() -> SearchResult<Vec<PathBuf>> {
    Ok(home_dir()
        .map(|home| home.join("Library").join("Safari").join("History.db"))
        .filter(|path| path.is_file())
        .into_iter()
        .collect())
}

#[cfg(not(target_os = "macos"))]
fn safari_history_paths() -> SearchResult<Vec<PathBuf>> {
    Ok(Vec::new())
}

#[cfg(target_os = "macos")]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chromium_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE urls (
                    id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    title TEXT,
                    visit_count INTEGER NOT NULL,
                    last_visit_time INTEGER NOT NULL
                 );",
            )
            .unwrap();
        let now = Utc::now().timestamp_micros() + 11_644_473_600_000_000_i64;
        connection
            .execute(
                "INSERT INTO urls(url, title, visit_count, last_visit_time)
                 VALUES (?1, ?2, 4, ?3), ('chrome://settings', 'Settings', 1, ?3)",
                params![
                    "https://user:password@example.com/projects/hero?take=2#cut",
                    "Hero Project",
                    now
                ],
            )
            .unwrap();
    }

    fn firefox_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE moz_places (
                    id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL,
                    title TEXT,
                    visit_count INTEGER NOT NULL,
                    last_visit_date INTEGER
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO moz_places(url, title, visit_count, last_visit_date)
                 VALUES ('https://mozilla.example/reference', 'Firefox Reference', 2, ?1)",
                [Utc::now().timestamp_micros()],
            )
            .unwrap();
    }

    fn safari_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT NOT NULL);
                 CREATE TABLE history_visits (
                    id INTEGER PRIMARY KEY,
                    history_item INTEGER NOT NULL,
                    title TEXT,
                    visit_time REAL NOT NULL
                 );",
            )
            .unwrap();
        let safari_time = Utc::now().timestamp_micros() as f64 / 1_000_000.0 - 978_307_200.0;
        connection
            .execute(
                "INSERT INTO history_items(id, url) VALUES (1, 'https://apple.example/guide')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO history_visits(history_item, title, visit_time)
                 VALUES (1, 'Safari Guide', ?1)",
                [safari_time],
            )
            .unwrap();
    }

    #[test]
    fn snapshots_and_extracts_supported_browser_schemas_without_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        prepare_snapshot_cache(&cache).unwrap();
        let device = Uuid::new_v4();
        let cutoff = Utc::now() - ChronoDuration::days(1);
        for (provider, create, expected_title) in [
            (
                BrowserProvider::Chrome,
                chromium_database as fn(&Path),
                "Hero Project",
            ),
            (
                BrowserProvider::Firefox,
                firefox_database,
                "Firefox Reference",
            ),
            (BrowserProvider::Safari, safari_database, "Safari Guide"),
        ] {
            let database = temp.path().join(format!("{}.sqlite", provider.as_str()));
            create(&database);
            let (records, source_entries) = collect_provider(
                provider,
                &[database],
                device,
                &cache,
                cutoff,
                100,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(source_entries, 1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].filename, expected_title);
            assert_eq!(records[0].item_kind, ItemKind::Browser);
            assert!(!records[0].canonical_path.contains("password"));
            assert!(!records[0].canonical_path.contains('#'));
        }
        assert_eq!(
            fs::read_dir(&cache).unwrap().count(),
            1,
            "temporary snapshot directories must be removed"
        );
    }

    #[test]
    fn duplicate_urls_keep_latest_title_and_accumulate_visits() {
        let now = Utc::now();
        let mut visits = HashMap::new();
        merge_visits(
            &mut visits,
            vec![RawVisit {
                url: "https://example.com".to_string(),
                title: "Old".to_string(),
                last_visit: now - ChronoDuration::minutes(1),
                visit_count: 2,
            }],
            10,
        );
        merge_visits(
            &mut visits,
            vec![RawVisit {
                url: "https://example.com".to_string(),
                title: "New".to_string(),
                last_visit: now,
                visit_count: 3,
            }],
            10,
        );
        let visit = visits.values().next().unwrap();
        assert_eq!(visit.title, "New");
        assert_eq!(visit.visit_count, 5);
    }

    #[test]
    fn nonempty_unowned_snapshot_cache_is_never_claimed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("unrelated.txt"), b"keep").unwrap();
        assert!(prepare_snapshot_cache(temp.path()).is_err());
        assert_eq!(
            fs::read(temp.path().join("unrelated.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn pre_cancelled_refresh_stops_before_browser_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let config = BrowserConfig {
            chrome: true,
            ..BrowserConfig::default()
        };
        let error =
            collect_enabled(&config, Uuid::new_v4(), &cache, &AtomicBool::new(true)).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert_eq!(fs::read_dir(cache).unwrap().count(), 1);
    }

    #[test]
    fn clear_removes_only_an_owned_snapshot_cache() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        prepare_snapshot_cache(&cache).unwrap();
        let stale = cache.join("snapshot-stale");
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("history.sqlite"), b"temporary history").unwrap();
        clear_snapshot_cache(&cache).unwrap();
        assert!(!cache.exists());

        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("unrelated.txt"), b"keep").unwrap();
        assert!(clear_snapshot_cache(&cache).is_err());
        assert_eq!(fs::read(cache.join("unrelated.txt")).unwrap(), b"keep");
    }
}
