use crate::error::{io_error, SearchError, SearchResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

pub const CONFIG_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SearchConfig {
    pub schema_version: u16,
    pub start_hidden: bool,
    pub scan_workers: u8,
    pub index_writer_memory_mb: u16,
    pub index_batch_size: u16,
    pub max_results: u16,
    pub candidate_multiplier: u8,
    pub watcher_debounce_ms: u16,
    pub watcher_channel_capacity: u16,
    pub reconciliation_minutes: u16,
    pub include_hidden: bool,
    pub include_system: bool,
    pub initial_scan_on_start: bool,
    pub workspace_catalog_path: Option<PathBuf>,
    pub content: ContentConfig,
    pub local_api: LocalApiConfig,
    pub browsers: BrowserConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContentConfig {
    pub enabled: bool,
    pub max_file_bytes: u64,
    pub max_extracted_bytes: u64,
    pub timeout_seconds: u16,
    pub workers: u8,
    pub extensions: Vec<String>,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalApiConfig {
    pub enabled: bool,
    pub port: u16,
    pub requests_per_minute: u16,
    pub max_body_bytes: u32,
    pub allow_preview_text: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserConfig {
    pub chrome: bool,
    pub edge: bool,
    pub firefox: bool,
    pub safari: bool,
    pub refresh_minutes: u16,
    pub retention_days: u16,
    pub max_entries_per_browser: u32,
}

impl Default for SearchConfig {
    fn default() -> Self {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4);
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            start_hidden: true,
            scan_workers: parallelism.clamp(2, 12) as u8,
            index_writer_memory_mb: 96,
            index_batch_size: 512,
            max_results: 200,
            candidate_multiplier: 8,
            watcher_debounce_ms: 250,
            watcher_channel_capacity: 2048,
            reconciliation_minutes: 360,
            include_hidden: false,
            include_system: false,
            initial_scan_on_start: true,
            workspace_catalog_path: None,
            content: ContentConfig::default(),
            local_api: LocalApiConfig::default(),
            browsers: BrowserConfig::default(),
        }
    }
}

impl Default for ContentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_bytes: 64 * 1024 * 1024,
            max_extracted_bytes: 4 * 1024 * 1024,
            timeout_seconds: 15,
            workers: 2,
            extensions: [
                "txt", "md", "rs", "py", "js", "ts", "tsx", "jsx", "css", "toml", "yaml", "yml",
                "c", "cpp", "h", "hpp", "cs", "java", "swift", "kt", "go", "rb", "php", "sh",
                "ps1", "ahk", "json", "xml", "csv", "html", "htm", "rtf", "srt", "vtt", "pdf",
                "docx", "pptx", "xlsx", "odt", "ods", "odp", "epub",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            exclusions: Vec::new(),
        }
    }
}

impl Default for LocalApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 0,
            requests_per_minute: 120,
            max_body_bytes: 64 * 1024,
            allow_preview_text: false,
        }
    }
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            chrome: false,
            edge: false,
            firefox: false,
            safari: false,
            refresh_minutes: 15,
            retention_days: 365,
            max_entries_per_browser: 100_000,
        }
    }
}

impl SearchConfig {
    pub fn load_or_create(path: &Path) -> SearchResult<Self> {
        if !path.exists() {
            let config = Self::default();
            config.save(path)?;
            return Ok(config);
        }
        let encoded = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
        let original: serde_json::Value = serde_json::from_str(&encoded)?;
        let config: Self = serde_json::from_value(original.clone())?;
        config.validate()?;
        if original != serde_json::to_value(&config)? {
            config.save(path)?;
            tracing::info!(config = %path.display(), "Search configuration defaults normalized");
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> SearchResult<()> {
        self.validate()?;
        let parent = path.parent().ok_or_else(|| {
            SearchError::Config(format!(
                "configuration path has no parent: {}",
                path.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
        let encoded = serde_json::to_vec_pretty(self)?;
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|error| io_error(parent, error))?;
        temporary
            .write_all(&encoded)
            .map_err(|error| io_error(temporary.path(), error))?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|error| io_error(temporary.path(), error))?;
        temporary
            .persist(path)
            .map_err(|error| io_error(path, error.error))?;
        Ok(())
    }

    pub fn validate(&self) -> SearchResult<()> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(SearchError::Config(format!(
                "unsupported configuration schema {}",
                self.schema_version
            )));
        }
        if !(1..=32).contains(&self.scan_workers) {
            return Err(SearchError::Config(
                "scan_workers must be between 1 and 32".to_string(),
            ));
        }
        if !(32..=1024).contains(&self.index_writer_memory_mb) {
            return Err(SearchError::Config(
                "index_writer_memory_mb must be between 32 and 1024".to_string(),
            ));
        }
        if !(32..=4096).contains(&self.index_batch_size)
            || !(10..=1000).contains(&self.max_results)
            || !(2..=32).contains(&self.candidate_multiplier)
        {
            return Err(SearchError::Config(
                "index/query batch settings are outside supported bounds".to_string(),
            ));
        }
        if !(100..=5000).contains(&self.watcher_debounce_ms)
            || !(128..=16_384).contains(&self.watcher_channel_capacity)
            || !(5..=1440).contains(&self.reconciliation_minutes)
        {
            return Err(SearchError::Config(
                "watcher timing or capacity is outside supported bounds".to_string(),
            ));
        }
        if self
            .workspace_catalog_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(SearchError::Config(
                "workspace_catalog_path must be an absolute path".to_string(),
            ));
        }
        self.content.validate()?;
        self.local_api.validate()?;
        self.browsers.validate()?;
        Ok(())
    }
}

impl ContentConfig {
    pub(crate) fn validate(&self) -> SearchResult<()> {
        if !(64 * 1024..=1024 * 1024 * 1024).contains(&self.max_file_bytes)
            || !(4 * 1024..=32 * 1024 * 1024).contains(&self.max_extracted_bytes)
            || !(1..=120).contains(&self.timeout_seconds)
            || !(1..=8).contains(&self.workers)
            || self.extensions.len() > 256
            || self.exclusions.len() > 256
            || self.extensions.iter().any(|extension| {
                extension.is_empty()
                    || extension.len() > 20
                    || !extension
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric())
                    || !crate::content_extractor::supported_extension(extension)
            })
            || self
                .exclusions
                .iter()
                .any(|pattern| pattern.is_empty() || pattern.len() > 1024)
        {
            return Err(SearchError::Config(
                "content extraction limits or extensions are invalid".to_string(),
            ));
        }
        let mut overrides = ignore::overrides::OverrideBuilder::new(".");
        for exclusion in &self.exclusions {
            overrides.add(&format!("!{exclusion}")).map_err(|error| {
                SearchError::Config(format!("invalid content exclusion '{exclusion}': {error}"))
            })?;
        }
        overrides
            .build()
            .map_err(|error| SearchError::Config(format!("invalid content exclusions: {error}")))?;
        Ok(())
    }
}

impl LocalApiConfig {
    pub(crate) fn validate(&self) -> SearchResult<()> {
        if !(10..=10_000).contains(&self.requests_per_minute)
            || !(1024..=1024 * 1024).contains(&self.max_body_bytes)
        {
            return Err(SearchError::Config(
                "local API rate or body limit is outside supported bounds".to_string(),
            ));
        }
        Ok(())
    }
}

impl BrowserConfig {
    fn validate(&self) -> SearchResult<()> {
        if !(1..=1440).contains(&self.refresh_minutes)
            || !(1..=3650).contains(&self.retention_days)
            || !(100..=500_000).contains(&self.max_entries_per_browser)
        {
            return Err(SearchError::Config(
                "browser refresh, retention, or entry limits are outside supported bounds"
                    .to_string(),
            ));
        }
        #[cfg(not(target_os = "macos"))]
        if self.safari {
            return Err(SearchError::Config(
                "Safari history is available only on macOS".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn data_dir() -> PathBuf {
    spiffy_shared::product_data_dir(spiffy_shared::Product::Search)
}

pub fn cache_dir() -> PathBuf {
    spiffy_shared::product_cache_dir(spiffy_shared::Product::Search)
}

pub fn config_path() -> PathBuf {
    data_dir().join("search-config.json")
}

pub fn database_path() -> PathBuf {
    data_dir().join("search.db")
}

pub fn filename_index_path() -> PathBuf {
    data_dir().join("indexes").join("filename")
}

pub fn content_index_path() -> PathBuf {
    data_dir().join("indexes").join("content")
}

pub fn browser_snapshot_cache_dir() -> PathBuf {
    cache_dir().join("browser-snapshots")
}

pub fn local_api_endpoint_path() -> PathBuf {
    data_dir().join("local-api-endpoint.json")
}

pub fn ipc_endpoint_path() -> PathBuf {
    data_dir().join("ipc-endpoint.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_private_bounded_and_valid() {
        let config = SearchConfig::default();
        config.validate().unwrap();
        assert!(!config.local_api.enabled);
        assert!(!config.content.enabled);
        assert!(!config.browsers.chrome);
        assert!(config.workspace_catalog_path.is_none());
        assert!(config.scan_workers <= 12);

        let mut unsupported = config;
        unsupported.content.extensions.push("doc".to_string());
        assert!(unsupported.validate().is_err());
    }

    #[test]
    fn round_trip_is_atomic_and_unknown_fields_fail() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("search-config.json");
        let config = SearchConfig::default();
        config.save(&path).unwrap();
        assert_eq!(SearchConfig::load_or_create(&path).unwrap(), config);
        let invalid = serde_json::json!({"schema_version": 1, "unknown": true});
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(SearchConfig::load_or_create(&path).is_err());
    }

    #[test]
    fn older_browser_configurations_receive_new_bounded_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("search-config.json");
        let mut encoded = serde_json::to_value(SearchConfig::default()).unwrap();
        let browsers = encoded["browsers"].as_object_mut().unwrap();
        browsers.remove("retention_days");
        browsers.remove("max_entries_per_browser");
        fs::write(&path, serde_json::to_vec(&encoded).unwrap()).unwrap();

        let config = SearchConfig::load_or_create(&path).unwrap();
        assert_eq!(config.browsers.retention_days, 365);
        assert_eq!(config.browsers.max_entries_per_browser, 100_000);
        config.validate().unwrap();
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(persisted["browsers"]["retention_days"], 365);
        assert_eq!(persisted["browsers"]["max_entries_per_browser"], 100_000);
    }

    #[test]
    fn workspace_catalog_path_is_optional_and_absolute_when_configured() {
        let mut config = SearchConfig {
            workspace_catalog_path: Some(PathBuf::from("relative/workspace_catalog.json")),
            ..SearchConfig::default()
        };
        assert!(config.validate().is_err());

        let absolute = std::env::current_dir()
            .unwrap()
            .join("workspace_catalog.json");
        config.workspace_catalog_path = Some(absolute.clone());
        config.validate().unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(
            encoded["workspace_catalog_path"],
            serde_json::Value::String(absolute.to_string_lossy().to_string())
        );
    }

    #[test]
    fn product_paths_stay_under_search_owner() {
        let root = spiffy_shared::product_data_dir(spiffy_shared::Product::Search);
        assert!(config_path().starts_with(&root));
        assert!(filename_index_path().starts_with(&root));
        assert!(local_api_endpoint_path().starts_with(&root));
        assert!(browser_snapshot_cache_dir().starts_with(cache_dir()));
        assert_ne!(
            root,
            spiffy_shared::product_data_dir(spiffy_shared::Product::Shelf)
        );
    }
}
