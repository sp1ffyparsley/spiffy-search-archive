use crate::catalog::SourceRoot;
use crate::config::SearchConfig;
use crate::error::{SearchError, SearchResult};
use crate::model::FileRecord;
use crate::platform;
use ignore::overrides::OverrideBuilder;
use ignore::{WalkBuilder, WalkState};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    pub workers: usize,
    pub batch_size: usize,
    pub channel_capacity: usize,
    pub include_hidden: bool,
    pub include_system: bool,
    pub respect_ignore_files: bool,
}

impl ScanOptions {
    pub fn from_config(config: &SearchConfig) -> Self {
        Self {
            workers: usize::from(config.scan_workers),
            batch_size: usize::from(config.index_batch_size),
            channel_capacity: usize::from(config.index_batch_size).saturating_mul(2),
            include_hidden: config.include_hidden,
            include_system: config.include_system,
            respect_ignore_files: true,
        }
    }

    fn validate(&self) -> SearchResult<()> {
        if !(1..=32).contains(&self.workers)
            || !(1..=4096).contains(&self.batch_size)
            || !(16..=16_384).contains(&self.channel_capacity)
        {
            return Err(SearchError::Config(
                "scanner workers, batch size, or channel capacity is outside supported bounds"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub visited_entries: u64,
    pub indexed_entries: u64,
    pub files: u64,
    pub folders: u64,
    pub skipped_entries: u64,
    pub metadata_errors: u64,
    pub batches: u64,
    pub elapsed_millis: u64,
    pub cancelled: bool,
}

struct Counters {
    visited: AtomicU64,
    indexed: AtomicU64,
    files: AtomicU64,
    folders: AtomicU64,
    skipped: AtomicU64,
    errors: AtomicU64,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            visited: AtomicU64::new(0),
            indexed: AtomicU64::new(0),
            files: AtomicU64::new(0),
            folders: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

pub fn scan_root<F>(
    root: &SourceRoot,
    device_id: Uuid,
    options: &ScanOptions,
    cancellation: Arc<AtomicBool>,
    mut on_batch: F,
) -> SearchResult<ScanStats>
where
    F: FnMut(Vec<FileRecord>) -> SearchResult<()>,
{
    options.validate()?;
    if !root.enabled {
        return Err(SearchError::State(format!(
            "source root {} is disabled",
            root.id
        )));
    }
    let root_path = PathBuf::from(&root.canonical_path);
    if !root_path.is_dir() {
        return Err(SearchError::State(format!(
            "source root is no longer an accessible directory: {}",
            root_path.display()
        )));
    }

    let mut overrides = OverrideBuilder::new(&root_path);
    #[cfg(target_os = "windows")]
    overrides.case_insensitive(true).map_err(|error| {
        SearchError::Config(format!(
            "could not configure case-insensitive exclusions: {error}"
        ))
    })?;
    for exclusion in &root.exclusions {
        overrides.add(&format!("!{exclusion}")).map_err(|error| {
            SearchError::Config(format!("invalid exclusion '{exclusion}': {error}"))
        })?;
    }

    let mut builder = WalkBuilder::new(&root_path);
    builder
        .threads(options.workers)
        .hidden(!options.include_hidden)
        .follow_links(false)
        .same_file_system(false)
        .parents(options.respect_ignore_files)
        .ignore(options.respect_ignore_files)
        .git_ignore(options.respect_ignore_files)
        .git_global(options.respect_ignore_files)
        .git_exclude(options.respect_ignore_files)
        .overrides(overrides.build().map_err(|error| {
            SearchError::Config(format!("could not compile root exclusions: {error}"))
        })?);
    let walker = builder.build_parallel();
    let counters = Arc::new(Counters::default());
    let (sender, receiver) = mpsc::sync_channel(options.channel_capacity);
    let started = Instant::now();
    let include_hidden = options.include_hidden;
    let include_system = options.include_system;
    let root_id = root.id;
    let mut batches = 0_u64;
    let mut callback_error = None;

    std::thread::scope(|scope| {
        let worker_cancellation = Arc::clone(&cancellation);
        let worker_counters = Arc::clone(&counters);
        let worker = scope.spawn(move || {
            walker.run(|| {
                let sender = sender.clone();
                let cancellation = Arc::clone(&worker_cancellation);
                let counters = Arc::clone(&worker_counters);
                Box::new(move |entry| {
                    if cancellation.load(Ordering::Relaxed) {
                        return WalkState::Quit;
                    }
                    counters.visited.fetch_add(1, Ordering::Relaxed);
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(_) => {
                            counters.errors.fetch_add(1, Ordering::Relaxed);
                            return WalkState::Continue;
                        }
                    };
                    if entry.depth() == 0 {
                        return WalkState::Continue;
                    }
                    if crate::file_ops::is_operation_staging_path(entry.path()) {
                        counters.skipped.fetch_add(1, Ordering::Relaxed);
                        return if entry.file_type().is_some_and(|kind| kind.is_dir()) {
                            WalkState::Skip
                        } else {
                            WalkState::Continue
                        };
                    }
                    if entry.file_type().is_some_and(|kind| kind.is_symlink()) {
                        counters.skipped.fetch_add(1, Ordering::Relaxed);
                        return WalkState::Continue;
                    }
                    let record = match platform::file_record(entry.path(), root_id, device_id) {
                        Ok(record) => record,
                        Err(_) => {
                            counters.errors.fetch_add(1, Ordering::Relaxed);
                            return WalkState::Continue;
                        }
                    };
                    let skip_tree = record.folder
                        && (record.package
                            || (!include_hidden && record.hidden)
                            || (!include_system && record.system));
                    if (!include_hidden && record.hidden) || (!include_system && record.system) {
                        counters.skipped.fetch_add(1, Ordering::Relaxed);
                        return if skip_tree {
                            WalkState::Skip
                        } else {
                            WalkState::Continue
                        };
                    }
                    if record.file {
                        counters.files.fetch_add(1, Ordering::Relaxed);
                    } else if record.folder {
                        counters.folders.fetch_add(1, Ordering::Relaxed);
                    }
                    counters.indexed.fetch_add(1, Ordering::Relaxed);
                    if sender.send(record).is_err() {
                        return WalkState::Quit;
                    }
                    if skip_tree {
                        WalkState::Skip
                    } else {
                        WalkState::Continue
                    }
                })
            });
        });

        let mut batch = Vec::with_capacity(options.batch_size);
        while let Ok(record) = receiver.recv() {
            if callback_error.is_some() {
                continue;
            }
            batch.push(record);
            if batch.len() >= options.batch_size {
                batches = batches.saturating_add(1);
                if let Err(error) = on_batch(std::mem::take(&mut batch)) {
                    cancellation.store(true, Ordering::Relaxed);
                    callback_error = Some(error);
                }
            }
        }
        if callback_error.is_none() && !batch.is_empty() {
            batches = batches.saturating_add(1);
            if let Err(error) = on_batch(batch) {
                cancellation.store(true, Ordering::Relaxed);
                callback_error = Some(error);
            }
        }
        if worker.join().is_err() && callback_error.is_none() {
            callback_error = Some(SearchError::State(
                "parallel filesystem scanner panicked".to_string(),
            ));
        }
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    Ok(ScanStats {
        visited_entries: counters.visited.load(Ordering::Relaxed),
        indexed_entries: counters.indexed.load(Ordering::Relaxed),
        files: counters.files.load(Ordering::Relaxed),
        folders: counters.folders.load(Ordering::Relaxed),
        skipped_entries: counters.skipped.load(Ordering::Relaxed),
        metadata_errors: counters.errors.load(Ordering::Relaxed),
        batches,
        elapsed_millis: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        cancelled: cancellation.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::SearchCatalog;
    use std::fs;
    use std::sync::Mutex;

    fn options() -> ScanOptions {
        ScanOptions {
            workers: 2,
            batch_size: 2,
            channel_capacity: 16,
            include_hidden: false,
            include_system: false,
            respect_ignore_files: false,
        }
    }

    #[test]
    fn parallel_scan_streams_bounded_batches_and_honors_exclusions() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Root");
        fs::create_dir_all(root_path.join("Sources")).unwrap();
        fs::create_dir_all(root_path.join("Cache")).unwrap();
        fs::write(root_path.join("Sources").join("Hero.mov"), b"hero").unwrap();
        fs::write(root_path.join("Sources").join("Notes.txt"), b"notes").unwrap();
        fs::write(root_path.join("Cache").join("Proxy.mov"), b"proxy").unwrap();
        fs::write(root_path.join(".private"), b"hidden").unwrap();
        let mut catalog = SearchCatalog::open(temp.path().join("search.db")).unwrap();
        let root = catalog
            .add_root(
                &root_path,
                false,
                vec!["Cache".to_string(), "Cache/**".to_string()],
            )
            .unwrap();
        let records = Mutex::new(Vec::new());
        let max_batch = Mutex::new(0_usize);
        let stats = scan_root(
            &root,
            Uuid::new_v4(),
            &options(),
            Arc::new(AtomicBool::new(false)),
            |batch| {
                let mut maximum = max_batch.lock().unwrap();
                *maximum = (*maximum).max(batch.len());
                drop(maximum);
                records.lock().unwrap().extend(batch);
                Ok(())
            },
        )
        .unwrap();
        let records = records.into_inner().unwrap();
        assert!(*max_batch.lock().unwrap() <= 2);
        assert!(records.iter().any(|record| record.filename == "Hero.mov"));
        assert!(records.iter().any(|record| record.filename == "Notes.txt"));
        assert!(!records.iter().any(|record| record.filename == "Proxy.mov"));
        assert!(!records.iter().any(|record| record.filename == ".private"));
        assert_eq!(stats.indexed_entries as usize, records.len());
        assert!(stats.batches >= 2);
    }

    #[test]
    fn pre_cancelled_scan_exits_without_records() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Root");
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("Clip.mov"), b"clip").unwrap();
        let mut catalog = SearchCatalog::open(temp.path().join("search.db")).unwrap();
        let root = catalog.add_root(&root_path, false, Vec::new()).unwrap();
        let cancellation = Arc::new(AtomicBool::new(true));
        let stats = scan_root(&root, Uuid::new_v4(), &options(), cancellation, |_| {
            panic!("cancelled scan produced a batch")
        })
        .unwrap();
        assert!(stats.cancelled);
        assert_eq!(stats.indexed_entries, 0);
    }

    #[test]
    fn operation_owned_staging_paths_are_never_indexed() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("Root");
        fs::create_dir(&root_path).unwrap();
        let stage = root_path.join(format!(".spiffy-search-{}-0.partial", Uuid::new_v4()));
        fs::write(&stage, b"incomplete copy").unwrap();
        fs::write(root_path.join("Visible.txt"), b"visible").unwrap();
        let mut catalog = SearchCatalog::open(temp.path().join("search.db")).unwrap();
        let root = catalog.add_root(&root_path, false, Vec::new()).unwrap();
        let records = Mutex::new(Vec::new());
        let mut scan_options = options();
        scan_options.include_hidden = true;
        scan_root(
            &root,
            Uuid::new_v4(),
            &scan_options,
            Arc::new(AtomicBool::new(false)),
            |batch| {
                records.lock().unwrap().extend(batch);
                Ok(())
            },
        )
        .unwrap();
        let records = records.into_inner().unwrap();
        assert!(records
            .iter()
            .any(|record| record.filename == "Visible.txt"));
        assert!(!records
            .iter()
            .any(|record| record.canonical_path == stage.to_string_lossy()));
    }
}
