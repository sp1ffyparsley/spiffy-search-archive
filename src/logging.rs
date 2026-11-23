use std::env;
use std::fs;
use std::io;
use std::path::Path;
use tracing_subscriber::EnvFilter;

pub const MAX_RETAINED_DAILY_LOGS: usize = 30;

fn is_owned_daily_log(name: &str, prefix: &str) -> bool {
    let Some(suffix) = name
        .strip_prefix(prefix)
        .and_then(|value| value.strip_prefix('.'))
    else {
        return false;
    };
    let bytes = suffix.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

pub fn prune_owned_daily_logs(log_dir: &Path, prefix: &str, retain: usize) -> io::Result<usize> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_owned_daily_log(name, prefix) || !entry.file_type()?.is_file() {
            continue;
        }
        candidates.push((name.to_string(), entry.path()));
    }

    candidates.sort_by(|left, right| right.0.cmp(&left.0));
    let mut removed = 0;
    for (_, path) in candidates.into_iter().skip(retain) {
        fs::remove_file(path)?;
        removed += 1;
    }
    Ok(removed)
}

pub fn search_env_filter() -> EnvFilter {
    for variable in ["SPIFFY_SEARCH_LOG_LEVEL", "SPIFFY_LOG_LEVEL", "RUST_LOG"] {
        let Ok(value) = env::var(variable) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Ok(filter) = EnvFilter::try_new(value) {
            return filter;
        }
    }

    EnvFilter::new("spiffy_search=info,warn")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_log_retention_removes_only_old_owned_files() {
        let directory = tempfile::tempdir().expect("log root");
        for day in 1..=35 {
            fs::write(
                directory
                    .path()
                    .join(format!("search-agent.log.2026-08-{day:02}")),
                format!("audit-{day}"),
            )
            .expect("owned log");
        }
        fs::write(directory.path().join("search-agent.log.notes"), b"preserve").unwrap();
        fs::write(directory.path().join("other.log.2026-08-01"), b"preserve").unwrap();

        assert_eq!(
            prune_owned_daily_logs(directory.path(), "search-agent.log", 30).unwrap(),
            5
        );
        assert!(!directory
            .path()
            .join("search-agent.log.2026-08-01")
            .exists());
        assert!(directory
            .path()
            .join("search-agent.log.2026-08-35")
            .exists());
        assert_eq!(
            fs::read(directory.path().join("search-agent.log.notes")).unwrap(),
            b"preserve"
        );
        assert_eq!(
            fs::read(directory.path().join("other.log.2026-08-01")).unwrap(),
            b"preserve"
        );
    }
}
