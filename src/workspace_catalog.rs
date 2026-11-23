use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{normalize_path, path_tokens, FileCategory, FileRecord, ItemKind};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;
use uuid::Uuid;

const WORKSPACE_CATALOG_SCHEMA: &str = "ss_scripts_workspace_catalog_v1";
const WORKSPACE_CATALOG_VERSION: u16 = 1;
const WORKSPACE_ROOT_NAMESPACE: Uuid = Uuid::from_u128(0x860c89a1_ebd0_4de5_b3d8_4e35331546d8);
const WORKSPACE_ITEM_NAMESPACE: Uuid = Uuid::from_u128(0xacdc72c9_8f37_434c_958b_9038c0d7f18b);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCatalogSnapshot {
    pub root_id: Uuid,
    pub records: Vec<FileRecord>,
}

#[derive(Debug, Deserialize)]
struct CatalogDocument {
    schema: String,
    version: u16,
    workspace_id: String,
    systems: Vec<CatalogSystem>,
}

#[derive(Debug, Deserialize)]
struct CatalogSystem {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    launch_targets: Vec<LaunchTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchTarget {
    id: String,
    label: String,
    #[serde(default)]
    aliases: Vec<String>,
    platform_paths: BTreeMap<String, String>,
}

pub fn root_id() -> Uuid {
    workspace_root_id("ss-scripts")
}

pub fn load(path: &Path, device_id: Uuid) -> SearchResult<WorkspaceCatalogSnapshot> {
    load_for_platform(path, device_id, current_platform()?)
}

fn load_for_platform(
    path: &Path,
    device_id: Uuid,
    platform: &str,
) -> SearchResult<WorkspaceCatalogSnapshot> {
    let catalog_path = path.canonicalize().map_err(|error| io_error(path, error))?;
    if !catalog_path.is_file() {
        return Err(SearchError::Config(format!(
            "workspace catalog is not a regular file: {}",
            catalog_path.display()
        )));
    }
    let catalog_root = catalog_path.parent().ok_or_else(|| {
        SearchError::Config("workspace catalog path has no parent directory".to_string())
    })?;
    let encoded = fs::read(&catalog_path).map_err(|error| io_error(&catalog_path, error))?;
    let document: CatalogDocument = serde_json::from_slice(&encoded)?;
    if document.schema != WORKSPACE_CATALOG_SCHEMA || document.version != WORKSPACE_CATALOG_VERSION
    {
        return Err(SearchError::Config(format!(
            "unsupported workspace catalog contract {} version {}",
            document.schema, document.version
        )));
    }
    validate_identifier("catalog workspace", &document.workspace_id)?;

    let mut matching_systems = document
        .systems
        .into_iter()
        .filter(|system| system.id == "spiffy_workspace");
    let system = matching_systems.next().ok_or_else(|| {
        SearchError::Config("workspace catalog is missing the spiffy_workspace system".to_string())
    })?;
    if matching_systems.next().is_some() {
        return Err(SearchError::Config(
            "workspace catalog contains duplicate spiffy_workspace systems".to_string(),
        ));
    }
    validate_identifier("system", &system.id)?;

    let catalog_root_id = workspace_root_id(&document.workspace_id);
    if !system
        .platforms
        .iter()
        .any(|candidate| candidate == platform)
    {
        return Ok(WorkspaceCatalogSnapshot {
            root_id: catalog_root_id,
            records: Vec::new(),
        });
    }

    let now = Utc::now();
    let mut records = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let system_label = if system.label.trim().is_empty() {
        system.id.as_str()
    } else {
        system.label.trim()
    };
    for target in system.launch_targets {
        validate_identifier("launch target", &target.id)?;
        let label = target.label.trim();
        if label.is_empty() || label.len() > 256 || label.chars().any(char::is_control) {
            return Err(SearchError::Config(format!(
                "workspace launch target {} has an invalid label",
                target.id
            )));
        }
        validate_aliases(&target.id, &target.aliases)?;
        validate_platform_keys(&target.id, &target.platform_paths)?;
        let Some(relative) = target.platform_paths.get(platform) else {
            continue;
        };
        let launcher = resolve_launcher(catalog_root, relative)?;
        let stable_key = workspace_stable_key(&document.workspace_id, &target.id);
        if !seen_keys.insert(stable_key.clone()) {
            return Err(SearchError::Config(format!(
                "workspace launch target is duplicated: {}:{}",
                system.id, target.id
            )));
        }
        records.push(launch_record(
            &document.workspace_id,
            system_label,
            &target,
            stable_key,
            launcher,
            catalog_root_id,
            device_id,
            now,
        )?);
    }
    records.sort_by(|left, right| left.stable_key.cmp(&right.stable_key));
    Ok(WorkspaceCatalogSnapshot {
        root_id: catalog_root_id,
        records,
    })
}

fn launch_record(
    workspace_id: &str,
    system_label: &str,
    target: &LaunchTarget,
    stable_key: String,
    launcher: PathBuf,
    catalog_root_id: Uuid,
    device_id: Uuid,
    last_seen: DateTime<Utc>,
) -> SearchResult<FileRecord> {
    let metadata = fs::metadata(&launcher).map_err(|error| io_error(&launcher, error))?;
    let parent = launcher.parent().unwrap_or(&launcher);
    let extension = launcher
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mut search_terms = vec![path_tokens(parent), system_label.to_string()];
    search_terms.extend(target.aliases.iter().cloned());
    let display_path = launcher.to_string_lossy().to_string();
    Ok(FileRecord {
        stable_key,
        stable_file_id: None,
        root_id: catalog_root_id,
        device_id,
        canonical_path: display_path.clone(),
        display_path,
        normalized_path: normalize_path(&launcher),
        filename: target.label.trim().to_string(),
        filename_stem: target.label.trim().to_string(),
        extension,
        parent_path: parent.to_string_lossy().to_string(),
        parent_tokens: search_terms.join(" "),
        item_kind: ItemKind::Application,
        category: FileCategory::Other,
        content_type: "workspace_launch".to_string(),
        mime_type: mime_guess::from_path(&launcher)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string(),
        size: metadata.len(),
        created_time: metadata.created().ok().map(system_time_to_utc),
        modified_time: metadata.modified().ok().map(system_time_to_utc),
        last_seen_time: last_seen,
        hidden: false,
        system: false,
        package: false,
        application: true,
        folder: false,
        file: true,
        cloud_placeholder: false,
        offline: false,
        missing: false,
        tombstone: false,
        source_provider: format!("workspace_catalog:{workspace_id}"),
        remote_device: None,
        content_index_state: "disabled".to_string(),
        preview_state: "not_applicable".to_string(),
        tags: target.aliases.clone(),
    })
}

fn resolve_launcher(root: &Path, relative: &str) -> SearchResult<PathBuf> {
    let normalized_relative = relative.replace('\\', "/");
    if looks_absolute_cross_platform(&normalized_relative) {
        return Err(SearchError::Config(format!(
            "workspace launcher path must be workspace-relative: {relative}"
        )));
    }
    let relative = Path::new(&normalized_relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(SearchError::Config(format!(
            "workspace launcher path must be workspace-relative: {}",
            relative.display()
        )));
    }
    reject_symlink_components(root, relative)?;
    let joined = root.join(relative);
    let canonical = joined
        .canonicalize()
        .map_err(|error| io_error(&joined, error))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(SearchError::Config(format!(
            "workspace launcher must resolve to a file inside the catalog root: {}",
            joined.display()
        )));
    }
    Ok(canonical)
}

fn reject_symlink_components(root: &Path, relative: &Path) -> SearchResult<()> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(value) = component {
            current.push(value);
            let metadata =
                fs::symlink_metadata(&current).map_err(|error| io_error(&current, error))?;
            if metadata.file_type().is_symlink() {
                return Err(SearchError::Config(format!(
                    "workspace launcher path may not traverse symlinks: {}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_identifier(kind: &str, value: &str) -> SearchResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(SearchError::Config(format!(
            "workspace {kind} id is invalid: {value}"
        )));
    }
    Ok(())
}

fn validate_aliases(target_id: &str, aliases: &[String]) -> SearchResult<()> {
    if aliases.len() > 32
        || aliases.iter().any(|alias| {
            alias.trim().is_empty() || alias.len() > 256 || alias.chars().any(char::is_control)
        })
    {
        return Err(SearchError::Config(format!(
            "workspace launch target {target_id} has invalid aliases"
        )));
    }
    Ok(())
}

fn validate_platform_keys(target_id: &str, paths: &BTreeMap<String, String>) -> SearchResult<()> {
    if paths.is_empty()
        || paths
            .keys()
            .any(|platform| !matches!(platform.as_str(), "windows" | "macos"))
    {
        return Err(SearchError::Config(format!(
            "workspace launch target {target_id} has unsupported platform paths"
        )));
    }
    Ok(())
}

fn workspace_stable_key(system_id: &str, target_id: &str) -> String {
    let identity = Uuid::new_v5(
        &WORKSPACE_ITEM_NAMESPACE,
        format!("{system_id}\0{target_id}").as_bytes(),
    );
    format!("workspace:{identity}")
}

fn workspace_root_id(workspace_id: &str) -> Uuid {
    Uuid::new_v5(&WORKSPACE_ROOT_NAMESPACE, workspace_id.as_bytes())
}

fn looks_absolute_cross_platform(value: &str) -> bool {
    let bytes = value.as_bytes();
    Path::new(value).is_absolute()
        || value.starts_with('/')
        || value.starts_with("//")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

fn system_time_to_utc(value: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(value)
}

fn current_platform() -> SearchResult<&'static str> {
    if cfg!(windows) {
        Ok("windows")
    } else if cfg!(target_os = "macos") {
        Ok("macos")
    } else {
        Err(SearchError::Config(
            "workspace launch targets are supported only on Windows and macOS".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_catalog(root: &Path, launcher_path: &str, aliases: &[&str]) -> PathBuf {
        let catalog = serde_json::json!({
            "schema": WORKSPACE_CATALOG_SCHEMA,
            "version": WORKSPACE_CATALOG_VERSION,
            "workspace_id": "ss-scripts",
            "systems": [{
                "id": "spiffy_workspace",
                "label": "Spiffy Workspace",
                "platforms": ["windows", "macos"],
                "launch_targets": [{
                    "id": "video_editor",
                    "label": "Spiffy Video Editor",
                    "aliases": aliases,
                    "platform_paths": {"windows": launcher_path, "macos": launcher_path}
                }]
            }],
            "relations": []
        });
        let path = root.join("workspace_catalog.json");
        fs::write(&path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        path
    }

    #[test]
    fn supported_catalog_projects_deterministic_application_records() {
        let temp = tempfile::tempdir().unwrap();
        let launchers = temp.path().join("Spiffy Workspace");
        fs::create_dir(&launchers).unwrap();
        let launcher = launchers.join("Launch Spiffy Workspace.command");
        fs::write(&launcher, b"#!/bin/zsh\n").unwrap();
        let catalog = write_catalog(
            temp.path(),
            "Spiffy Workspace/Launch Spiffy Workspace.command",
            &["Video Editor", "Spiffy Editor"],
        );
        let device_id = Uuid::new_v4();

        let first = load_for_platform(&catalog, device_id, "macos").unwrap();
        let second = load_for_platform(&catalog, device_id, "macos").unwrap();
        assert_eq!(first.root_id, root_id());
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].stable_key, second.records[0].stable_key);
        assert_eq!(first.records[0].item_kind, ItemKind::Application);
        assert!(first.records[0].application);
        assert_eq!(first.records[0].filename, "Spiffy Video Editor");
        assert!(first.records[0].parent_tokens.contains("Video Editor"));
        assert_eq!(first.records[0].tags, vec!["Video Editor", "Spiffy Editor"]);
        assert_eq!(
            first.records[0].source_provider,
            "workspace_catalog:ss-scripts"
        );
        assert_eq!(
            Path::new(&first.records[0].canonical_path),
            launcher.canonicalize().unwrap()
        );
    }

    #[test]
    fn other_platform_targets_are_ignored_without_touching_the_launcher() {
        let temp = tempfile::tempdir().unwrap();
        let catalog = serde_json::json!({
            "schema": WORKSPACE_CATALOG_SCHEMA,
            "version": WORKSPACE_CATALOG_VERSION,
            "workspace_id": "ss-scripts",
            "systems": [{
                "id": "spiffy_workspace",
                "label": "Spiffy Workspace",
                "platforms": ["windows", "macos"],
                "launch_targets": [{
                    "id": "app",
                    "label": "Mac App",
                    "platform_paths": {"macos": "missing.command"}
                }]
            }]
        });
        let path = temp.path().join("workspace_catalog.json");
        fs::write(&path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        let snapshot = load_for_platform(&path, Uuid::new_v4(), "windows").unwrap();
        assert!(snapshot.records.is_empty());
    }

    #[test]
    fn launcher_path_escape_and_missing_launchers_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let escaped = write_catalog(temp.path(), "../outside.command", &[]);
        assert!(load_for_platform(&escaped, Uuid::new_v4(), "macos").is_err());

        let missing = write_catalog(temp.path(), "missing.command", &[]);
        assert!(load_for_platform(&missing, Uuid::new_v4(), "macos").is_err());

        let absolute = if cfg!(windows) {
            r"C:\\Windows\\System32\\cmd.exe"
        } else {
            "/usr/bin/true"
        };
        let absolute_catalog = write_catalog(temp.path(), absolute, &[]);
        assert!(load_for_platform(&absolute_catalog, Uuid::new_v4(), "macos").is_err());
    }

    #[test]
    fn contract_and_spiffy_workspace_identity_are_strict() {
        let temp = tempfile::tempdir().unwrap();
        let launcher = temp.path().join("launch.command");
        fs::write(&launcher, b"#!/bin/zsh\n").unwrap();
        let valid = serde_json::json!({
            "schema": WORKSPACE_CATALOG_SCHEMA,
            "version": WORKSPACE_CATALOG_VERSION,
            "workspace_id": "ss-scripts",
            "systems": [{
                "id": "some_other_workspace",
                "label": "Other",
                "platforms": ["macos"],
                "launch_targets": [{
                    "id": "other",
                    "label": "Other",
                    "platform_paths": {"macos": "launch.command"}
                }]
            }]
        });
        let path = temp.path().join("workspace_catalog.json");
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(load_for_platform(&path, Uuid::new_v4(), "macos").is_err());

        let wrong_schema = serde_json::json!({
            "schema": "ss_scripts_workspace_catalog_v2",
            "version": 1,
            "workspace_id": "ss-scripts",
            "systems": []
        });
        fs::write(&path, serde_json::to_vec(&wrong_schema).unwrap()).unwrap();
        assert!(load_for_platform(&path, Uuid::new_v4(), "macos").is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn symlink_launchers_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real.command");
        fs::write(&real, b"#!/bin/zsh\n").unwrap();
        let link = temp.path().join("linked.command");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_file(&real, &link).is_err() {
                return;
            }
        }
        let catalog = write_catalog(temp.path(), "linked.command", &[]);
        assert!(load_for_platform(&catalog, Uuid::new_v4(), "macos").is_err());
    }
}
