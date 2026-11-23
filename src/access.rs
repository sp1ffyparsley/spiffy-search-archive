use crate::error::{SearchError, SearchResult};
use crate::model::ItemKind;
use crate::query::{ParsedQuery, SearchMode};

pub const MAX_ACCESS_RESULTS: u16 = 100;
pub const DEFAULT_PREVIEW_CHARS: u32 = 4_000;
pub const MAX_PREVIEW_CHARS: u32 = 16_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSearchScope {
    Files,
    Folders,
    Applications,
    Content,
}

pub fn scoped_query(scope: AccessSearchScope, raw_query: &str) -> SearchResult<String> {
    let raw_query = raw_query.trim();
    let parsed = ParsedQuery::parse(raw_query)?;
    match scope {
        AccessSearchScope::Files => {
            scoped_filename_query(raw_query, &parsed, ItemKind::File, "file:", "file search")
        }
        AccessSearchScope::Folders => scoped_filename_query(
            raw_query,
            &parsed,
            ItemKind::Folder,
            "folder:",
            "folder search",
        ),
        AccessSearchScope::Applications => scoped_filename_query(
            raw_query,
            &parsed,
            ItemKind::Application,
            "app:",
            "application search",
        ),
        AccessSearchScope::Content => {
            if raw_query.is_empty() {
                return Err(SearchError::Query(
                    "content access requires a nonempty query".to_string(),
                ));
            }
            if !matches!(parsed.mode, SearchMode::Filename | SearchMode::Content)
                || parsed.kinds.iter().any(|kind| *kind != ItemKind::File)
            {
                return Err(SearchError::Query(
                    "content access cannot switch to another search mode or item kind".to_string(),
                ));
            }
            if parsed.mode == SearchMode::Content {
                Ok(raw_query.to_string())
            } else {
                Ok(format!("content: {raw_query}"))
            }
        }
    }
}

pub fn bounded_result_limit(requested: Option<u16>, configured: u16) -> u16 {
    requested
        .unwrap_or(25)
        .clamp(1, configured.min(MAX_ACCESS_RESULTS))
}

pub fn bounded_preview_chars(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_PREVIEW_CHARS)
        .clamp(1, MAX_PREVIEW_CHARS)
}

fn scoped_filename_query(
    raw_query: &str,
    parsed: &ParsedQuery,
    required_kind: ItemKind,
    filter: &str,
    label: &str,
) -> SearchResult<String> {
    if parsed.mode != SearchMode::Filename || parsed.kinds.iter().any(|kind| *kind != required_kind)
    {
        return Err(SearchError::Query(format!(
            "{label} cannot switch to another search mode or item kind"
        )));
    }
    Ok(if raw_query.is_empty() {
        filter.to_string()
    } else {
        format!("{filter} {raw_query}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_access_queries_without_allowing_mode_or_kind_escape() {
        assert_eq!(
            scoped_query(AccessSearchScope::Files, "hero ext:mov").unwrap(),
            "file: hero ext:mov"
        );
        assert_eq!(
            scoped_query(AccessSearchScope::Folders, "projects").unwrap(),
            "folder: projects"
        );
        assert_eq!(
            scoped_query(AccessSearchScope::Applications, "spiffy clipboard").unwrap(),
            "app: spiffy clipboard"
        );
        assert_eq!(
            scoped_query(AccessSearchScope::Content, "needle").unwrap(),
            "content: needle"
        );
        assert!(scoped_query(AccessSearchScope::Files, "browser:private").is_err());
        assert!(scoped_query(AccessSearchScope::Folders, "file: hero").is_err());
        assert!(scoped_query(AccessSearchScope::Applications, "folder: projects").is_err());
        assert!(scoped_query(AccessSearchScope::Content, "").is_err());
    }

    #[test]
    fn access_limits_are_bounded() {
        assert_eq!(bounded_result_limit(None, 200), 25);
        assert_eq!(bounded_result_limit(Some(500), 200), MAX_ACCESS_RESULTS);
        assert_eq!(bounded_preview_chars(Some(u32::MAX)), MAX_PREVIEW_CHARS);
    }
}
