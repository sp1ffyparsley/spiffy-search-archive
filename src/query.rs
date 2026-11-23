use crate::error::{SearchError, SearchResult};
use crate::model::{FileCategory, ItemKind};
use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_QUERY_BYTES: usize = 4096;
pub const MAX_FILTER_VALUES: usize = 128;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    #[default]
    Filename,
    Content,
    Clipboard,
    Browser,
    Shelf,
    Window,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedQuery {
    pub raw_text: String,
    pub terms: Vec<String>,
    pub exact_phrases: Vec<String>,
    pub excluded_terms: Vec<String>,
    pub excluded_extensions: BTreeSet<String>,
    pub excluded_folders: Vec<String>,
    pub extensions: BTreeSet<String>,
    pub kinds: BTreeSet<ItemKind>,
    pub categories: BTreeSet<FileCategory>,
    pub paths: Vec<String>,
    pub drives: BTreeSet<String>,
    pub devices: BTreeSet<String>,
    pub libraries: BTreeSet<String>,
    pub date_range: Option<TimeRange>,
    pub size_range: Option<SizeRange>,
    pub favorite_only: bool,
    pub current_only: bool,
    pub remote_only: bool,
    pub mode: SearchMode,
    pub parent_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: Option<DateTime<Utc>>,
    pub end_exclusive: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeRange {
    pub min_inclusive: Option<u64>,
    pub max_exclusive: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSuggestion {
    pub token: String,
    pub category: String,
    pub description: String,
}

impl ParsedQuery {
    pub fn parse(input: &str) -> SearchResult<Self> {
        Self::parse_at(input, Utc::now())
    }

    pub fn parse_at(input: &str, now: DateTime<Utc>) -> SearchResult<Self> {
        if input.len() > MAX_QUERY_BYTES {
            return Err(SearchError::Query(format!(
                "query exceeds the {MAX_QUERY_BYTES} byte limit"
            )));
        }
        let mut query = Self {
            raw_text: input.to_string(),
            terms: Vec::new(),
            exact_phrases: Vec::new(),
            excluded_terms: Vec::new(),
            excluded_extensions: BTreeSet::new(),
            excluded_folders: Vec::new(),
            extensions: BTreeSet::new(),
            kinds: BTreeSet::new(),
            categories: BTreeSet::new(),
            paths: Vec::new(),
            drives: BTreeSet::new(),
            devices: BTreeSet::new(),
            libraries: BTreeSet::new(),
            date_range: None,
            size_range: None,
            favorite_only: false,
            current_only: false,
            remote_only: false,
            mode: SearchMode::Filename,
            parent_hint: None,
        };

        for token in tokenize(input)? {
            if token.quoted {
                query.exact_phrases.push(token.value);
                continue;
            }
            if parse_filter(&mut query, &token.value, now)? {
                continue;
            }
            if let Some(excluded) = token.value.strip_prefix('-') {
                if !excluded.is_empty() {
                    query.excluded_terms.push(excluded.to_string());
                }
            } else if !token.value.is_empty() && token.value != "@" {
                query.terms.push(token.value);
            }
        }

        if query
            .terms
            .first()
            .is_some_and(|term| term.eq_ignore_ascii_case("gety"))
        {
            query.terms.remove(0);
            query.mode = SearchMode::Content;
        }

        if query.terms.len()
            + query.exact_phrases.len()
            + query.excluded_terms.len()
            + query.extensions.len()
            + query.paths.len()
            > MAX_FILTER_VALUES
        {
            return Err(SearchError::Query(
                "query contains too many values".to_string(),
            ));
        }

        if let Some((parent, filename)) = path_narrowing_hint(&query.terms) {
            query.parent_hint = Some(parent);
            query.terms = filename;
        }
        Ok(query)
    }

    pub fn free_text(&self) -> String {
        self.terms
            .iter()
            .chain(self.exact_phrases.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug)]
struct Token {
    value: String,
    quoted: bool,
}

fn tokenize(input: &str) -> SearchResult<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => {
                if quoted {
                    if !current.is_empty() {
                        tokens.push(Token {
                            value: std::mem::take(&mut current),
                            quoted: true,
                        });
                    }
                    quoted = false;
                } else {
                    if !current.trim().is_empty() {
                        tokens.push(Token {
                            value: std::mem::take(&mut current),
                            quoted: false,
                        });
                    }
                    quoted = true;
                }
            }
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(Token {
                        value: std::mem::take(&mut current),
                        quoted: false,
                    });
                }
            }
            _ => current.push(character),
        }
    }
    if escaped {
        current.push('\\');
    }
    if quoted {
        return Err(SearchError::Query(
            "query contains an unclosed quote".to_string(),
        ));
    }
    if !current.is_empty() {
        tokens.push(Token {
            value: current,
            quoted: false,
        });
    }
    Ok(tokens)
}

/// Preserve token order for the live Shelf owner's literal substring contract.
pub(crate) fn shelf_query_text(input: &str) -> SearchResult<String> {
    let input = input.trim();
    let prefix = input
        .get(..6)
        .filter(|v| v.eq_ignore_ascii_case("shelf:"))
        .ok_or_else(|| {
            SearchError::Query("Use shelf: at the start of a saved Shelf query".into())
        })?;
    Ok(input[prefix.len()..].trim().to_owned())
}

fn parse_filter(query: &mut ParsedQuery, token: &str, now: DateTime<Utc>) -> SearchResult<bool> {
    let lower = token.to_ascii_lowercase();
    let (negative, filter) = if let Some(value) = lower.strip_prefix('-') {
        (true, value)
    } else {
        (false, lower.as_str())
    };

    if let Some(value) = filter.strip_prefix("ext:") {
        for extension in split_extensions(value)? {
            if negative {
                query.excluded_extensions.insert(extension);
            } else {
                query.extensions.insert(extension);
            }
        }
        return Ok(true);
    }
    if let Some(extension) = filter.strip_prefix("*.") {
        query.extensions.insert(normalize_extension(extension)?);
        return Ok(true);
    }
    if let Some(folder) = filter.strip_prefix("folder:") {
        if folder.is_empty() {
            query.kinds.insert(ItemKind::Folder);
        } else if negative {
            query.excluded_folders.push(folder.to_string());
        } else {
            query.paths.push(folder.to_string());
        }
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("path:") {
        require_value("path", value)?;
        query.paths.push(value.to_string());
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("drive:") {
        for drive in split_plain_values("drive", value)? {
            let drive = drive.trim_end_matches(':');
            if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() {
                return Err(SearchError::Query(format!(
                    "invalid drive filter '{drive}'"
                )));
            }
            query.drives.insert(drive.to_ascii_lowercase());
        }
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("device:") {
        require_value("device", value)?;
        query.devices.insert(value.to_string());
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("library:") {
        require_value("library", value)?;
        query.libraries.insert(value.to_string());
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("date:") {
        query.date_range = Some(parse_date_range(value, now)?);
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("size:") {
        query.size_range = Some(parse_size_range(value)?);
        return Ok(true);
    }
    if let Some(value) = filter
        .strip_prefix("content:")
        .or_else(|| filter.strip_prefix("gety:"))
    {
        query.mode = SearchMode::Content;
        if !value.is_empty() {
            query.terms.push(value.to_string());
        }
        return Ok(true);
    }
    if let Some(value) = filter.strip_prefix("browser:") {
        query.mode = SearchMode::Browser;
        if !value.is_empty() {
            query.terms.push(value.to_string());
        }
        return Ok(true);
    }

    match filter {
        "file:" => {
            query.kinds.insert(ItemKind::File);
            Ok(true)
        }
        "folder:" => {
            query.kinds.insert(ItemKind::Folder);
            Ok(true)
        }
        "app:" => {
            query.kinds.insert(ItemKind::Application);
            Ok(true)
        }
        "window:" => {
            query.mode = SearchMode::Window;
            query.kinds.insert(ItemKind::Window);
            Ok(true)
        }
        "clipboard:" => {
            query.mode = SearchMode::Clipboard;
            Ok(true)
        }
        "shelf:" => {
            query.mode = SearchMode::Shelf;
            Ok(true)
        }
        "doc:" => category(query, FileCategory::Document),
        "image:" => category(query, FileCategory::Image),
        "video:" => category(query, FileCategory::Video),
        "audio:" => category(query, FileCategory::Audio),
        "archive:" => category(query, FileCategory::Archive),
        "code:" => category(query, FileCategory::Code),
        "favorite:" => {
            query.favorite_only = true;
            Ok(true)
        }
        "current:" => {
            query.current_only = true;
            Ok(true)
        }
        "remote:" => {
            query.remote_only = true;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn category(query: &mut ParsedQuery, category: FileCategory) -> SearchResult<bool> {
    query.categories.insert(category);
    Ok(true)
}

fn split_extensions(value: &str) -> SearchResult<Vec<String>> {
    let values = value
        .split([',', ';'])
        .map(normalize_extension)
        .collect::<SearchResult<Vec<_>>>()?;
    if values.is_empty() {
        return Err(SearchError::Query(
            "extension filter requires a value".to_string(),
        ));
    }
    Ok(values)
}

fn split_plain_values(name: &str, value: &str) -> SearchResult<Vec<String>> {
    let values = value
        .split([',', ';'])
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err(SearchError::Query(format!(
            "{name} filter contains an empty value"
        )));
    }
    Ok(values)
}

fn normalize_extension(value: &str) -> SearchResult<String> {
    let extension = value.trim().trim_start_matches('.').to_ascii_lowercase();
    if extension.is_empty()
        || extension.len() > 20
        || !extension.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '+' || character == '-'
        })
    {
        return Err(SearchError::Query(format!(
            "invalid extension filter '{value}'"
        )));
    }
    Ok(extension)
}

fn require_value(name: &str, value: &str) -> SearchResult<()> {
    if value.trim().is_empty() {
        Err(SearchError::Query(format!(
            "{name} filter requires a value"
        )))
    } else {
        Ok(())
    }
}

fn parse_date_range(value: &str, now: DateTime<Utc>) -> SearchResult<TimeRange> {
    let today = now.date_naive();
    match value {
        "today" => day_range(today),
        "week" => {
            let start = today - Duration::days(i64::from(today.weekday().num_days_from_monday()));
            range_dates(start, start + Duration::days(7))
        }
        "month" => {
            let start = NaiveDate::from_ymd_opt(today.year(), today.month(), 1)
                .ok_or_else(|| SearchError::Query("could not calculate month range".to_string()))?;
            let (year, month) = if today.month() == 12 {
                (today.year() + 1, 1)
            } else {
                (today.year(), today.month() + 1)
            };
            let end = NaiveDate::from_ymd_opt(year, month, 1)
                .ok_or_else(|| SearchError::Query("could not calculate month range".to_string()))?;
            range_dates(start, end)
        }
        value if value.contains("..") => {
            let (start, end) = value
                .split_once("..")
                .ok_or_else(|| SearchError::Query("invalid date range".to_string()))?;
            let start = parse_date(start)?;
            let end = parse_date(end)? + Duration::days(1);
            if end <= start {
                return Err(SearchError::Query(
                    "date range end precedes start".to_string(),
                ));
            }
            range_dates(start, end)
        }
        value if value.len() == 7 => {
            let start = NaiveDate::parse_from_str(&format!("{value}-01"), "%Y-%m-%d")
                .map_err(|_| SearchError::Query(format!("invalid month filter '{value}'")))?;
            let (year, month) = if start.month() == 12 {
                (start.year() + 1, 1)
            } else {
                (start.year(), start.month() + 1)
            };
            let end = NaiveDate::from_ymd_opt(year, month, 1)
                .ok_or_else(|| SearchError::Query("invalid month range".to_string()))?;
            range_dates(start, end)
        }
        value => day_range(parse_date(value)?),
    }
}

fn parse_date(value: &str) -> SearchResult<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| SearchError::Query(format!("invalid date filter '{value}'")))
}

fn day_range(day: NaiveDate) -> SearchResult<TimeRange> {
    range_dates(day, day + Duration::days(1))
}

fn range_dates(start: NaiveDate, end: NaiveDate) -> SearchResult<TimeRange> {
    let start = start
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| SearchError::Query("invalid date start".to_string()))?;
    let end = end
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| SearchError::Query("invalid date end".to_string()))?;
    Ok(TimeRange {
        start: Some(Utc.from_utc_datetime(&start)),
        end_exclusive: Some(Utc.from_utc_datetime(&end)),
    })
}

fn parse_size_range(value: &str) -> SearchResult<SizeRange> {
    if let Some(rest) = value.strip_prefix('>') {
        return Ok(SizeRange {
            min_inclusive: Some(parse_size(rest)?.saturating_add(1)),
            max_exclusive: None,
        });
    }
    if let Some(rest) = value.strip_prefix('<') {
        return Ok(SizeRange {
            min_inclusive: None,
            max_exclusive: Some(parse_size(rest)?),
        });
    }
    if let Some((start, end)) = value.split_once("..") {
        let start = parse_size(start)?;
        let end = parse_size(end)?;
        if end < start {
            return Err(SearchError::Query(
                "size range end precedes start".to_string(),
            ));
        }
        return Ok(SizeRange {
            min_inclusive: Some(start),
            max_exclusive: end.checked_add(1),
        });
    }
    let exact = parse_size(value)?;
    Ok(SizeRange {
        min_inclusive: Some(exact),
        max_exclusive: exact.checked_add(1),
    })
}

fn parse_size(value: &str) -> SearchResult<u64> {
    let value = value.trim().to_ascii_lowercase();
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number: f64 = number
        .parse()
        .map_err(|_| SearchError::Query(format!("invalid size filter '{value}'")))?;
    if !number.is_finite() || number < 0.0 {
        return Err(SearchError::Query(format!("invalid size filter '{value}'")));
    }
    let multiplier = match unit.trim() {
        "" | "b" => 1_f64,
        "kb" | "kib" => 1024_f64,
        "mb" | "mib" => 1024_f64.powi(2),
        "gb" | "gib" => 1024_f64.powi(3),
        "tb" | "tib" => 1024_f64.powi(4),
        _ => {
            return Err(SearchError::Query(format!(
                "unsupported size unit '{unit}'"
            )))
        }
    };
    let bytes = number * multiplier;
    if bytes > u64::MAX as f64 {
        return Err(SearchError::Query("size filter overflows u64".to_string()));
    }
    Ok(bytes.round() as u64)
}

fn path_narrowing_hint(terms: &[String]) -> Option<(String, Vec<String>)> {
    let position = terms
        .iter()
        .position(|term| term.contains('/') || term.contains('\\'))?;
    let token = &terms[position];
    let separator = token.rfind(['/', '\\'])?;
    let parent = token[..separator].trim();
    let filename = token[separator + 1..].trim();
    if parent.is_empty() {
        return None;
    }
    let mut remaining = terms.to_vec();
    remaining.remove(position);
    if !filename.is_empty() {
        remaining.push(filename.to_string());
    }
    Some((parent.to_string(), remaining))
}

pub fn filter_suggestions(prefix: &str) -> Vec<FilterSuggestion> {
    let needle = prefix.trim_start_matches('@').to_ascii_lowercase();
    const FILTERS: &[(&str, &str, &str)] = &[
        ("file:", "kind", "Files only"),
        ("folder:", "kind", "Folders only or folder path"),
        ("app:", "kind", "Applications only"),
        ("ext:", "type", "One or more extensions"),
        ("doc:", "type", "Documents"),
        ("image:", "type", "Images"),
        ("video:", "type", "Video projects and media"),
        ("audio:", "type", "Audio"),
        ("archive:", "type", "Archives"),
        ("code:", "type", "Source code"),
        ("date:today", "date", "Modified today"),
        ("date:week", "date", "Modified this week"),
        ("date:month", "date", "Modified this month"),
        ("size:>10mb", "size", "Larger than 10 MiB"),
        ("device:", "device", "Specific local or paired device"),
        ("favorite:", "source", "Favorites only"),
        ("current:", "source", "Current folder context"),
        ("content:", "mode", "Full-text content search"),
        ("clipboard:", "mode", "Cross Shelf clipboard history"),
        ("browser:", "mode", "Enabled local browser history"),
        ("shelf:", "mode", "Spiffy Shelf items"),
        ("remote:", "mode", "Remote device only"),
    ];
    FILTERS
        .iter()
        .filter(|(token, category, description)| {
            needle.is_empty()
                || token.contains(&needle)
                || category.contains(&needle)
                || description.to_ascii_lowercase().contains(&needle)
        })
        .map(|(token, category, description)| FilterSuggestion {
            token: (*token).to_string(),
            category: (*category).to_string(),
            description: (*description).to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0).unwrap()
    }

    #[test]
    fn parses_phrases_exclusions_extensions_and_modes() {
        let query = ParsedQuery::parse_at(
            "\"annual report\" snowfall -draft ext:pdf;docx -ext:tmp content:",
            fixed_now(),
        )
        .unwrap();
        assert_eq!(query.exact_phrases, ["annual report"]);
        assert_eq!(query.terms, ["snowfall"]);
        assert_eq!(query.excluded_terms, ["draft"]);
        assert!(query.extensions.contains("pdf"));
        assert!(query.extensions.contains("docx"));
        assert!(query.excluded_extensions.contains("tmp"));
        assert_eq!(query.mode, SearchMode::Content);
    }

    #[test]
    fn content_aliases_support_separate_and_attached_queries() {
        for (raw, expected) in [
            ("gety annual report", vec!["annual", "report"]),
            ("gety:annual", vec!["annual"]),
            ("content:annual", vec!["annual"]),
            ("content: annual", vec!["annual"]),
        ] {
            let query = ParsedQuery::parse(raw).unwrap();
            assert_eq!(query.mode, SearchMode::Content, "{raw}");
            assert_eq!(query.terms, expected, "{raw}");
        }
    }

    #[test]
    fn browser_mode_supports_separate_and_attached_queries() {
        for (raw, expected) in [
            ("browser: annual report", vec!["annual", "report"]),
            ("browser:annual report", vec!["annual", "report"]),
        ] {
            let query = ParsedQuery::parse(raw).unwrap();
            assert_eq!(query.mode, SearchMode::Browser, "{raw}");
            assert_eq!(query.terms, expected, "{raw}");
        }
    }

    #[test]
    fn parses_combined_date_size_kind_and_location_filters() {
        let query = ParsedQuery::parse_at(
            "video: date:2026-07-01..2026-07-19 size:10mb..1gb drive:c,d path:projects device:macbook",
            fixed_now(),
        )
        .unwrap();
        assert!(query.categories.contains(&FileCategory::Video));
        assert_eq!(
            query.size_range.unwrap().min_inclusive,
            Some(10 * 1024 * 1024)
        );
        assert_eq!(query.drives.len(), 2);
        assert_eq!(query.paths, ["projects"]);
        assert!(query.devices.contains("macbook"));
        assert!(query.date_range.is_some());
    }

    #[test]
    fn rejects_unclosed_quote_bad_range_and_too_long_query() {
        assert!(ParsedQuery::parse("\"unfinished").is_err());
        assert!(ParsedQuery::parse("size:2gb..1gb").is_err());
        assert!(ParsedQuery::parse("ext:pdf,not/valid").is_err());
        assert!(ParsedQuery::parse("drive:c,zebra").is_err());
        assert!(ParsedQuery::parse(&"a".repeat(MAX_QUERY_BYTES + 1)).is_err());
    }

    #[test]
    fn picker_and_parent_path_are_discoverable() {
        let suggestions = filter_suggestions("@dev");
        assert!(suggestions.iter().any(|item| item.token == "device:"));
        let query = ParsedQuery::parse("snowfall/sources clip").unwrap();
        assert_eq!(query.parent_hint.as_deref(), Some("snowfall"));
        assert_eq!(query.terms, ["clip", "sources"]);
    }
}
