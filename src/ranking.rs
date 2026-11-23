use crate::model::{ContentMatch, FileRecord, ItemOverlay, RankingDiagnostics, SearchHit};
use crate::query::{ParsedQuery, SearchMode};
use chrono::Utc;
use nucleo_matcher::pattern::{AtomKind, CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct RankingContext {
    pub current_folder: Option<String>,
    pub open_folders: Vec<String>,
}

pub fn rank_candidates(
    query: &ParsedQuery,
    candidates: impl IntoIterator<Item = (FileRecord, ItemOverlay)>,
    context: &RankingContext,
    limit: usize,
) -> Vec<SearchHit> {
    let require_filename_match = query.mode != SearchMode::Browser;
    rank_candidates_with(
        query,
        candidates
            .into_iter()
            .map(|(record, overlay)| (record, overlay, 0.0, None)),
        context,
        limit,
        require_filename_match,
    )
}

pub fn rank_content_candidates(
    query: &ParsedQuery,
    candidates: impl IntoIterator<Item = (FileRecord, ItemOverlay, f64, ContentMatch)>,
    context: &RankingContext,
    limit: usize,
) -> Vec<SearchHit> {
    rank_candidates_with(
        query,
        candidates
            .into_iter()
            .map(|(record, overlay, relevance, content_match)| {
                (record, overlay, relevance, Some(content_match))
            }),
        context,
        limit,
        false,
    )
}

fn rank_candidates_with(
    query: &ParsedQuery,
    candidates: impl IntoIterator<Item = (FileRecord, ItemOverlay, f64, Option<ContentMatch>)>,
    context: &RankingContext,
    limit: usize,
    require_filename_match: bool,
) -> Vec<SearchHit> {
    let free_text = query.free_text();
    let pattern = Pattern::new(
        &free_text,
        CaseMatching::Smart,
        Normalization::Smart,
        AtomKind::Fuzzy,
    );
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut utf32 = Vec::new();
    let now = Utc::now();
    let query_lower = free_text.to_lowercase();
    let mut hits = candidates
        .into_iter()
        .filter_map(|(record, overlay, relevance, content_match)| {
            let name_lower = record.filename.to_lowercase();
            let stem_lower = record.filename_stem.to_lowercase();
            let mut signals = BTreeMap::new();
            let mut indices = Vec::new();
            let filename_fuzzy = if free_text.is_empty() {
                None
            } else {
                pattern
                    .indices(
                        Utf32Str::new(&record.filename, &mut utf32),
                        &mut matcher,
                        &mut indices,
                    )
                    .map(f64::from)
            };
            let record_aliases = if record.content_type == "workspace_launch" {
                record.tags.as_slice()
            } else {
                &[]
            };
            let mut alias_exact = false;
            let mut alias_fuzzy = 0.0_f64;
            if !free_text.is_empty() {
                for alias in overlay.aliases.iter().chain(record_aliases.iter()) {
                    alias_exact |= alias.eq_ignore_ascii_case(&free_text);
                    let mut alias_indices = Vec::new();
                    if let Some(score) = pattern.indices(
                        Utf32Str::new(alias, &mut utf32),
                        &mut matcher,
                        &mut alias_indices,
                    ) {
                        alias_fuzzy = alias_fuzzy.max(f64::from(score));
                    }
                }
            }
            if require_filename_match
                && !free_text.is_empty()
                && filename_fuzzy.is_none()
                && alias_fuzzy == 0.0
            {
                return None;
            }
            let fuzzy = filename_fuzzy.unwrap_or_default();
            add_signal(&mut signals, "fuzzy_filename", fuzzy);
            add_signal(&mut signals, "fuzzy_alias", alias_fuzzy);
            add_signal(&mut signals, "content_relevance", relevance * 100.0);
            if !query_lower.is_empty() && name_lower == query_lower {
                add_signal(&mut signals, "exact_filename", 1200.0);
            }
            if !query_lower.is_empty() && stem_lower == query_lower {
                add_signal(&mut signals, "exact_stem", 1000.0);
            }
            if !query_lower.is_empty() && name_lower.starts_with(&query_lower) {
                add_signal(&mut signals, "prefix", 600.0);
            }
            if !query_lower.is_empty() && word_boundary_match(&name_lower, &query_lower) {
                add_signal(&mut signals, "word_boundary", 350.0);
            }
            if !query_lower.is_empty() && abbreviation_match(&record.filename, &free_text) {
                add_signal(&mut signals, "abbreviation", 260.0);
            }
            if query.mode == SearchMode::Browser && !query.terms.is_empty() {
                let path =
                    format!("{} {}", record.parent_path, record.normalized_path).to_lowercase();
                let matched_terms = query
                    .terms
                    .iter()
                    .filter(|term| path.contains(&term.to_lowercase()))
                    .count();
                add_signal(&mut signals, "browser_path", matched_terms as f64 * 180.0);
            }
            if let Some(parent) = query.parent_hint.as_deref() {
                if record
                    .parent_path
                    .to_lowercase()
                    .contains(&parent.to_lowercase())
                {
                    add_signal(&mut signals, "parent_path", 420.0);
                } else {
                    add_signal(&mut signals, "parent_path_miss", -800.0);
                }
            }
            if context
                .current_folder
                .as_ref()
                .is_some_and(|folder| record.normalized_path.starts_with(folder))
            {
                add_signal(&mut signals, "current_folder", 240.0);
            }
            if context
                .open_folders
                .iter()
                .any(|folder| record.normalized_path.starts_with(folder))
            {
                add_signal(&mut signals, "open_folder", 100.0);
            }
            if overlay.favorite {
                add_signal(&mut signals, "favorite", 300.0);
            }
            if overlay.pinned {
                add_signal(&mut signals, "pin", 500.0);
            }
            if alias_exact {
                add_signal(&mut signals, "alias", 1100.0);
            }
            if overlay.usage_count > 0 {
                add_signal(
                    &mut signals,
                    "frequency",
                    (overlay.usage_count as f64).ln_1p() * 45.0,
                );
            }
            if let Some(last_used) = overlay.last_opened.or(overlay.last_selected) {
                let age_days = (now - last_used).num_seconds().max(0) as f64 / 86_400.0;
                add_signal(&mut signals, "recency", 180.0 / (1.0 + age_days / 7.0));
            }
            add_signal(
                &mut signals,
                "custom_priority",
                f64::from(overlay.custom_priority) * 10.0,
            );
            if record.missing {
                add_signal(&mut signals, "missing", -1500.0);
            }
            if record.tombstone {
                add_signal(&mut signals, "tombstone", -3000.0);
            }
            let score = signals.values().sum();
            Some(SearchHit {
                record,
                score,
                match_indices: indices,
                diagnostics: RankingDiagnostics { signals },
                content_match,
            })
        })
        .collect::<Vec<_>>();
    hits.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| {
                left.record
                    .normalized_path
                    .cmp(&right.record.normalized_path)
            })
            .then_with(|| left.record.stable_key.cmp(&right.record.stable_key))
    });
    hits.truncate(limit);
    hits
}

fn add_signal(signals: &mut BTreeMap<String, f64>, name: &str, value: f64) {
    if value != 0.0 {
        signals.insert(name.to_string(), value);
    }
}

fn word_boundary_match(haystack: &str, needle: &str) -> bool {
    haystack
        .match_indices(needle)
        .any(|(index, _)| index == 0 || !haystack.as_bytes()[index - 1].is_ascii_alphanumeric())
}

fn abbreviation_match(haystack: &str, needle: &str) -> bool {
    let abbreviation = haystack
        .split(|character: char| !character.is_alphanumeric())
        .filter_map(|word| word.chars().next())
        .collect::<String>();
    !abbreviation.is_empty() && abbreviation.eq_ignore_ascii_case(needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FileCategory, ItemKind};
    use uuid::Uuid;

    fn record(name: &str, path: &str) -> FileRecord {
        FileRecord {
            stable_key: path.to_string(),
            stable_file_id: None,
            root_id: Uuid::nil(),
            device_id: Uuid::nil(),
            canonical_path: path.to_string(),
            display_path: path.to_string(),
            normalized_path: path.to_lowercase(),
            filename: name.to_string(),
            filename_stem: name.split('.').next().unwrap_or(name).to_string(),
            extension: name.rsplit('.').next().unwrap_or("").to_string(),
            parent_path: "c:/projects".to_string(),
            parent_tokens: "projects".to_string(),
            item_kind: ItemKind::File,
            category: FileCategory::Video,
            content_type: "video".to_string(),
            mime_type: "video/mp4".to_string(),
            size: 100,
            created_time: None,
            modified_time: None,
            last_seen_time: Utc::now(),
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
            source_provider: "private_index".to_string(),
            remote_device: None,
            content_index_state: "disabled".to_string(),
            preview_state: "unknown".to_string(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn exact_pin_and_alias_signals_are_deterministic() {
        let query = ParsedQuery::parse("snowfall sources").unwrap();
        let overlay = ItemOverlay {
            favorite: true,
            pinned: true,
            aliases: vec!["snowfall sources".to_string()],
            ..ItemOverlay::default()
        };
        let hits = rank_candidates(
            &query,
            [(
                record("Snowfall Sources.mp4", "c:/projects/snowfall.mp4"),
                overlay,
            )],
            &RankingContext::default(),
            10,
        );
        assert_eq!(hits.len(), 1);
        assert!(hits[0].diagnostics.signals.contains_key("alias"));
        assert!(hits[0].diagnostics.signals.contains_key("pin"));
    }

    #[test]
    fn stable_path_breaks_equal_score_ties() {
        let query = ParsedQuery::parse("clip").unwrap();
        let hits = rank_candidates(
            &query,
            [
                (record("clip.mp4", "c:/b/clip.mp4"), ItemOverlay::default()),
                (record("clip.mp4", "c:/a/clip.mp4"), ItemOverlay::default()),
            ],
            &RankingContext::default(),
            10,
        );
        assert_eq!(hits[0].record.normalized_path, "c:/a/clip.mp4");
    }

    #[test]
    fn browser_candidates_can_match_the_url_when_the_title_does_not() {
        let query = ParsedQuery::parse("browser:projects").unwrap();
        let mut browser = record("Unrelated title", "https://example.com/projects/hero");
        browser.item_kind = crate::model::ItemKind::Browser;
        browser.parent_path = "example.com".to_string();
        let hits = rank_candidates(
            &query,
            [(browser, ItemOverlay::default())],
            &RankingContext::default(),
            10,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].diagnostics.signals.get("browser_path"),
            Some(&180.0)
        );
    }

    #[test]
    fn workspace_application_alias_can_rank_when_filename_does_not_match() {
        let query = ParsedQuery::parse("Visual Clipboard").unwrap();
        let mut application = record(
            "Spiffy Clipboard",
            "c:/spiffy/Launch Spiffy Photo Editor.bat",
        );
        application.item_kind = ItemKind::Application;
        application.application = true;
        application.content_type = "workspace_launch".to_string();
        application.tags = vec!["Visual Clipboard".to_string(), "Photo Editor".to_string()];

        let hits = rank_candidates(
            &query,
            [(application, ItemOverlay::default())],
            &RankingContext::default(),
            10,
        );

        assert_eq!(hits.len(), 1);
        assert!(hits[0].diagnostics.signals.contains_key("alias"));
        assert!(hits[0].diagnostics.signals.contains_key("fuzzy_alias"));
        assert!(!hits[0].diagnostics.signals.contains_key("fuzzy_filename"));
    }
}
