//! Search consumes saved Shelf metadata through a separate capability token.
//! These DTOs never carry a local path, payload, preview, or private item grant.
use crate::ProtocolVersion;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

pub const SHELF_SEARCH_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 1);
pub const SHELF_SEARCH_DISCOVERY_RELATIVE_PATH: &str = "ipc/search-endpoint-v1.json";
pub const SHELF_SEARCH_MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShelfSearchCommand {
    QuerySavedShelf {
        #[serde(deserialize_with = "exact_protocol")]
        protocol: ProtocolVersion,
        generation: u64,
        query: String,
        limit: u16,
        #[serde(default)]
        cursor: Option<String>,
    },
    RevealShelfResult {
        #[serde(deserialize_with = "exact_protocol")]
        protocol: ProtocolVersion,
        reference: ShelfSearchReference,
    },
}

impl ShelfSearchCommand {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::QuerySavedShelf {
                protocol,
                generation,
                query,
                limit,
                cursor,
            } => {
                if *protocol != SHELF_SEARCH_PROTOCOL_VERSION
                    || *generation > i64::MAX as u64
                    || query.len() > 2048
                    || query.contains('\0')
                    || !(1..=100).contains(limit)
                    || cursor.as_ref().is_some_and(|v| !valid_cursor(v))
                {
                    return Err("saved Shelf query is invalid");
                }
            }
            Self::RevealShelfResult {
                protocol,
                reference,
            } => {
                if *protocol != SHELF_SEARCH_PROTOCOL_VERSION {
                    return Err("saved Shelf protocol is incompatible");
                }
                reference.validate()?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ShelfSearchCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::QuerySavedShelf { .. } => "QuerySavedShelf([redacted])",
            Self::RevealShelfResult { .. } => "RevealShelfResult([redacted])",
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShelfSearchReference {
    pub shelf_id: Uuid,
    pub shelf_stamp: String,
    pub item_id: Option<Uuid>,
    pub item_revision: Option<u64>,
}

impl ShelfSearchReference {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.shelf_id.is_nil()
            || self.shelf_stamp.len() != 64
            || !self.shelf_stamp.bytes().all(|b| b.is_ascii_hexdigit())
            || self.item_id.is_some_and(|id| id.is_nil())
            || self.item_id.is_some() != self.item_revision.is_some()
            || self
                .item_revision
                .is_some_and(|v| v == 0 || v > i64::MAX as u64)
        {
            return Err("saved Shelf result reference is invalid");
        }
        Ok(())
    }
}

impl fmt::Debug for ShelfSearchReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShelfSearchReference([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShelfSearchHit {
    pub reference: ShelfSearchReference,
    pub title: String,
    pub shelf_name: String,
    pub kind: String,
    pub missing: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShelfSearchPage {
    pub generation: u64,
    pub results: Vec<ShelfSearchHit>,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    pub stage: ShelfSearchStage,
    pub scanned: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShelfSearchStage {
    Scanning,
    Ready,
}

fn valid_cursor(value: &str) -> bool {
    value.len() <= 96
        && value.split_once(':').is_some_and(|(id, offset)| {
            Uuid::parse_str(id).is_ok_and(|id| !id.is_nil())
                && !offset.is_empty()
                && offset.bytes().all(|v| v.is_ascii_digit())
                && offset.parse::<u64>().is_ok()
        })
}

impl ShelfSearchPage {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.generation > i64::MAX as u64
            || self.results.len() > 100
            || self.has_more != self.next_cursor.is_some()
            || self.next_cursor.as_ref().is_some_and(|v| !valid_cursor(v))
            || self.complete != (self.stage == ShelfSearchStage::Ready && !self.has_more)
            || (self.stage == ShelfSearchStage::Scanning
                && (!self.results.is_empty() || !self.has_more))
        {
            return Err("saved Shelf page exceeds its bounds");
        }
        for hit in &self.results {
            hit.reference.validate()?;
            if hit.title.chars().count() > 240
                || hit.shelf_name.chars().count() > 120
                || hit.title.chars().any(char::is_control)
                || hit.shelf_name.chars().any(char::is_control)
                || !matches!(
                    hit.kind.as_str(),
                    "shelf"
                        | "file"
                        | "folder"
                        | "text"
                        | "url"
                        | "image"
                        | "video"
                        | "audio"
                        | "other"
                )
                || (hit.kind == "shelf") != hit.reference.item_id.is_none()
            {
                return Err("saved Shelf metadata is invalid");
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShelfSearchNavigationReceipt {
    pub reference: ShelfSearchReference,
    pub applied: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShelfSearchReply {
    #[serde(deserialize_with = "exact_protocol")]
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub ok: bool,
    pub page: Option<ShelfSearchPage>,
    pub navigation: Option<ShelfSearchNavigationReceipt>,
    pub error_code: Option<String>,
}

fn exact_protocol<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<ProtocolVersion, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExactProtocol {
        major: u16,
        minor: u16,
    }
    let value = ExactProtocol::deserialize(deserializer)?;
    Ok(ProtocolVersion::new(value.major, value.minor))
}

impl ShelfSearchReply {
    pub fn validate_for(
        &self,
        request_id: Uuid,
        command: &ShelfSearchCommand,
    ) -> Result<(), &'static str> {
        command.validate()?;
        if self.protocol != SHELF_SEARCH_PROTOCOL_VERSION
            || self.request_id != request_id
            || request_id.is_nil()
        {
            return Err("saved Shelf reply identity is invalid");
        }
        if !self.ok {
            if self.page.is_some()
                || self.navigation.is_some()
                || !self.error_code.as_ref().is_some_and(|v| {
                    !v.is_empty()
                        && v.len() <= 80
                        && v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })
            {
                return Err("saved Shelf failure must be content-free");
            }
            return Ok(());
        }
        if self.error_code.is_some() {
            return Err("saved Shelf success includes an error");
        }
        match command {
            ShelfSearchCommand::QuerySavedShelf {
                generation, limit, ..
            } => {
                let page = self
                    .page
                    .as_ref()
                    .ok_or("saved Shelf query omitted its page")?;
                page.validate()?;
                if self.navigation.is_some()
                    || page.generation != *generation
                    || page.results.len() > usize::from(*limit)
                {
                    return Err("saved Shelf page is mismatched");
                }
            }
            ShelfSearchCommand::RevealShelfResult { reference, .. } => {
                if self.page.is_some()
                    || !self
                        .navigation
                        .as_ref()
                        .is_some_and(|v| v.applied && v.reference == *reference)
                {
                    return Err("saved Shelf navigation was not acknowledged");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_requires_explicit_bound_cursor_and_honest_stage() {
        let cursor = format!("{}:31", Uuid::new_v4());
        let mut page = ShelfSearchPage {
            generation: 1,
            results: vec![],
            has_more: true,
            next_cursor: Some(cursor.clone()),
            stage: ShelfSearchStage::Scanning,
            scanned: 64,
            complete: false,
        };
        assert!(page.validate().is_ok());
        page.complete = true;
        assert!(page.validate().is_err());
        page.complete = false;
        page.next_cursor = None;
        assert!(page.validate().is_err());
        for bad in [
            "",
            "../../private:1",
            "00000000-0000-0000-0000-000000000000:1",
        ] {
            let command = ShelfSearchCommand::QuerySavedShelf {
                protocol: SHELF_SEARCH_PROTOCOL_VERSION,
                generation: 1,
                query: "needle".into(),
                limit: 31,
                cursor: Some(bad.into()),
            };
            assert!(command.validate().is_err());
        }
    }
    #[test]
    fn exact_scopes_and_metadata_only_failure_are_enforced() {
        let command = ShelfSearchCommand::QuerySavedShelf {
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            generation: 7,
            query: "private query marker".into(),
            limit: 100,
            cursor: None,
        };
        assert!(command.validate().is_ok());
        assert!(!format!("{command:?}").contains("private query marker"));
        let mut value = serde_json::to_value(&command).unwrap();
        value["path"] = "forbidden".into();
        assert!(serde_json::from_value::<ShelfSearchCommand>(value).is_err());
        let mut nested = serde_json::to_value(&command).unwrap();
        nested["protocol"]["path"] = "forbidden".into();
        assert!(serde_json::from_value::<ShelfSearchCommand>(nested).is_err());
        let request = Uuid::new_v4();
        let mut reply = ShelfSearchReply {
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            request_id: request,
            ok: false,
            page: None,
            navigation: None,
            error_code: Some("unavailable".into()),
        };
        assert!(reply.validate_for(request, &command).is_ok());
        reply.page = Some(ShelfSearchPage {
            generation: 7,
            results: vec![],
            has_more: false,
            next_cursor: None,
            stage: ShelfSearchStage::Ready,
            scanned: 0,
            complete: true,
        });
        assert!(reply.validate_for(request, &command).is_err());
    }
    #[test]
    fn navigation_requires_exact_stable_reference_and_positive_readback() {
        let reference = ShelfSearchReference {
            shelf_id: Uuid::new_v4(),
            shelf_stamp: "a".repeat(64),
            item_id: Some(Uuid::new_v4()),
            item_revision: Some(4),
        };
        let command = ShelfSearchCommand::RevealShelfResult {
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            reference: reference.clone(),
        };
        let request = Uuid::new_v4();
        let mut reply = ShelfSearchReply {
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            request_id: request,
            ok: true,
            page: None,
            navigation: Some(ShelfSearchNavigationReceipt {
                reference,
                applied: true,
            }),
            error_code: None,
        };
        assert!(reply.validate_for(request, &command).is_ok());
        reply.navigation.as_mut().unwrap().applied = false;
        assert!(reply.validate_for(request, &command).is_err());
        reply.navigation.as_mut().unwrap().applied = true;
        reply.navigation.as_mut().unwrap().reference.item_revision = Some(5);
        assert!(reply.validate_for(request, &command).is_err());
    }
}
