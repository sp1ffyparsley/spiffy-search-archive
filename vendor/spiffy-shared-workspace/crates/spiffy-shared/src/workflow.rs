use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ProtocolVersion, ShelfItemKind};

pub const WORKFLOW_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
pub const MAX_OWNER_ID_CHARS: usize = 128;
pub const MAX_ENTITY_ID_CHARS: usize = 256;
pub const MAX_DISPLAY_NAME_CHARS: usize = 512;
pub const MAX_RELATION_MEMBERS: usize = 500;
pub const MAX_RECIPE_DEPENDENCIES: usize = 128;
pub const MAX_RECIPE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_LEASE_BYTES: u64 = 100 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    Reference,
    ManagedCopy,
    SecureTemp,
    ClipboardProviderItem,
    AppRecipe,
    CaptureReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfile {
    Standard,
    Private,
    SecureTemp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableOwnerRef {
    pub owner_id: String,
    pub entity_id: String,
    pub entity_kind: String,
    pub revision: u64,
    pub digest_blake3: String,
}

impl StableOwnerRef {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_token(&self.owner_id, MAX_OWNER_ID_CHARS, "owner ID")?;
        validate_token(&self.entity_id, MAX_ENTITY_ID_CHARS, "entity ID")?;
        validate_token(&self.entity_kind, 64, "entity kind")?;
        validate_blake3(&self.digest_blake3)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    Input,
    Output,
    Drag,
    Clipboard,
    Preview,
    FilePromise,
    SecureCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Offered,
    Active,
    Completed,
    Cancelled,
    Expired,
    Failed,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFileLease {
    pub lease_id: Uuid,
    pub kind: LeaseKind,
    pub owner_id: String,
    pub opaque_path: String,
    pub expected_bytes: Option<u64>,
    pub expected_blake3: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: LeaseState,
}

impl LocalFileLease {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if self.lease_id.is_nil() {
            return Err("lease ID must not be nil");
        }
        validate_token(&self.owner_id, MAX_OWNER_ID_CHARS, "lease owner ID")?;
        if self.opaque_path.is_empty() || self.opaque_path.len() > 32_768 {
            return Err("lease path must contain 1 to 32768 bytes");
        }
        if self
            .expected_bytes
            .is_some_and(|size| size > MAX_LEASE_BYTES)
        {
            return Err("lease byte limit exceeds 100 GiB");
        }
        if let Some(digest) = &self.expected_blake3 {
            validate_blake3(digest)?;
        }
        if self.expires_at <= self.created_at || self.expires_at <= now {
            return Err("lease must have a future expiry after creation");
        }
        Ok(())
    }
}

impl fmt::Debug for LocalFileLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalFileLease")
            .field("lease_id", &self.lease_id)
            .field("kind", &self.kind)
            .field("owner_id", &self.owner_id)
            .field("opaque_path", &"[redacted]")
            .field("expected_bytes", &self.expected_bytes)
            .field("expected_blake3", &self.expected_blake3)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureKind {
    Screenshot,
    Recording,
    CaptureSet,
}

/// A finalized OBS master-session take. Digests name bounded owner sidecars,
/// never claim that a metadata-only recording lease hashed the raw media.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingOrigin {
    pub schema_version: u32,
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub stopped_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub range_start_ms: u64,
    pub range_end_ms: u64,
    pub source_modified_ns: u64,
    pub certificate_digest_blake3: String,
    pub session_digest_blake3: String,
    pub events_digest_blake3: String,
}

impl RecordingOrigin {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_token(
            &self.session_id,
            MAX_ENTITY_ID_CHARS,
            "recording session ID",
        )?;
        if self.schema_version != 1
            || self.stopped_at <= self.started_at
            || self.duration_ms == 0
            || self.duration_ms > 7 * 24 * 60 * 60 * 1000
            || self.range_start_ms != 0
            || self.range_end_ms != self.duration_ms
            || self.source_modified_ns == 0
        {
            return Err("recording origin requires one finalized whole take with certified timing");
        }
        validate_blake3(&self.certificate_digest_blake3)?;
        validate_blake3(&self.session_digest_blake3)?;
        validate_blake3(&self.events_digest_blake3)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePublication {
    pub protocol: ProtocolVersion,
    pub publication_id: Uuid,
    pub capture: StableOwnerRef,
    pub capture_kind: CaptureKind,
    pub display_name: String,
    pub source_lease: LocalFileLease,
    pub preview_lease: Option<LocalFileLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_origin: Option<RecordingOrigin>,
    pub created_at: DateTime<Utc>,
    pub published_at: DateTime<Utc>,
}

impl CapturePublication {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if !self.protocol.is_compatible_with(WORKFLOW_PROTOCOL_VERSION) {
            return Err("capture publication protocol major is incompatible");
        }
        if self.publication_id.is_nil() {
            return Err("capture publication ID must not be nil");
        }
        self.capture.validate()?;
        validate_text(
            &self.display_name,
            MAX_DISPLAY_NAME_CHARS,
            "capture display name",
        )?;
        self.source_lease.validate(now)?;
        if let Some(origin) = &self.recording_origin {
            origin.validate()?;
            if self.capture.owner_id != "spiffy.obs_capture"
                || self.capture.entity_kind != "recording"
                || self.capture_kind != CaptureKind::Recording
                || self.capture.entity_id != origin.session_id
                || self.capture.digest_blake3 != origin.certificate_digest_blake3
                || self
                    .source_lease
                    .expected_bytes
                    .is_none_or(|size| size == 0)
                || self.created_at != origin.started_at
                || self.published_at < origin.stopped_at
            {
                return Err("recording origin does not match the finalized capture identity");
            }
        } else if self.capture.owner_id == "spiffy.obs_capture" {
            return Err("OBS capture publication requires its recording origin");
        }
        if let Some(preview) = &self.preview_lease {
            preview.validate(now)?;
        }
        if self.published_at < self.created_at {
            return Err("capture publication predates capture creation");
        }
        Ok(())
    }
}

impl fmt::Debug for CapturePublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturePublication")
            .field("protocol", &self.protocol)
            .field("publication_id", &self.publication_id)
            .field("capture", &self.capture)
            .field("capture_kind", &self.capture_kind)
            .field("display_name", &"[redacted]")
            .field("source_lease", &self.source_lease)
            .field("preview_lease", &self.preview_lease)
            .field("created_at", &self.created_at)
            .field("published_at", &self.published_at)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    OriginalToVariant,
    SourceToOutput,
    CaptureToShelf,
    RecipeToOutput,
    ProjectContextMember,
    StackMember,
    DerivedFrom,
    Related,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRelation {
    pub relation_id: Uuid,
    pub kind: RelationKind,
    pub source: StableOwnerRef,
    pub target: StableOwnerRef,
    pub provider_id: String,
    pub created_at: DateTime<Utc>,
    pub supersedes: Option<Uuid>,
}

impl WorkflowRelation {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.relation_id.is_nil() || self.supersedes.is_some_and(|value| value.is_nil()) {
            return Err("relation IDs must not be nil");
        }
        self.source.validate()?;
        self.target.validate()?;
        validate_token(
            &self.provider_id,
            MAX_OWNER_ID_CHARS,
            "relation provider ID",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackMemberContract {
    pub item: StableOwnerRef,
    pub ordinal: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackContract {
    pub stack_id: Uuid,
    pub owner_id: String,
    pub name: String,
    pub members: Vec<StackMemberContract>,
    pub security_profile: SecurityProfile,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl StackContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.stack_id.is_nil() {
            return Err("stack ID must not be nil");
        }
        validate_token(&self.owner_id, MAX_OWNER_ID_CHARS, "stack owner ID")?;
        validate_text(&self.name, MAX_DISPLAY_NAME_CHARS, "stack name")?;
        if self.members.is_empty() || self.members.len() > MAX_RELATION_MEMBERS {
            return Err("stack must contain 1 to 500 members");
        }
        let mut ordinals = std::collections::BTreeSet::new();
        for member in &self.members {
            member.item.validate()?;
            if !ordinals.insert(member.ordinal) {
                return Err("stack member ordinals must be unique");
            }
        }
        Ok(())
    }
}

impl fmt::Debug for StackContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StackContract")
            .field("stack_id", &self.stack_id)
            .field("owner_id", &self.owner_id)
            .field("name", &"[redacted]")
            .field("member_count", &self.members.len())
            .field("security_profile", &self.security_profile)
            .field("expires_at", &self.expires_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectContextContract {
    pub context_id: Uuid,
    pub owner_id: String,
    pub name: String,
    pub revision: u64,
    pub members: Vec<StableOwnerRef>,
    pub updated_at: DateTime<Utc>,
}

impl ProjectContextContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.context_id.is_nil() {
            return Err("project context ID must not be nil");
        }
        validate_token(
            &self.owner_id,
            MAX_OWNER_ID_CHARS,
            "project context owner ID",
        )?;
        validate_text(&self.name, MAX_DISPLAY_NAME_CHARS, "project context name")?;
        if self.members.len() > MAX_RELATION_MEMBERS {
            return Err("project context permits at most 500 members");
        }
        for member in &self.members {
            member.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for ProjectContextContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectContextContract")
            .field("context_id", &self.context_id)
            .field("owner_id", &self.owner_id)
            .field("name", &"[redacted]")
            .field("revision", &self.revision)
            .field("member_count", &self.members.len())
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRecipeContract {
    pub protocol: ProtocolVersion,
    pub recipe_id: Uuid,
    pub owner_id: String,
    pub host_application_id: String,
    pub recipe_type: String,
    pub recipe_version: u16,
    pub title: String,
    pub source: StableOwnerRef,
    pub dependencies: Vec<StableOwnerRef>,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl AppRecipeContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.protocol.is_compatible_with(WORKFLOW_PROTOCOL_VERSION) {
            return Err("app recipe protocol major is incompatible");
        }
        if self.recipe_id.is_nil() || self.recipe_version == 0 {
            return Err("app recipe ID must not be nil and version must be positive");
        }
        validate_token(&self.owner_id, MAX_OWNER_ID_CHARS, "recipe owner ID")?;
        validate_token(
            &self.host_application_id,
            MAX_OWNER_ID_CHARS,
            "recipe host application ID",
        )?;
        validate_token(&self.recipe_type, 128, "recipe type")?;
        validate_text(&self.title, MAX_DISPLAY_NAME_CHARS, "recipe title")?;
        self.source.validate()?;
        if self.dependencies.len() > MAX_RECIPE_DEPENDENCIES {
            return Err("app recipe permits at most 128 dependencies");
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        let payload_size = serde_json::to_vec(&self.payload)
            .map_err(|_| "app recipe payload is not serializable")?
            .len();
        if payload_size > MAX_RECIPE_PAYLOAD_BYTES {
            return Err("app recipe payload exceeds 1 MiB");
        }
        Ok(())
    }
}

impl fmt::Debug for AppRecipeContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppRecipeContract")
            .field("protocol", &self.protocol)
            .field("recipe_id", &self.recipe_id)
            .field("owner_id", &self.owner_id)
            .field("host_application_id", &self.host_application_id)
            .field("recipe_type", &self.recipe_type)
            .field("recipe_version", &self.recipe_version)
            .field("title", &"[redacted]")
            .field("source", &self.source)
            .field("dependency_count", &self.dependencies.len())
            .field("payload", &"[redacted]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariantContract {
    pub variant_id: Uuid,
    pub root_original: StableOwnerRef,
    pub immediate_parent: StableOwnerRef,
    pub output: StableOwnerRef,
    pub job_id: Uuid,
    pub preset_id: String,
    pub preset_version: u16,
    pub output_format: String,
    pub preferred: bool,
    pub created_at: DateTime<Utc>,
}

impl VariantContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.variant_id.is_nil() || self.job_id.is_nil() || self.preset_version == 0 {
            return Err("variant and job IDs must not be nil and preset version must be positive");
        }
        self.root_original.validate()?;
        self.immediate_parent.validate()?;
        self.output.validate()?;
        validate_token(&self.preset_id, 128, "variant preset ID")?;
        validate_token(&self.output_format, 64, "variant output format")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShelfSelectionRef {
    pub item: StableOwnerRef,
    pub kind: ShelfItemKind,
    pub storage_class: StorageClass,
    pub security_profile: SecurityProfile,
}

impl ShelfSelectionRef {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.item.validate()
    }
}

pub(crate) fn validate_token(
    value: &str,
    max_chars: usize,
    label: &'static str,
) -> Result<(), &'static str> {
    let count = value.chars().count();
    if count == 0 || count > max_chars || value.chars().any(char::is_whitespace) {
        return Err(match label {
            "owner ID" => "owner ID must be a non-whitespace token of at most 128 characters",
            _ => "identifier must be a bounded non-whitespace token",
        });
    }
    Ok(())
}

pub(crate) fn validate_text(
    value: &str,
    max_chars: usize,
    _label: &'static str,
) -> Result<(), &'static str> {
    let count = value.chars().count();
    if value.trim().is_empty() || count > max_chars {
        return Err("text field is empty or exceeds its character limit");
    }
    Ok(())
}

pub(crate) fn validate_blake3(value: &str) -> Result<(), &'static str> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("BLAKE3 digest must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_ref() -> StableOwnerRef {
        StableOwnerRef {
            owner_id: "spiffy.shelf".to_string(),
            entity_id: Uuid::new_v4().to_string(),
            entity_kind: "shelf_item".to_string(),
            revision: 4,
            digest_blake3: "ab".repeat(32),
        }
    }

    #[test]
    fn stable_owner_refs_require_full_digest_and_bounded_ids() {
        assert!(owner_ref().validate().is_ok());
        let mut invalid = owner_ref();
        invalid.digest_blake3 = "abcd".to_string();
        assert!(invalid.validate().is_err());
        invalid = owner_ref();
        invalid.owner_id = "contains a space".to_string();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn leases_redact_paths_and_reject_expired_or_unbounded_files() {
        let now = Utc::now();
        let mut lease = LocalFileLease {
            lease_id: Uuid::new_v4(),
            kind: LeaseKind::Input,
            owner_id: "spiffy.shelf".to_string(),
            opaque_path: "C:/private/client.mov".to_string(),
            expected_bytes: Some(42),
            expected_blake3: Some("cd".repeat(32)),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            state: LeaseState::Active,
        };
        assert!(lease.validate(now).is_ok());
        assert!(!format!("{lease:?}").contains("client.mov"));
        lease.expected_bytes = Some(MAX_LEASE_BYTES + 1);
        assert!(lease.validate(now).is_err());
    }

    #[test]
    fn stack_ordinals_are_unique_and_bounded() {
        let item = owner_ref();
        let stack = StackContract {
            stack_id: Uuid::new_v4(),
            owner_id: "spiffy.shelf".to_string(),
            name: "Upload set".to_string(),
            members: vec![
                StackMemberContract {
                    item: item.clone(),
                    ordinal: 0,
                },
                StackMemberContract { item, ordinal: 0 },
            ],
            security_profile: SecurityProfile::Standard,
            expires_at: None,
            updated_at: Utc::now(),
        };
        assert_eq!(
            stack.validate(),
            Err("stack member ordinals must be unique")
        );
    }

    #[test]
    fn recipe_debug_redacts_title_and_payload() {
        let recipe = AppRecipeContract {
            protocol: WORKFLOW_PROTOCOL_VERSION,
            recipe_id: Uuid::new_v4(),
            owner_id: "spiffy.premiere".to_string(),
            host_application_id: "premiere".to_string(),
            recipe_type: "marker_set".to_string(),
            recipe_version: 1,
            title: "private-client-title".to_string(),
            source: owner_ref(),
            dependencies: Vec::new(),
            payload: serde_json::json!({"secret": "private-payload"}),
            created_at: Utc::now(),
        };
        assert!(recipe.validate().is_ok());
        let debug = format!("{recipe:?}");
        assert!(!debug.contains("private-client-title"));
        assert!(!debug.contains("private-payload"));
    }

    #[test]
    fn content_bearing_workflow_debug_is_privacy_safe() {
        let now = Utc::now();
        let lease = LocalFileLease {
            lease_id: Uuid::new_v4(),
            kind: LeaseKind::Input,
            owner_id: "spiffy.capture".to_string(),
            opaque_path: "C:/private/capture.png".to_string(),
            expected_bytes: Some(42),
            expected_blake3: Some("de".repeat(32)),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            state: LeaseState::Active,
        };
        let capture = CapturePublication {
            recording_origin: None,
            protocol: WORKFLOW_PROTOCOL_VERSION,
            publication_id: Uuid::new_v4(),
            capture: owner_ref(),
            capture_kind: CaptureKind::Screenshot,
            display_name: "private-capture-title".to_string(),
            source_lease: lease,
            preview_lease: None,
            created_at: now,
            published_at: now,
        };
        let capture_debug = format!("{capture:?}");
        assert!(!capture_debug.contains("private-capture-title"));
        assert!(!capture_debug.contains("capture.png"));

        let stack = StackContract {
            stack_id: Uuid::new_v4(),
            owner_id: "spiffy.shelf".to_string(),
            name: "private-stack-name".to_string(),
            members: vec![StackMemberContract {
                item: owner_ref(),
                ordinal: 0,
            }],
            security_profile: SecurityProfile::Private,
            expires_at: None,
            updated_at: now,
        };
        assert!(!format!("{stack:?}").contains("private-stack-name"));
    }

    #[test]
    fn workflow_contracts_deny_unknown_fields() {
        let encoded = serde_json::json!({
            "owner_id": "spiffy.shelf",
            "entity_id": "item-1",
            "entity_kind": "shelf_item",
            "revision": 1,
            "digest_blake3": "aa".repeat(32),
            "unexpected": true
        });
        assert!(serde_json::from_value::<StableOwnerRef>(encoded).is_err());
    }

    #[test]
    fn recording_origin_requires_bounded_whole_take_and_exact_schema() {
        let now = Utc::now();
        let mut origin = RecordingOrigin {
            schema_version: 1,
            session_id: "session-real-owner".into(),
            started_at: now - chrono::Duration::seconds(2),
            stopped_at: now,
            duration_ms: 1000,
            range_start_ms: 0,
            range_end_ms: 1000,
            source_modified_ns: 1,
            certificate_digest_blake3: "a".repeat(64),
            session_digest_blake3: "b".repeat(64),
            events_digest_blake3: "c".repeat(64),
        };
        origin.validate().unwrap();
        let mut json = serde_json::to_value(&origin).unwrap();
        assert_eq!(
            serde_json::from_value::<RecordingOrigin>(json.clone()).unwrap(),
            origin
        );
        json["source_path"] = "unowned".into();
        assert!(serde_json::from_value::<RecordingOrigin>(json).is_err());
        origin.range_start_ms = 1;
        assert!(origin.validate().is_err());
        origin.range_start_ms = 0;
        origin.duration_ms = 8 * 24 * 60 * 60 * 1000;
        origin.range_end_ms = origin.duration_ms;
        assert!(origin.validate().is_err());
    }
}
