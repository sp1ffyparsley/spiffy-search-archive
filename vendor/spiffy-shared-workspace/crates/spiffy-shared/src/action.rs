use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::workflow::{validate_text, validate_token};
use crate::{
    LeaseKind, LocalFileLease, ProtocolVersion, SecurityProfile, ShelfItemKind, ShelfSelectionRef,
    StableOwnerRef, StorageClass,
};

pub const ACTION_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
pub const ACTION_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const ACTION_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const MAX_ACTION_SELECTIONS: usize = 500;
pub const MAX_ACTION_RELATIONS: usize = 500;
pub const MAX_ACTION_CAPABILITIES: usize = 128;
pub const MAX_ACTION_PARAMETERS_BYTES: usize = 1024 * 1024;
pub const MAX_ACTION_MESSAGES: usize = 100;
pub const MAX_ACTION_MESSAGE_CHARS: usize = 2_048;
pub const MAX_ACTION_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProviderIdentity {
    pub owner_id: String,
    pub provider_version: String,
    pub executable_digest_blake3: Option<String>,
}

impl ActionProviderIdentity {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_token(&self.owner_id, 128, "provider owner ID")?;
        validate_token(&self.provider_version, 64, "provider version")?;
        if let Some(digest) = &self.executable_digest_blake3 {
            crate::workflow::validate_blake3(digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMutationPolicy {
    None,
    MetadataOnly,
    CreatesDerivedOutput,
    MutatesSourceWithReadback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationPolicy {
    None,
    BeforeDispatch,
    BeforeSourceMutation,
    BeforeDestructiveAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationPolicy {
    None,
    WhenPrivate,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencePolicy {
    Required,
    Supported,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProviderManifest {
    pub schema_version: u16,
    pub action_id: String,
    pub display_name: String,
    pub provider: ActionProviderIdentity,
    pub supported_item_kinds: Vec<ShelfItemKind>,
    pub supported_storage_classes: Vec<StorageClass>,
    pub supported_security_profiles: Vec<SecurityProfile>,
    pub input_schema: String,
    pub output_schema: String,
    pub source_mutation_policy: SourceMutationPolicy,
    pub destructive: bool,
    pub confirmation_policy: ConfirmationPolicy,
    pub authentication_policy: AuthenticationPolicy,
    pub supports_progress: bool,
    pub supports_cancel: bool,
    pub timeout_millis: u64,
    pub idempotence_policy: IdempotencePolicy,
    pub resource_class: String,
    pub receipt_schema: String,
    pub minimum_owner_version: String,
    pub required_capabilities: Vec<String>,
}

impl ActionProviderManifest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != ACTION_MANIFEST_SCHEMA_VERSION {
            return Err("action manifest schema version is unsupported");
        }
        validate_token(&self.action_id, 192, "action ID")?;
        validate_text(&self.display_name, 256, "action display name")?;
        self.provider.validate()?;
        validate_nonempty_unique(&self.supported_item_kinds, 32, "item kinds")?;
        validate_nonempty_unique(&self.supported_storage_classes, 16, "storage classes")?;
        validate_nonempty_unique(&self.supported_security_profiles, 16, "security profiles")?;
        for token in [
            &self.input_schema,
            &self.output_schema,
            &self.resource_class,
            &self.receipt_schema,
            &self.minimum_owner_version,
        ] {
            validate_token(token, 192, "action manifest token")?;
        }
        if self.timeout_millis == 0 || self.timeout_millis > MAX_ACTION_TIMEOUT_MILLIS {
            return Err("action timeout must be between 1 ms and 24 hours");
        }
        if self.destructive
            && self.confirmation_policy != ConfirmationPolicy::BeforeDestructiveAction
        {
            return Err("destructive actions require destructive confirmation policy");
        }
        if self.source_mutation_policy == SourceMutationPolicy::MutatesSourceWithReadback
            && self.confirmation_policy == ConfirmationPolicy::None
        {
            return Err("source-mutating actions require confirmation");
        }
        if self.required_capabilities.len() > MAX_ACTION_CAPABILITIES {
            return Err("action manifest permits at most 128 capabilities");
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.required_capabilities {
            validate_token(capability, 128, "action capability")?;
            if !capabilities.insert(capability) {
                return Err("action capabilities must be unique");
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAuthorizationScope {
    pub grant_id: Uuid,
    pub security_profile: SecurityProfile,
    pub unlock_epoch: u64,
    pub permitted_action_id: String,
    pub expires_at: DateTime<Utc>,
}

impl ActionAuthorizationScope {
    pub fn validate(&self, now: DateTime<Utc>, action_id: &str) -> Result<(), &'static str> {
        if self.grant_id.is_nil() {
            return Err("authorization grant ID must not be nil");
        }
        if self.expires_at <= now {
            return Err("authorization grant is expired");
        }
        if self.permitted_action_id != action_id {
            return Err("authorization grant does not cover the action");
        }
        Ok(())
    }
}

impl fmt::Debug for ActionAuthorizationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionAuthorizationScope")
            .field("grant_id", &self.grant_id)
            .field("security_profile", &self.security_profile)
            .field("unlock_epoch", &"[redacted]")
            .field("permitted_action_id", &self.permitted_action_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDispatchPacket {
    pub protocol: ProtocolVersion,
    pub action_run_id: Uuid,
    pub action_id: String,
    pub provider: ActionProviderIdentity,
    pub selections: Vec<ShelfSelectionRef>,
    pub relation_ids: Vec<Uuid>,
    pub parameters: serde_json::Value,
    pub authorization: Option<ActionAuthorizationScope>,
    pub output_lease: LocalFileLease,
    pub idempotence_key: String,
    pub requested_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

impl ActionDispatchPacket {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if !self.protocol.is_compatible_with(ACTION_PROTOCOL_VERSION) {
            return Err("action protocol major is incompatible");
        }
        if self.action_run_id.is_nil() {
            return Err("action run ID must not be nil");
        }
        validate_token(&self.action_id, 192, "action ID")?;
        self.provider.validate()?;
        if self.selections.is_empty() || self.selections.len() > MAX_ACTION_SELECTIONS {
            return Err("action dispatch requires 1 to 500 selections");
        }
        for selection in &self.selections {
            selection.validate()?;
        }
        if self.relation_ids.len() > MAX_ACTION_RELATIONS
            || self.relation_ids.iter().any(Uuid::is_nil)
            || self.relation_ids.iter().collect::<BTreeSet<_>>().len() != self.relation_ids.len()
        {
            return Err("action relation IDs must be unique, non-nil, and at most 500");
        }
        let parameters_size = serde_json::to_vec(&self.parameters)
            .map_err(|_| "action parameters are not serializable")?
            .len();
        if parameters_size > MAX_ACTION_PARAMETERS_BYTES {
            return Err("action parameters exceed 1 MiB");
        }
        if let Some(authorization) = &self.authorization {
            authorization.validate(now, &self.action_id)?;
        }
        self.output_lease.validate(now)?;
        if self.output_lease.kind != LeaseKind::Output {
            return Err("action dispatch requires an output lease");
        }
        validate_token(&self.idempotence_key, 256, "idempotence key")?;
        if self.deadline <= self.requested_at || self.deadline <= now {
            return Err("action deadline must be in the future and after request time");
        }
        if (self.deadline - self.requested_at).num_milliseconds() > MAX_ACTION_TIMEOUT_MILLIS as i64
        {
            return Err("action deadline exceeds the 24-hour maximum");
        }
        Ok(())
    }
}

impl fmt::Debug for ActionDispatchPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionDispatchPacket")
            .field("protocol", &self.protocol)
            .field("action_run_id", &self.action_run_id)
            .field("action_id", &self.action_id)
            .field("provider", &self.provider)
            .field("selection_count", &self.selections.len())
            .field("relation_count", &self.relation_ids.len())
            .field("parameters", &"[redacted]")
            .field("authorization", &self.authorization)
            .field("output_lease", &self.output_lease)
            .field("idempotence_key", &"[redacted]")
            .field("requested_at", &self.requested_at)
            .field("deadline", &self.deadline)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRunState {
    Queued,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Stale,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProgress {
    pub action_run_id: Uuid,
    pub sequence: u64,
    pub state: ActionRunState,
    pub completed_units: u64,
    pub total_units: Option<u64>,
    pub phase_code: String,
    pub updated_at: DateTime<Utc>,
}

impl ActionProgress {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.action_run_id.is_nil() {
            return Err("action progress run ID must not be nil");
        }
        validate_token(&self.phase_code, 128, "action progress phase")?;
        if self
            .total_units
            .is_some_and(|total| self.completed_units > total)
        {
            return Err("action progress exceeds its total");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMutationState {
    NotRequested,
    Unchanged,
    ChangedAndVerified,
    ChangedRollbackAvailable,
    ChangedRollbackFailed,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    pub schema_version: u16,
    pub action_run_id: Uuid,
    pub action_id: String,
    pub provider: ActionProviderIdentity,
    pub state: ActionRunState,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub inputs: Vec<StableOwnerRef>,
    pub outputs: Vec<StableOwnerRef>,
    pub source_mutation_state: SourceMutationState,
    pub source_current: bool,
    pub superseded_by: Option<Uuid>,
    pub warning_codes: Vec<String>,
    pub error_codes: Vec<String>,
    pub retryable: bool,
    pub rollback_receipt_id: Option<Uuid>,
    pub cleanup_complete: bool,
    pub human_review_required: bool,
}

impl ActionReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != ACTION_RECEIPT_SCHEMA_VERSION {
            return Err("action receipt schema version is unsupported");
        }
        if self.action_run_id.is_nil()
            || self.superseded_by.is_some_and(|value| value.is_nil())
            || self.rollback_receipt_id.is_some_and(|value| value.is_nil())
        {
            return Err("action receipt IDs must not be nil");
        }
        validate_token(&self.action_id, 192, "action ID")?;
        self.provider.validate()?;
        if self.ended_at < self.started_at {
            return Err("action receipt ends before it starts");
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_ACTION_SELECTIONS {
            return Err("action receipt requires 1 to 500 inputs");
        }
        if self.outputs.len() > MAX_ACTION_SELECTIONS {
            return Err("action receipt permits at most 500 outputs");
        }
        for reference in self.inputs.iter().chain(&self.outputs) {
            reference.validate()?;
        }
        validate_codes(&self.warning_codes)?;
        validate_codes(&self.error_codes)?;
        if self.state == ActionRunState::Succeeded && !self.error_codes.is_empty() {
            return Err("successful action receipt must not include errors");
        }
        if !self.source_current && self.state == ActionRunState::Succeeded {
            return Err("a stale source cannot produce a current successful receipt");
        }
        Ok(())
    }
}

fn validate_nonempty_unique<T>(
    values: &[T],
    max: usize,
    _label: &'static str,
) -> Result<(), &'static str>
where
    T: Ord,
{
    if values.is_empty() || values.len() > max {
        return Err("manifest compatibility list is empty or exceeds its limit");
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err("manifest compatibility values must be unique");
    }
    Ok(())
}

fn validate_codes(values: &[String]) -> Result<(), &'static str> {
    if values.len() > MAX_ACTION_MESSAGES {
        return Err("action receipt permits at most 100 warning or error codes");
    }
    for value in values {
        validate_token(value, MAX_ACTION_MESSAGE_CHARS, "action receipt code")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LeaseKind, LeaseState};

    fn provider() -> ActionProviderIdentity {
        ActionProviderIdentity {
            owner_id: "spiffy.photo_editor".to_string(),
            provider_version: "1.0.0".to_string(),
            executable_digest_blake3: None,
        }
    }

    fn manifest() -> ActionProviderManifest {
        ActionProviderManifest {
            schema_version: ACTION_MANIFEST_SCHEMA_VERSION,
            action_id: "photo.open_selection".to_string(),
            display_name: "Open in Photo Editor".to_string(),
            provider: provider(),
            supported_item_kinds: vec![ShelfItemKind::Image],
            supported_storage_classes: vec![StorageClass::Reference],
            supported_security_profiles: vec![SecurityProfile::Standard],
            input_schema: "spiffy.action.input.v1".to_string(),
            output_schema: "spiffy.action.output.v1".to_string(),
            source_mutation_policy: SourceMutationPolicy::None,
            destructive: false,
            confirmation_policy: ConfirmationPolicy::None,
            authentication_policy: AuthenticationPolicy::WhenPrivate,
            supports_progress: true,
            supports_cancel: true,
            timeout_millis: 30_000,
            idempotence_policy: IdempotencePolicy::Required,
            resource_class: "cpu.ffmpeg".to_string(),
            receipt_schema: "spiffy.action.receipt.v1".to_string(),
            minimum_owner_version: "1.0.0".to_string(),
            required_capabilities: vec!["photo.intake.v1".to_string()],
        }
    }

    #[test]
    fn manifests_reject_unsafe_destructive_configuration() {
        assert!(manifest().validate().is_ok());
        let mut invalid = manifest();
        invalid.destructive = true;
        assert_eq!(
            invalid.validate(),
            Err("destructive actions require destructive confirmation policy")
        );
    }

    #[test]
    fn dispatch_debug_redacts_parameters_paths_and_idempotence_key() {
        let now = Utc::now();
        let packet = ActionDispatchPacket {
            protocol: ACTION_PROTOCOL_VERSION,
            action_run_id: Uuid::new_v4(),
            action_id: "photo.open_selection".to_string(),
            provider: provider(),
            selections: vec![ShelfSelectionRef {
                item: StableOwnerRef {
                    owner_id: "spiffy.shelf".to_string(),
                    entity_id: "item-1".to_string(),
                    entity_kind: "shelf_item".to_string(),
                    revision: 1,
                    digest_blake3: "ab".repeat(32),
                },
                kind: ShelfItemKind::Image,
                storage_class: StorageClass::Reference,
                security_profile: SecurityProfile::Standard,
            }],
            relation_ids: Vec::new(),
            parameters: serde_json::json!({"private": "client-name"}),
            authorization: None,
            output_lease: LocalFileLease {
                lease_id: Uuid::new_v4(),
                kind: LeaseKind::Output,
                owner_id: "spiffy.shelf".to_string(),
                opaque_path: "C:/private/output".to_string(),
                expected_bytes: None,
                expected_blake3: None,
                created_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                state: LeaseState::Offered,
            },
            idempotence_key: "private-key".to_string(),
            requested_at: now,
            deadline: now + chrono::Duration::minutes(1),
        };
        assert!(packet.validate(now).is_ok());
        let debug = format!("{packet:?}");
        assert!(!debug.contains("client-name"));
        assert!(!debug.contains("C:/private"));
        assert!(!debug.contains("private-key"));
    }

    #[test]
    fn stale_success_receipts_are_rejected() {
        let now = Utc::now();
        let reference = StableOwnerRef {
            owner_id: "spiffy.shelf".to_string(),
            entity_id: "item-1".to_string(),
            entity_kind: "shelf_item".to_string(),
            revision: 1,
            digest_blake3: "ef".repeat(32),
        };
        let receipt = ActionReceipt {
            schema_version: ACTION_RECEIPT_SCHEMA_VERSION,
            action_run_id: Uuid::new_v4(),
            action_id: "photo.open_selection".to_string(),
            provider: provider(),
            state: ActionRunState::Succeeded,
            started_at: now,
            ended_at: now,
            inputs: vec![reference],
            outputs: Vec::new(),
            source_mutation_state: SourceMutationState::Unchanged,
            source_current: false,
            superseded_by: None,
            warning_codes: Vec::new(),
            error_codes: Vec::new(),
            retryable: false,
            rollback_receipt_id: None,
            cleanup_complete: true,
            human_review_required: false,
        };
        assert_eq!(
            receipt.validate(),
            Err("a stale source cannot produce a current successful receipt")
        );
    }
}
