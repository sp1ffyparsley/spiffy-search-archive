use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ProtocolVersion;

pub const CLIPBOARD_PROVIDER_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
pub const CLIPBOARD_PROVIDER_DISCOVERY_RELATIVE_PATH: &str = "ipc/provider-endpoint-v2.json";
pub const CLIPBOARD_PROVIDER_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const CLIPBOARD_PROVIDER_MAX_QUERY_CHARS: usize = 1_024;
pub const CLIPBOARD_PROVIDER_MAX_PAGE_ITEMS: u16 = 500;
pub const CLIPBOARD_PROVIDER_MAX_MUTATION_ITEMS: usize = 500;
pub const CLIPBOARD_PROVIDER_MAX_NAME_CHARS: usize = 256;

/// Separate native-to-native capability. Never accept these commands from a
/// renderer and never expand administrative v1 with protected payloads.
pub const CLIPBOARD_SECURE_COPY_VERSION: u16 = 1;
pub const CLIPBOARD_SECURE_COPY_DPAPI_ENTROPY: &[u8] = b"Spiffy.SecureCopy.v1";
pub const CLIPBOARD_SECURE_COPY_MAX_PLAINTEXT_BYTES: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardSecureCopyLease {
    #[serde(rename = "seconds_15")]
    Seconds15,
    #[serde(rename = "seconds_30")]
    Seconds30,
    #[serde(rename = "seconds_60")]
    Seconds60,
    UntilPaste,
    UntilLock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardSecureCopyFormat {
    TextUtf8,
    FileDropUtf16,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopyContent {
    pub format: ClipboardSecureCopyFormat,
    pub protected_data_base64: String,
}
impl fmt::Debug for ClipboardSecureCopyContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClipboardSecureCopyContent([redacted])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopySubject {
    pub shelf_id: Uuid,
    pub item_id: Uuid,
    pub expected_revision: i64,
    pub lock_epoch: u64,
    pub security_generation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopyFence {
    pub shelf_id: Uuid,
    pub minimum_lock_epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardSecureCopyAcknowledgement {
    OwnerDispatch,
    HostAcknowledged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ClipboardSecureCopyCommand {
    #[serde(rename = "secure_copy_capabilities")]
    Capabilities,
    #[serde(rename = "secure_copy_publish")]
    Publish {
        operation_id: Uuid,
        consumer_window: u64,
        subjects: Vec<ClipboardSecureCopySubject>,
        lease: ClipboardSecureCopyLease,
        content: ClipboardSecureCopyContent,
    },
    #[serde(rename = "secure_copy_status")]
    Status { operation_id: Uuid },
    #[serde(rename = "secure_copy_recovery_status")]
    RecoveryStatus { operation_id: Uuid },
    #[serde(rename = "secure_copy_cancel")]
    Cancel { operation_id: Uuid },
    #[serde(rename = "secure_copy_release_receipt")]
    ReleaseReceipt { operation_id: Uuid },
    #[serde(rename = "secure_copy_revoke")]
    Revoke {
        operation_id: Uuid,
        minimum_generation: u64,
        shelf_fences: Vec<ClipboardSecureCopyFence>,
    },
    #[serde(rename = "secure_copy_acknowledge")]
    Acknowledge {
        operation_id: Uuid,
        acknowledgement: ClipboardSecureCopyAcknowledgement,
    },
}
impl ClipboardSecureCopyCommand {
    pub fn operation_id(&self) -> Option<Uuid> {
        match self {
            Self::Capabilities => None,
            Self::Publish { operation_id, .. }
            | Self::Status { operation_id }
            | Self::RecoveryStatus { operation_id }
            | Self::Cancel { operation_id }
            | Self::ReleaseReceipt { operation_id }
            | Self::Revoke { operation_id, .. }
            | Self::Acknowledge { operation_id, .. } => Some(*operation_id),
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.operation_id().is_some_and(|id| id.is_nil()) {
            return Err("secure copy operation identity is required");
        }
        match self {
            Self::Publish {
                consumer_window,
                subjects,
                content,
                ..
            } => {
                let mut ids = BTreeSet::new();
                if *consumer_window == 0
                    || *consumer_window > i64::MAX as u64
                    || subjects.is_empty()
                    || subjects.len() > 100
                    || subjects.iter().any(|subject| {
                        subject.shelf_id.is_nil()
                            || subject.item_id.is_nil()
                            || subject.expected_revision < 1
                            || subject.lock_epoch == 0
                            || !ids.insert(subject.item_id)
                            || subject.lock_epoch > i64::MAX as u64
                            || subject.security_generation > i64::MAX as u64
                            || subject.security_generation != subjects[0].security_generation
                            || subjects.iter().any(|other| {
                                other.shelf_id == subject.shelf_id
                                    && other.lock_epoch != subject.lock_epoch
                            })
                    })
                    || content.protected_data_base64.is_empty()
                    || content.protected_data_base64.len() > 710_000
                    || !content
                        .protected_data_base64
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c))
                {
                    return Err("secure copy publication exceeds its native bounds");
                }
            }
            Self::Revoke {
                minimum_generation,
                shelf_fences,
                ..
            } => {
                let mut ids = BTreeSet::new();
                if *minimum_generation > i64::MAX as u64
                    || shelf_fences.len() > 256
                    || shelf_fences.iter().any(|f| {
                        f.shelf_id.is_nil()
                            || f.minimum_lock_epoch == 0
                            || f.minimum_lock_epoch > i64::MAX as u64
                            || !ids.insert(f.shelf_id)
                    })
                {
                    return Err("secure copy revocation fence is invalid");
                }
            }
            Self::Capabilities
            | Self::Status { .. }
            | Self::RecoveryStatus { .. }
            | Self::Cancel { .. }
            | Self::ReleaseReceipt { .. }
            | Self::Acknowledge { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopyCapabilities {
    pub formats: Vec<ClipboardSecureCopyFormat>,
    pub leases: Vec<ClipboardSecureCopyLease>,
    pub max_plaintext_bytes: u32,
    pub until_paste_fallback_seconds: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardSecureCopyState {
    ReceiptReleased,
    Published,
    Revoked,
    Expired,
    Replaced,
    Acknowledged,
    OwnerExited,
    Fenced,
    Blocked,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopyReceipt {
    pub operation_id: Uuid,
    pub state: ClipboardSecureCopyState,
    pub clipboard_sequence: u32,
    pub expires_at: Option<DateTime<Utc>>,
    pub minimum_generation: u64,
    pub revocation_complete: bool,
}
/// Fresh native-owner attestation for a restarting producer. Counts include
/// live or unqueryable prior producer identities; absence of a local attempt is
/// never evidence that the other owner released a protected publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopyRecovery {
    pub operation_id: Uuid,
    pub producer_pid: u32,
    pub producer_birth: u64,
    pub settled: bool,
    pub pending_producers: u32,
    pub pending_publications: u32,
    pub journal_ready: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSecureCopyResponse {
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub secure_copy_version: u16,
    pub ok: bool,
    pub error_code: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub capabilities: Option<ClipboardSecureCopyCapabilities>,
    #[serde(default)]
    pub receipt: Option<ClipboardSecureCopyReceipt>,
    #[serde(default)]
    pub recovery: Option<ClipboardSecureCopyRecovery>,
}
impl ClipboardSecureCopyResponse {
    pub fn validate_for(
        &self,
        command: &ClipboardSecureCopyCommand,
        request_id: Uuid,
    ) -> Result<(), &'static str> {
        command.validate()?;
        if self.request_id != request_id
            || self.secure_copy_version != CLIPBOARD_SECURE_COPY_VERSION
            || !self
                .protocol
                .is_compatible_with(CLIPBOARD_PROVIDER_PROTOCOL_VERSION)
            || self.message.as_ref().is_some_and(|m| m.len() > 256)
        {
            return Err("secure copy response identity is invalid");
        }
        if !self.ok {
            if self.receipt.is_some()
                || self.recovery.is_some()
                || self.capabilities.is_some()
                || !self.error_code.as_ref().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 128
                        && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                })
            {
                return Err("secure copy error projection is invalid");
            }
            return Ok(());
        }
        if self.error_code.is_some() || self.message.is_some() {
            return Err("secure copy success contains an error");
        }
        if matches!(command, ClipboardSecureCopyCommand::Capabilities) {
            let c = self
                .capabilities
                .as_ref()
                .ok_or("secure copy capabilities are absent")?;
            if self.receipt.is_some()
                || self.recovery.is_some()
                || c.formats.is_empty()
                || c.formats.len() > 2
                || c.leases.is_empty()
                || c.leases.len() > 5
                || c.max_plaintext_bytes == 0
                || c.max_plaintext_bytes as usize > CLIPBOARD_SECURE_COPY_MAX_PLAINTEXT_BYTES
                || c.until_paste_fallback_seconds != 60
                || c.formats
                    .iter()
                    .enumerate()
                    .any(|(i, v)| c.formats[..i].contains(v))
                || c.leases
                    .iter()
                    .enumerate()
                    .any(|(i, v)| c.leases[..i].contains(v))
            {
                return Err("secure copy capabilities are invalid");
            }
        } else if matches!(command, ClipboardSecureCopyCommand::RecoveryStatus { .. }) {
            let recovery = self
                .recovery
                .as_ref()
                .ok_or("secure copy recovery proof is absent")?;
            if self.receipt.is_some()
                || self.capabilities.is_some()
                || Some(recovery.operation_id) != command.operation_id()
                || recovery.producer_pid == 0
                || recovery.producer_birth == 0
                || recovery.producer_birth > i64::MAX as u64
                || recovery.pending_producers > 2304
                || recovery.pending_publications > 2048
                || recovery.settled
                    != (recovery.journal_ready
                        && recovery.pending_producers == 0
                        && recovery.pending_publications == 0)
            {
                return Err("secure copy recovery proof is invalid");
            }
        } else {
            let r = self
                .receipt
                .as_ref()
                .ok_or("secure copy receipt is absent")?;
            if self.capabilities.is_some()
                || self.recovery.is_some()
                || Some(r.operation_id) != command.operation_id()
                || r.minimum_generation > i64::MAX as u64
                || (r.state == ClipboardSecureCopyState::Published
                    && (r.clipboard_sequence == 0 || r.revocation_complete))
                || (matches!(
                    r.state,
                    ClipboardSecureCopyState::Unknown
                        | ClipboardSecureCopyState::Blocked
                        | ClipboardSecureCopyState::ReceiptReleased
                ) && r.revocation_complete)
            {
                return Err("secure copy receipt is invalid");
            }
            let terminal = matches!(
                r.state,
                ClipboardSecureCopyState::Revoked
                    | ClipboardSecureCopyState::Expired
                    | ClipboardSecureCopyState::Replaced
                    | ClipboardSecureCopyState::Acknowledged
                    | ClipboardSecureCopyState::OwnerExited
                    | ClipboardSecureCopyState::Fenced
            );
            if terminal != r.revocation_complete
                || (matches!(command, ClipboardSecureCopyCommand::ReleaseReceipt { .. })
                    && r.state != ClipboardSecureCopyState::ReceiptReleased)
            {
                return Err("secure copy terminal receipt is inconsistent");
            }
        }
        Ok(())
    }
}

/// A separately negotiated, ephemeral UI surface. Legacy administrative v1
/// projections remain unchanged and must never receive these excerpts.
pub const CLIPBOARD_PRESENTATION_VERSION: u16 = 2;
pub const CLIPBOARD_PRESENTATION_MAX_ITEMS: u16 = 100;

fn settings_hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardCaptureRule {
    pub id: Uuid,
    pub enabled: bool,
    pub priority: u16,
    pub executable_path: String,
    pub content_types: u16,
    pub action: String,
}
impl fmt::Debug for ClipboardCaptureRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClipboardCaptureRule([configuration])")
    }
}
impl ClipboardCaptureRule {
    pub fn validate(&self) -> Result<(), &'static str> {
        let path = &self.executable_path;
        let bytes = path.as_bytes();
        let drive = bytes.len() > 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\';
        let unc = path.starts_with("\\\\");
        if self.id.is_nil()
            || !(1..=15).contains(&self.content_types)
            || self.action != "exclude"
            || path.len() > 4096
            || path.encode_utf16().count() > 1024
            || bytes.len() < 7
            || (!drive && !unc)
            || path.starts_with("\\\\?\\")
            || path.starts_with("\\\\.\\")
            || !path.to_ascii_lowercase().ends_with(".exe")
        {
            return Err("native capture rule is invalid");
        }
        let components: Vec<_> = path[if drive { 3 } else { 2 }..].split('\\').collect();
        if (unc && components.len() < 3)
            || components.iter().any(|part| {
                part.is_empty()
                    || *part == "."
                    || *part == ".."
                    || part.ends_with(['.', ' '])
                    || part
                        .chars()
                        .any(|c| c.is_control() || "/:\"<>|?*".contains(c))
            })
        {
            return Err("native capture rule path is invalid");
        }
        Ok(())
    }
}
fn validate_capture_rules(rules: &[ClipboardCaptureRule]) -> Result<(), &'static str> {
    if rules.len() > 32
        || serde_json::to_vec(rules)
            .map_err(|_| "native capture rules are invalid")?
            .len()
            > 64 * 1024
    {
        return Err("native capture rules exceed bounds");
    }
    let mut ids = BTreeSet::new();
    let mut priorities = BTreeSet::new();
    for rule in rules {
        rule.validate()?;
        if !ids.insert(rule.id) || !priorities.insert(rule.priority) {
            return Err("native capture rules contain duplicate identities or priorities");
        }
    }
    Ok(())
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSettingsPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_ocr_screenshots: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_max_entries: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_expired_entries: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_days: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_duplicates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_consecutive_duplicates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_paste_after_selection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_order_on_paste: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_multi_paste: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_paste_reverse: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_paste_separator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clip_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_include_apps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_exclude_apps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_to_group_timeout_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_rules: Option<Vec<ClipboardCaptureRule>>,
}
impl fmt::Debug for ClipboardSettingsPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClipboardSettingsPatch([configuration])")
    }
}
impl ClipboardSettingsPatch {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(rules) = &self.capture_rules {
            validate_capture_rules(rules)?;
        }
        for (value, min, max) in [
            (self.max_entries, 0, 1_000_000),
            (self.expire_days, 1, 36_500),
            (self.max_clip_bytes, 0, 1_073_741_824),
            (self.capture_to_group_timeout_ms, 0, 86_400_000),
        ] {
            if value.is_some_and(|v| v < min || v > max) {
                return Err("native settings number exceeds its bounds");
            }
        }
        for (value, max) in [
            (self.multi_paste_separator.as_deref(), 256),
            (self.legacy_include_apps.as_deref(), 4096),
            (self.legacy_exclude_apps.as_deref(), 4096),
        ] {
            if value.is_some_and(|v| v.len() > max || v.chars().any(char::is_control)) {
                return Err("native settings text exceeds its bounds");
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSettingsValues {
    #[serde(default)]
    pub auto_ocr_screenshots: bool,
    #[serde(default)]
    pub active_queue_id: String,
    pub check_max_entries: bool,
    pub max_entries: i64,
    pub check_expired_entries: bool,
    pub expire_days: i64,
    pub allow_duplicates: bool,
    pub allow_consecutive_duplicates: bool,
    pub send_paste_after_selection: bool,
    pub update_order_on_paste: bool,
    pub save_multi_paste: bool,
    pub multi_paste_reverse: bool,
    pub multi_paste_separator: String,
    pub max_clip_bytes: i64,
    pub legacy_include_apps: String,
    pub legacy_exclude_apps: String,
    pub capture_to_group_timeout_ms: i64,
    #[serde(default)]
    pub capture_rules: Vec<ClipboardCaptureRule>,
}
impl fmt::Debug for ClipboardSettingsValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClipboardSettingsValues([configuration])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSettingsSnapshot {
    pub schema_version: u16,
    pub owner_revision: String,
    pub values: ClipboardSettingsValues,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_fields: Option<Vec<String>>,
}
const CLIPBOARD_SETTINGS_FIELDS: &[&str] = &[
    "check_max_entries",
    "max_entries",
    "check_expired_entries",
    "expire_days",
    "allow_duplicates",
    "allow_consecutive_duplicates",
    "send_paste_after_selection",
    "update_order_on_paste",
    "save_multi_paste",
    "multi_paste_reverse",
    "multi_paste_separator",
    "max_clip_bytes",
    "legacy_include_apps",
    "legacy_exclude_apps",
    "capture_to_group_timeout_ms",
    "capture_rules",
    "active_queue_id",
    "auto_ocr_screenshots",
];
impl ClipboardSettingsSnapshot {
    /// Older owners expose the original fifteen preferences. Default-empty
    /// values never establish support for a newer optional capability.
    pub fn supports_field(&self, field: &str) -> bool {
        CLIPBOARD_SETTINGS_FIELDS.contains(&field)
            && self.supported_fields.as_ref().map_or(
                !matches!(
                    field,
                    "capture_rules" | "active_queue_id" | "auto_ocr_screenshots"
                ),
                |fields| fields.iter().any(|value| value == field),
            )
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_capture_rules(&self.values.capture_rules)?;
        if self.schema_version != 1
            || (!self.values.active_queue_id.is_empty()
                && Uuid::parse_str(&self.values.active_queue_id).is_err())
            || !settings_hash_valid(&self.owner_revision)
            || self.values.multi_paste_separator.len() > 128 * 1024
            || self.values.legacy_include_apps.len() > 128 * 1024
            || self.values.legacy_exclude_apps.len() > 128 * 1024
        {
            return Err("native settings snapshot exceeds its bounds");
        }
        if let Some(fields) = &self.supported_fields {
            let mut seen = BTreeSet::new();
            if fields.len() > CLIPBOARD_SETTINGS_FIELDS.len()
                || fields.iter().any(|field| {
                    !CLIPBOARD_SETTINGS_FIELDS.contains(&field.as_str()) || !seen.insert(field)
                })
            {
                return Err("native settings capabilities are invalid");
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSettingsValidationError {
    pub setting_id: String,
    pub code: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSettingsValidation {
    pub valid: bool,
    pub digest: String,
    pub current_revision: String,
    pub normalized_patch: ClipboardSettingsPatch,
    pub errors: Vec<ClipboardSettingsValidationError>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSettingsReceipt {
    pub operation_id: Uuid,
    pub digest: String,
    pub state: String,
    pub base_revision: String,
    pub applied_revision: Option<String>,
    pub current_revision: String,
    pub config_committed: bool,
    pub runtime_acknowledged: bool,
    pub error_code: Option<String>,
}
impl ClipboardSettingsReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.operation_id.is_nil()
            || !settings_hash_valid(&self.digest)
            || !settings_hash_valid(&self.base_revision)
            || !settings_hash_valid(&self.current_revision)
            || self
                .applied_revision
                .as_deref()
                .is_some_and(|v| !settings_hash_valid(v))
            || !matches!(
                self.state.as_str(),
                "prepared"
                    | "pending_runtime"
                    | "committed"
                    | "compensating"
                    | "compensated"
                    | "conflict"
            )
            || self.config_committed
                != matches!(self.state.as_str(), "pending_runtime" | "committed")
            || self.runtime_acknowledged
                != matches!(self.state.as_str(), "committed" | "compensated")
            || (self.config_committed && self.applied_revision.is_none())
            || self.error_code.as_ref().is_some_and(|v| {
                v.len() > 64 || !v.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
            })
        {
            return Err("native settings receipt is invalid");
        }
        Ok(())
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationSmartPackFilter {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    pub kinds: Vec<String>,
    pub source_app: Option<String>,
    pub after_utc: Option<i64>,
    pub before_utc: Option<i64>,
}

impl ClipboardPresentationSmartPackFilter {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.query.len() > 2048
            || self.mode.as_ref().is_some_and(|mode| {
                !matches!(
                    mode.as_str(),
                    "all_words" | "source_phrase" | "literal" | "prefix"
                )
            })
            || self.kinds.len() > 8
            || self.source_app.as_ref().is_some_and(|s| s.len() > 256)
            || self.after_utc.is_some_and(|v| v < 0)
            || self.before_utc.is_some_and(|v| v < 0)
            || matches!((self.after_utc,self.before_utc),(Some(a),Some(b)) if a>b)
            || self.kinds.iter().any(|kind| {
                !matches!(
                    kind.as_str(),
                    "text" | "image" | "file" | "files" | "url" | "audio" | "video" | "other"
                )
            })
        {
            return Err("smart pack filter exceeds its bounds");
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClipboardPresentationCommand {
    PresentationSetColor {
        view_id: Uuid,
        operation_id: Uuid,
        clips: Vec<ClipboardDeleteClip>,
        color_token: String,
    },
    PresentationClipMetadata {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
    },
    PresentationEditClipMetadata {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        recall_name: String,
        note: String,
        operation_id: Uuid,
    },
    PresentationSourceReferences {
        view_id: Uuid,
        pack_id: Uuid,
        expected_revision: u64,
        offset: u32,
        limit: u32,
    },
    PresentationSaveSourceReference {
        view_id: Uuid,
        pack_id: Uuid,
        expected_pack_revision: u64,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        field_id: String,
        representation_revision: String,
        start: u64,
        end: u64,
        label: String,
        operation_id: Uuid,
    },
    PresentationRemoveSourceReference {
        view_id: Uuid,
        pack_id: Uuid,
        expected_pack_revision: u64,
        reference_id: Uuid,
        operation_id: Uuid,
    },
    PresentationResolveSourceReference {
        view_id: Uuid,
        pack_id: Uuid,
        expected_pack_revision: u64,
        reference_id: Uuid,
    },
    PresentationReuseSettings {
        view_id: Uuid,
    },
    PresentationReuseSetEnabled {
        view_id: Uuid,
        expected_policy_epoch: u64,
        operation_id: Uuid,
        enabled: bool,
    },
    PresentationReuseClearStatistics {
        view_id: Uuid,
        expected_policy_epoch: u64,
        operation_id: Uuid,
    },
    PresentationReuseResetDismissals {
        view_id: Uuid,
        expected_policy_epoch: u64,
        operation_id: Uuid,
    },
    PresentationReuseClaim {
        view_id: Uuid,
        operation_id: Uuid,
        active_search: bool,
        active_paste: bool,
        reader_selection: bool,
    },
    PresentationReuseRespond {
        view_id: Uuid,
        operation_id: Uuid,
        offer_id: String,
        expected_policy_epoch: u64,
        response: String,
        pack_name: String,
    },
    PresentationOcrCorrect {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        field_id: String,
        representation_revision: String,
        start: u64,
        end: u64,
        text: String,
        operation_id: Uuid,
    },
    PresentationOcrSaveText {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        field_id: String,
        representation_revision: String,
        operation_id: Uuid,
    },
    PresentationOrganize {
        view_id: Uuid,
        collection: String,
        collection_id: Option<Uuid>,
        expected_revision: u64,
        action: String,
        name: String,
        items: Vec<Uuid>,
        operation_id: Uuid,
    },
    PresentationDeleteClips {
        view_id: Uuid,
        operation_id: Uuid,
        clips: Vec<ClipboardDeleteClip>,
    },
    PresentationSemantic {
        view_id: Uuid,
        action: String,
        operation_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clip_ids: Option<Vec<Uuid>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    PresentationQueueSelection {
        view_id: Uuid,
    },
    PresentationSelectQueue {
        view_id: Uuid,
        queue_id: Uuid,
        queue_revision: u64,
        expected_revision: String,
        operation_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ctrl_v_enabled: Option<bool>,
    },
    PresentationOcrStatus {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
    },
    PresentationPreviewOcrAppend {
        view_id: Uuid,
        grant_id: Uuid,
        offset: u64,
        total_bytes: u64,
        document_sha256: String,
        text: String,
        eof: bool,
    },
    PresentationKeepOpen {
        view_id: Uuid,
        enabled: bool,
    },
    PresentationDocumentFind {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        representation_revision: Option<String>,
        query: String,
        after_utf8: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before_utf8: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field_id: Option<String>,
        #[serde(default = "document_find_literal")]
        mode: String,
    },
    PresentationDocumentCopy {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        representation_revision: String,
        start: u64,
        end: u64,
        operation_id: Uuid,
        #[serde(default)]
        full_entry: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field_id: Option<String>,
    },
    PresentationDocumentRead {
        view_id: Uuid,
        clip_id: Uuid,
        occurrence_id: Uuid,
        expected_revision: u64,
        offset: u64,
        max_bytes: u32,
        representation_revision: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field_id: Option<String>,
    },
    PresentationPreviewCapabilities,
    PresentationPreviewOpen {
        view_id: Uuid,
        operation_id: Uuid,
        consumer_window: u64,
        item: ClipboardPreviewItem,
    },
    PresentationPreviewRead {
        view_id: Uuid,
        grant_id: Uuid,
        offset: u64,
        max_bytes: u32,
    },
    PresentationPreviewValidate {
        view_id: Uuid,
        grant_id: Uuid,
    },
    PresentationPreviewClose {
        operation_id: Uuid,
    },
    PresentationDragCapabilities,
    PresentationDragProvenanceCapabilities,
    PresentationDragStart {
        view_id: Uuid,
        operation_id: Uuid,
        generated_offer_version: u16,
        consumer_window: u64,
        items: Vec<ClipboardDragItem>,
    },
    PresentationDragStatus {
        operation_id: Uuid,
    },
    PresentationDragCancel {
        operation_id: Uuid,
    },
    /// Native receiver only: renderer-supplied paths never enter this route.
    PresentationDragVerifyOffer {
        operation_id: Uuid,
        lease_id: Uuid,
        target_window: u64,
        paths: Vec<String>,
    },
    SettingsRead,
    SettingsValidate {
        expected_revision: String,
        patch: ClipboardSettingsPatch,
    },
    SettingsPrepare {
        operation_id: Uuid,
        expected_revision: String,
        patch: ClipboardSettingsPatch,
        digest: String,
    },
    SettingsCommit {
        operation_id: Uuid,
        digest: String,
    },
    SettingsStatus {
        operation_id: Uuid,
        digest: String,
    },
    SettingsCompensate {
        operation_id: Uuid,
        digest: String,
    },
    PresentationHotkeyState,
    PresentationFavorites {
        view_id: Uuid,
    },
    PresentationSwapFavorites {
        view_id: Uuid,
        operation_id: Uuid,
        first_slot: u8,
        first_expected_revision: u64,
        second_slot: u8,
        second_expected_revision: u64,
    },
    PresentationCustomizeFavorite {
        view_id: Uuid,
        operation_id: Uuid,
        slot: u8,
        expected_revision: u64,
        title_override: Option<String>,
        icon_token: Option<String>,
        color_token: Option<String>,
    },
    PresentationArchiveStart {
        view_id: Uuid,
        operation_id: Uuid,
        action: String,
        clips: Vec<ClipboardPresentationClipRevision>,
    },
    PresentationArchiveStatus {
        operation_id: Uuid,
    },
    PresentationArchiveCancel {
        operation_id: Uuid,
    },
    PresentationArchiveCommit {
        view_id: Uuid,
        operation_id: Uuid,
    },
    PresentationCapturedFiles {
        view_id: Uuid,
        clip_id: Uuid,
        expected_revision: u64,
        offset: u32,
        limit: u16,
    },
    PresentationCreateFileSubset {
        view_id: Uuid,
        clip_id: Uuid,
        expected_revision: u64,
        ordinals: Vec<u32>,
    },
    PresentationDrafts {
        view_id: Uuid,
    },
    PresentationReadDraft {
        view_id: Uuid,
        draft_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_revision: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<u32>,
    },
    PresentationEditDraft {
        view_id: Uuid,
        draft_id: Uuid,
        expected_revision: u64,
        operation_id: Uuid,
        offset: u32,
        total_bytes: u32,
        representation_revision: String,
        text: String,
    },
    PresentationPublishDraft {
        view_id: Uuid,
        draft_id: Uuid,
        expected_revision: u64,
        operation_id: Uuid,
        paste: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        end: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        representation_revision: Option<String>,
    },
    PresentationStartDraft {
        view_id: Uuid,
        name: String,
        separator: String,
        clips: Vec<ClipboardPresentationClipRevision>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capture: Option<bool>,
    },
    PresentationAppendDraft {
        view_id: Uuid,
        draft_id: Uuid,
        expected_revision: u64,
        clips: Vec<ClipboardPresentationClipRevision>,
    },
    PresentationUndoDraft {
        view_id: Uuid,
        draft_id: Uuid,
        expected_revision: u64,
    },
    PresentationStopDraft {
        view_id: Uuid,
        draft_id: Uuid,
        expected_revision: u64,
    },
    PresentationFinishDraft {
        view_id: Uuid,
        draft_id: Uuid,
        expected_revision: u64,
    },
    PresentationCaptureSessions {
        view_id: Uuid,
    },
    PresentationStartCaptureSession {
        view_id: Uuid,
        pack_id: Option<Uuid>,
        pack_revision: Option<u64>,
        inactivity_timeout_seconds: Option<u32>,
        persist_across_restart: bool,
    },
    PresentationStopCaptureSession {
        view_id: Uuid,
        session_id: Uuid,
        expected_revision: u64,
    },
    PresentationMaterializeSession {
        view_id: Uuid,
        session_id: Uuid,
        expected_revision: u64,
        name: String,
        target: String,
        mode: String,
    },
    PresentationQueueCurrent {
        view_id: Uuid,
        queue_id: Uuid,
    },
    PresentationListSmartPacks {
        view_id: Uuid,
    },
    PresentationSaveSmartPack {
        view_id: Uuid,
        pack_id: Option<Uuid>,
        expected_revision: Option<u64>,
        name: String,
        filter: ClipboardPresentationSmartPackFilter,
    },
    PresentationDeleteSmartPack {
        view_id: Uuid,
        pack_id: Uuid,
        expected_revision: u64,
    },
    PresentationBegin {
        window_label: String,
        target_window: u64,
    },
    PresentationQuery {
        #[serde(default, skip_serializing_if = "is_false")]
        include_color_labels: bool,
        view_id: Uuid,
        generation: u64,
        query: String,
        #[serde(default = "document_query_all_words")]
        mode: String,
        kinds: Vec<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        pinned_only: bool,
        #[serde(default)]
        clip_ids: Vec<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        legacy_group_id: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner_scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pack_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        smart_pack_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capture_session_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "is_false")]
        related_tags: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        related_group_id: Option<String>,
        source_app: Option<String>,
        after_utc: Option<i64>,
        before_utc: Option<i64>,
        limit: u16,
        before_sequence: Option<u64>,
        around_occurrence: Option<Uuid>,
    },
    PresentationRevoke {
        view_id: Uuid,
    },
    PresentationRenew {
        view_id: Uuid,
    },
    PresentationPublish {
        view_id: Uuid,
        clip_id: Uuid,
        expected_revision: u64,
        plain_text: bool,
        paste: bool,
        operation_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_revision: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_item_id: Option<Uuid>,
    },
}

fn document_query_all_words() -> String {
    "all_words".into()
}
fn document_find_literal() -> String {
    "literal".into()
}

impl ClipboardPresentationCommand {
    /// Body-bearing preview transport is native-consumer-only. The renderer
    /// receives a separately authorized, bounded final image projection.
    pub fn is_preview_command(&self) -> bool {
        matches!(
            self,
            Self::PresentationPreviewCapabilities
                | Self::PresentationPreviewOpen { .. }
                | Self::PresentationPreviewRead { .. }
                | Self::PresentationPreviewValidate { .. }
                | Self::PresentationPreviewClose { .. }
        )
    }
    pub fn is_drag_command(&self) -> bool {
        matches!(
            self,
            Self::PresentationDragCapabilities
                | Self::PresentationDragProvenanceCapabilities
                | Self::PresentationDragStart { .. }
                | Self::PresentationDragStatus { .. }
                | Self::PresentationDragCancel { .. }
                | Self::PresentationDragVerifyOffer { .. }
        )
    }
    /// Settings metadata is authorized by the exact focused Settings window,
    /// independently of content-bearing presentation leases.
    pub fn is_settings_command(&self) -> bool {
        matches!(
            self,
            Self::SettingsRead
                | Self::SettingsValidate { .. }
                | Self::SettingsPrepare { .. }
                | Self::SettingsCommit { .. }
                | Self::SettingsStatus { .. }
                | Self::SettingsCompensate { .. }
        )
    }
    /// Only these peer-bound commands may run after the content view loses focus.
    /// Their response projections must contain no paths, bodies or clip titles.
    pub fn presentation_allows_unfocused(&self) -> bool {
        matches!(
            self,
            Self::PresentationHotkeyState
                | Self::PresentationPreviewCapabilities
                | Self::PresentationPreviewClose { .. }
                | Self::PresentationDragCapabilities
                | Self::PresentationDragProvenanceCapabilities
                | Self::PresentationDragStatus { .. }
                | Self::PresentationDragCancel { .. }
                | Self::PresentationDragVerifyOffer { .. }
                | Self::PresentationArchiveStatus { .. }
                | Self::PresentationArchiveCancel { .. }
        )
    }
    /// Whether the command requests a durable owner mutation or system publication.
    /// Ephemeral view leases and read-triggered expiry maintenance are excluded.
    pub fn presentation_may_mutate(&self) -> bool {
        match self {
            Self::PresentationSemantic { action, .. } => {
                !matches!(action.as_str(), "status" | "doctor")
            }
            Self::PresentationClipMetadata { .. }
            | Self::PresentationSourceReferences { .. }
            | Self::PresentationResolveSourceReference { .. } => false,
            Self::PresentationSetColor { .. }
            | Self::PresentationEditClipMetadata { .. }
            | Self::PresentationSaveSourceReference { .. }
            | Self::PresentationRemoveSourceReference { .. } => true,
            Self::PresentationReuseSettings { .. } => false,
            Self::PresentationReuseSetEnabled { .. }
            | Self::PresentationReuseClearStatistics { .. }
            | Self::PresentationReuseResetDismissals { .. }
            | Self::PresentationReuseClaim { .. }
            | Self::PresentationReuseRespond { .. } => true,
            Self::PresentationOcrCorrect { .. } | Self::PresentationOcrSaveText { .. } => true,
            Self::PresentationOrganize { .. } | Self::PresentationDeleteClips { .. } => true,
            Self::PresentationQueueSelection { .. } => false,
            Self::PresentationSelectQueue { .. } => true,
            Self::PresentationOcrStatus { .. }
            | Self::PresentationDocumentRead { .. }
            | Self::PresentationDocumentFind { .. } => false,
            Self::PresentationPreviewOcrAppend { .. } => true,
            Self::PresentationDocumentCopy { .. } | Self::PresentationKeepOpen { .. } => true,
            Self::PresentationPreviewCapabilities
            | Self::PresentationPreviewOpen { .. }
            | Self::PresentationPreviewRead { .. }
            | Self::PresentationPreviewValidate { .. }
            | Self::PresentationPreviewClose { .. } => false,
            Self::PresentationDragStart { .. } => true,
            Self::SettingsRead | Self::SettingsValidate { .. } => false,
            Self::SettingsPrepare { .. }
            | Self::SettingsCommit { .. }
            | Self::SettingsCompensate { .. }
            | Self::SettingsStatus { .. } => true,
            Self::PresentationFavorites { .. } => false,
            Self::PresentationSwapFavorites { .. } | Self::PresentationCustomizeFavorite { .. } => {
                true
            }
            Self::PresentationArchiveStart { .. } | Self::PresentationArchiveCommit { .. } => true,
            Self::PresentationArchiveStatus { .. } | Self::PresentationArchiveCancel { .. } => {
                false
            }
            Self::PresentationCapturedFiles { .. } => false,
            Self::PresentationCreateFileSubset { .. } => true,
            Self::PresentationPublish { .. }
            | Self::PresentationSaveSmartPack { .. }
            | Self::PresentationDeleteSmartPack { .. }
            | Self::PresentationStartCaptureSession { .. }
            | Self::PresentationStopCaptureSession { .. }
            | Self::PresentationMaterializeSession { .. } => true,
            Self::PresentationStartDraft { .. }
            | Self::PresentationAppendDraft { .. }
            | Self::PresentationUndoDraft { .. }
            | Self::PresentationStopDraft { .. }
            | Self::PresentationFinishDraft { .. } => true,
            Self::PresentationEditDraft { .. } => true,
            Self::PresentationPublishDraft { .. } => true,
            Self::PresentationHotkeyState
            | Self::PresentationDragCapabilities
            | Self::PresentationDragProvenanceCapabilities
            | Self::PresentationDragStatus { .. }
            | Self::PresentationDragCancel { .. }
            | Self::PresentationDragVerifyOffer { .. }
            | Self::PresentationCaptureSessions { .. }
            | Self::PresentationQueueCurrent { .. }
            | Self::PresentationListSmartPacks { .. }
            | Self::PresentationBegin { .. }
            | Self::PresentationQuery { .. }
            | Self::PresentationRevoke { .. }
            | Self::PresentationRenew { .. } => false,
            Self::PresentationDrafts { .. } | Self::PresentationReadDraft { .. } => false,
        }
    }
    pub fn presentation_view_id(&self) -> Option<Uuid> {
        match self {
            Self::PresentationSemantic { view_id, .. } => Some(*view_id),
            Self::PresentationSetColor { view_id, .. }
            | Self::PresentationClipMetadata { view_id, .. }
            | Self::PresentationEditClipMetadata { view_id, .. }
            | Self::PresentationSourceReferences { view_id, .. }
            | Self::PresentationSaveSourceReference { view_id, .. }
            | Self::PresentationRemoveSourceReference { view_id, .. }
            | Self::PresentationResolveSourceReference { view_id, .. } => Some(*view_id),
            Self::PresentationReuseSettings { view_id }
            | Self::PresentationReuseSetEnabled { view_id, .. }
            | Self::PresentationReuseClearStatistics { view_id, .. }
            | Self::PresentationReuseResetDismissals { view_id, .. }
            | Self::PresentationReuseClaim { view_id, .. }
            | Self::PresentationReuseRespond { view_id, .. } => Some(*view_id),
            Self::PresentationOcrCorrect { view_id, .. }
            | Self::PresentationOcrSaveText { view_id, .. } => Some(*view_id),
            Self::PresentationOrganize { view_id, .. }
            | Self::PresentationDeleteClips { view_id, .. } => Some(*view_id),
            Self::PresentationQueueSelection { view_id }
            | Self::PresentationSelectQueue { view_id, .. } => Some(*view_id),
            Self::PresentationOcrStatus { view_id, .. }
            | Self::PresentationPreviewOcrAppend { view_id, .. }
            | Self::PresentationKeepOpen { view_id, .. }
            | Self::PresentationDocumentFind { view_id, .. }
            | Self::PresentationDocumentRead { view_id, .. }
            | Self::PresentationDocumentCopy { view_id, .. } => Some(*view_id),
            Self::PresentationPreviewCapabilities | Self::PresentationPreviewClose { .. } => None,
            Self::PresentationPreviewOpen { view_id, .. }
            | Self::PresentationPreviewRead { view_id, .. }
            | Self::PresentationPreviewValidate { view_id, .. } => Some(*view_id),
            Self::SettingsRead
            | Self::SettingsValidate { .. }
            | Self::SettingsPrepare { .. }
            | Self::SettingsCommit { .. }
            | Self::SettingsStatus { .. }
            | Self::SettingsCompensate { .. } => None,
            Self::PresentationHotkeyState
            | Self::PresentationDragCapabilities
            | Self::PresentationDragProvenanceCapabilities
            | Self::PresentationDragStatus { .. }
            | Self::PresentationDragCancel { .. }
            | Self::PresentationDragVerifyOffer { .. }
            | Self::PresentationBegin { .. }
            | Self::PresentationArchiveStatus { .. }
            | Self::PresentationArchiveCancel { .. } => None,
            Self::PresentationQueueCurrent { view_id, .. }
            | Self::PresentationDragStart { view_id, .. }
            | Self::PresentationFavorites { view_id }
            | Self::PresentationSwapFavorites { view_id, .. }
            | Self::PresentationCustomizeFavorite { view_id, .. }
            | Self::PresentationArchiveStart { view_id, .. }
            | Self::PresentationArchiveCommit { view_id, .. }
            | Self::PresentationCapturedFiles { view_id, .. }
            | Self::PresentationCreateFileSubset { view_id, .. }
            | Self::PresentationDrafts { view_id }
            | Self::PresentationReadDraft { view_id, .. }
            | Self::PresentationEditDraft { view_id, .. }
            | Self::PresentationPublishDraft { view_id, .. }
            | Self::PresentationStartDraft { view_id, .. }
            | Self::PresentationAppendDraft { view_id, .. }
            | Self::PresentationUndoDraft { view_id, .. }
            | Self::PresentationStopDraft { view_id, .. }
            | Self::PresentationFinishDraft { view_id, .. }
            | Self::PresentationCaptureSessions { view_id }
            | Self::PresentationStartCaptureSession { view_id, .. }
            | Self::PresentationStopCaptureSession { view_id, .. }
            | Self::PresentationMaterializeSession { view_id, .. }
            | Self::PresentationListSmartPacks { view_id }
            | Self::PresentationSaveSmartPack { view_id, .. }
            | Self::PresentationDeleteSmartPack { view_id, .. }
            | Self::PresentationQuery { view_id, .. }
            | Self::PresentationRenew { view_id }
            | Self::PresentationRevoke { view_id }
            | Self::PresentationPublish { view_id, .. } => Some(*view_id),
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.presentation_view_id().is_some_and(|id| id.is_nil()) {
            return Err("presentation view is invalid");
        }
        match self {
            Self::PresentationSemantic {
                action,
                operation_id,
                generation_id,
                clip_ids,
                query,
                ..
            } => {
                if operation_id.is_nil()
                    || !matches!(
                        action.as_str(),
                        "status" | "doctor" | "prepare" | "query" | "cancel" | "clear"
                    )
                    || matches!(action.as_str(), "query" | "cancel" | "clear")
                        != generation_id.is_some()
                    || generation_id.is_some_and(|id| id.is_nil())
                    || (action == "prepare") != clip_ids.is_some()
                    || (action == "query") != query.is_some()
                {
                    return Err("semantic action requires an exact generation and explicit scope");
                }
                if let Some(ids) = clip_ids {
                    let mut unique = std::collections::HashSet::new();
                    if ids.is_empty()
                        || ids.len() > 1000
                        || ids.iter().any(|id| id.is_nil() || !unique.insert(*id))
                    {
                        return Err("semantic scope must contain unique bounded source references");
                    }
                }
                if query.as_ref().is_some_and(|value| {
                    value.trim().is_empty() || value.len() > 4096 || value.contains('\0')
                }) {
                    return Err("semantic query is empty or exceeds its bound");
                }
            }
            Self::PresentationReuseSettings { .. } => {}
            Self::PresentationReuseClaim { operation_id, .. } => {
                if operation_id.is_nil() {
                    return Err("reuse operation identity is invalid");
                }
            }
            Self::PresentationSetColor { color_token, .. }
                if !clipboard_color_token_valid(color_token) =>
            {
                return Err("clipboard color token is invalid");
            }
            Self::PresentationSetColor {
                operation_id,
                clips,
                ..
            }
            | Self::PresentationDeleteClips {
                operation_id,
                clips,
                ..
            } => {
                let mut ids = std::collections::HashSet::new();
                if operation_id.is_nil()
                    || clips.is_empty()
                    || clips.len() > 100
                    || clips.iter().any(|clip| {
                        clip.clip_id.is_nil()
                            || clip.occurrence_id.is_nil()
                            || clip.expected_revision == 0
                            || clip.expected_revision > 9007199254740991
                            || !ids.insert(clip.clip_id)
                    })
                {
                    return Err("history deletion requires exact bounded source identities");
                }
            }
            Self::PresentationReuseSetEnabled {
                expected_policy_epoch,
                operation_id,
                ..
            }
            | Self::PresentationReuseClearStatistics {
                expected_policy_epoch,
                operation_id,
                ..
            }
            | Self::PresentationReuseResetDismissals {
                expected_policy_epoch,
                operation_id,
                ..
            }
            | Self::PresentationReuseRespond {
                expected_policy_epoch,
                operation_id,
                ..
            } => {
                if operation_id.is_nil()
                    || *expected_policy_epoch == 0
                    || *expected_policy_epoch > 9007199254740991
                {
                    return Err("reuse policy identity is invalid");
                }
                if let Self::PresentationReuseRespond {
                    offer_id,
                    response,
                    pack_name,
                    ..
                } = self
                {
                    if offer_id.len() != 32
                        || !offer_id.bytes().all(|c| c.is_ascii_hexdigit())
                        || !matches!(response.as_str(), "accept" | "not_now" | "never")
                        || pack_name.len() > 320
                        || pack_name.chars().count() > 80
                        || pack_name.chars().any(char::is_control)
                    {
                        return Err("reuse response is invalid");
                    }
                }
            }
            Self::PresentationOcrCorrect {
                clip_id,
                occurrence_id,
                expected_revision,
                field_id,
                representation_revision,
                operation_id,
                ..
            }
            | Self::PresentationOcrSaveText {
                clip_id,
                occurrence_id,
                expected_revision,
                field_id,
                representation_revision,
                operation_id,
                ..
            } => {
                if clip_id.is_nil()
                    || occurrence_id.is_nil()
                    || operation_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                    || !field_id.starts_with("ocr:")
                    || field_id.len() > 96
                    || representation_revision.len() != 71
                    || !representation_revision.starts_with("sha256:")
                    || !settings_hash_valid(&representation_revision[7..])
                {
                    return Err("OCR edit source identity is invalid");
                }
                if let Self::PresentationOcrCorrect {
                    start, end, text, ..
                } = self
                {
                    if start > end || *end > 16777216 || text.len() > 65536 || text.contains('\0') {
                        return Err("OCR correction exceeds its source bounds");
                    }
                }
            }
            Self::PresentationClipMetadata {
                clip_id,
                occurrence_id,
                expected_revision,
                ..
            }
            | Self::PresentationEditClipMetadata {
                clip_id,
                occurrence_id,
                expected_revision,
                ..
            } => {
                if clip_id.is_nil()
                    || occurrence_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                {
                    return Err("clipboard metadata source is invalid");
                }
                if let Self::PresentationEditClipMetadata {
                    recall_name,
                    note,
                    operation_id,
                    ..
                } = self
                {
                    if operation_id.is_nil()
                        || recall_name.len() > 320
                        || recall_name.chars().count() > 80
                        || recall_name.chars().any(char::is_control)
                        || note.len() > 8192
                        || note.contains('\0')
                    {
                        return Err("clipboard metadata exceeds its bounds");
                    }
                }
            }
            Self::PresentationSourceReferences {
                pack_id,
                expected_revision,
                offset,
                limit,
                ..
            } => {
                if pack_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                    || *offset > 100000
                    || !(1..=100).contains(limit)
                {
                    return Err("source reference page is invalid");
                }
            }
            Self::PresentationSaveSourceReference {
                pack_id,
                expected_pack_revision,
                clip_id,
                occurrence_id,
                expected_revision,
                field_id,
                representation_revision,
                start,
                end,
                label,
                operation_id,
                ..
            } => {
                if [pack_id, clip_id, occurrence_id, operation_id]
                    .iter()
                    .any(|id| id.is_nil())
                    || [*expected_pack_revision, *expected_revision]
                        .iter()
                        .any(|v| *v == 0 || *v > 9007199254740991)
                    || field_id.is_empty()
                    || field_id.len() > 128
                    || field_id.contains('\0')
                    || representation_revision.len() != 71
                    || !representation_revision.starts_with("sha256:")
                    || !settings_hash_valid(&representation_revision[7..])
                    || start >= end
                    || *end > 67108864
                    || label.len() > 320
                    || label.chars().count() > 80
                    || label.chars().any(char::is_control)
                {
                    return Err("saved source reference identity or range is invalid");
                }
            }
            Self::PresentationRemoveSourceReference {
                pack_id,
                expected_pack_revision,
                reference_id,
                ..
            }
            | Self::PresentationResolveSourceReference {
                pack_id,
                expected_pack_revision,
                reference_id,
                ..
            } => {
                if pack_id.is_nil()
                    || reference_id.is_nil()
                    || *expected_pack_revision == 0
                    || *expected_pack_revision > 9007199254740991
                {
                    return Err("source reference identity is invalid");
                }
                if let Self::PresentationRemoveSourceReference { operation_id, .. } = self {
                    if operation_id.is_nil() {
                        return Err("source reference operation is invalid");
                    }
                }
            }
            Self::PresentationOrganize {
                collection,
                collection_id,
                expected_revision,
                action,
                name,
                items,
                operation_id,
                ..
            } => {
                if !matches!(collection.as_str(), "pack" | "queue")
                    || collection_id.is_some_and(|id| id.is_nil())
                    || operation_id.is_nil()
                    || *expected_revision > i64::MAX as u64
                    || name.len() > 256
                    || name.chars().any(char::is_control)
                    || items.len() > 500
                    || items.iter().any(Uuid::is_nil)
                    || items.iter().collect::<BTreeSet<_>>().len() != items.len()
                    || !matches!(
                        action.as_str(),
                        "create"
                            | "rename"
                            | "delete"
                            | "remove_members"
                            | "clear_members"
                            | "from_pack"
                            | "mode"
                            | "restart"
                            | "move_up"
                            | "move_down"
                    )
                    || (action == "create"
                        && (collection_id.is_some() || *expected_revision != 0 || items.is_empty()))
                    || (action == "clear_members" && (collection != "queue" || !items.is_empty()))
                    || (action != "create" && (collection_id.is_none() || *expected_revision == 0))
                {
                    return Err("collection operation is invalid");
                }
            }
            Self::PresentationQueueSelection { .. } => {}
            Self::PresentationSelectQueue {
                queue_id,
                queue_revision,
                expected_revision,
                operation_id,
                ..
            } => {
                if queue_id.is_nil()
                    || operation_id.is_nil()
                    || *queue_revision == 0
                    || *queue_revision > i64::MAX as u64
                    || !settings_hash_valid(expected_revision)
                {
                    return Err("active queue selection identity is invalid");
                }
            }
            Self::PresentationOcrStatus {
                clip_id,
                occurrence_id,
                expected_revision,
                ..
            } => {
                if clip_id.is_nil()
                    || occurrence_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                {
                    return Err("invalid OCR source identity");
                }
            }
            Self::PresentationPreviewOcrAppend {
                grant_id,
                offset,
                total_bytes,
                document_sha256,
                text,
                eof,
                ..
            } => {
                if grant_id.is_nil()
                    || *total_bytes == 0
                    || *total_bytes > 33554432
                    || text.is_empty()
                    || text.len() > 65536
                    || offset
                        .checked_add(text.len() as u64)
                        .is_none_or(|end| end > *total_bytes || *eof != (end == *total_bytes))
                    || document_sha256.len() != 64
                    || !document_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("invalid OCR document chunk");
                }
            }
            Self::PresentationKeepOpen { view_id, .. } => {
                if view_id.is_nil() {
                    return Err("invalid presentation mode identity");
                }
            }
            Self::PresentationDocumentFind {
                view_id,
                clip_id,
                occurrence_id,
                expected_revision,
                representation_revision,
                query,
                after_utf8,
                before_utf8,
                field_id,
                mode,
            } => {
                if view_id.is_nil()
                    || clip_id.is_nil()
                    || occurrence_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                    || query.is_empty()
                    || query.len() > 1024
                    || *after_utf8 > 67108864
                    || before_utf8.is_some_and(|n| n > 67108864 || *after_utf8 != 0)
                    || field_id
                        .as_ref()
                        .is_some_and(|f| f.is_empty() || f.len() > 128)
                    || !matches!(
                        mode.as_str(),
                        "literal" | "source_phrase" | "all_words" | "prefix"
                    )
                    || representation_revision.as_ref().is_some_and(|r| {
                        r.len() != 71
                            || !r.starts_with("sha256:")
                            || !r[7..].bytes().all(|b| b.is_ascii_hexdigit())
                    })
                {
                    return Err("invalid document find identity or query");
                }
            }
            Self::PresentationDocumentCopy {
                view_id,
                clip_id,
                occurrence_id,
                expected_revision,
                representation_revision,
                start,
                end,
                operation_id,
                field_id,
                full_entry,
            } => {
                if view_id.is_nil()
                    || (*full_entry && (*start != 0 || *end == 0))
                    || clip_id.is_nil()
                    || occurrence_id.is_nil()
                    || operation_id.is_nil()
                    || field_id
                        .as_ref()
                        .is_some_and(|f| f.is_empty() || f.len() > 128)
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                    || *start > *end
                    || *end > 67108864
                    || representation_revision.len() != 71
                    || !representation_revision.starts_with("sha256:")
                    || !representation_revision[7..]
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                {
                    return Err("invalid document selection identity or range");
                }
            }
            Self::PresentationDocumentRead {
                clip_id,
                occurrence_id,
                expected_revision,
                offset,
                max_bytes,
                representation_revision,
                field_id,
                ..
            } => {
                if field_id
                    .as_ref()
                    .is_some_and(|f| f.is_empty() || f.len() > 128)
                    || clip_id.is_nil()
                    || occurrence_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > 9007199254740991
                    || *offset > 67108864
                    || !(4..=65536).contains(max_bytes)
                    || representation_revision.as_ref().is_some_and(|value| {
                        value.len() != 71
                            || !value.starts_with("sha256:")
                            || !value[7..].bytes().all(|b| b.is_ascii_hexdigit())
                    })
                {
                    return Err("document range or representation identity is invalid");
                }
            }
            Self::PresentationPreviewCapabilities => {}
            Self::PresentationPreviewOpen {
                operation_id,
                consumer_window,
                item,
                ..
            } => {
                if operation_id.is_nil()
                    || *consumer_window == 0
                    || *consumer_window > i64::MAX as u64
                {
                    return Err("clipboard preview consumer identity is invalid");
                }
                item.validate()?;
            }
            Self::PresentationPreviewRead {
                grant_id,
                offset,
                max_bytes,
                ..
            } => {
                if grant_id.is_nil() || *offset >= 67108864 || !(1..=65536).contains(max_bytes) {
                    return Err("clipboard preview read exceeds its bounds");
                }
            }
            Self::PresentationPreviewValidate { grant_id, .. } => {
                if grant_id.is_nil() {
                    return Err("clipboard preview grant is invalid");
                }
            }
            Self::PresentationPreviewClose { operation_id } => {
                if operation_id.is_nil() {
                    return Err("clipboard preview operation is invalid");
                }
            }
            Self::PresentationDragVerifyOffer {
                operation_id,
                lease_id,
                target_window,
                paths,
            } => {
                if operation_id.is_nil()
                    || lease_id.is_nil()
                    || *target_window == 0
                    || *target_window > i64::MAX as u64
                    || paths.is_empty()
                    || paths.len() > 500
                    || paths
                        .iter()
                        .any(|p| p.is_empty() || p.len() > 32767 || p.contains('\0'))
                    || paths.iter().map(String::len).sum::<usize>() > 262144
                {
                    return Err("generated drag offer scope is invalid");
                }
            }
            Self::PresentationDragCapabilities | Self::PresentationDragProvenanceCapabilities => {}
            Self::PresentationDragStart {
                operation_id,
                generated_offer_version,
                consumer_window,
                items,
                ..
            } => {
                if operation_id.is_nil()
                    || !(1..=2).contains(generated_offer_version)
                    || *consumer_window == 0
                    || *consumer_window > i64::MAX as u64
                    || items.is_empty()
                    || items.len() > 100
                {
                    return Err("clipboard drag scope is invalid");
                }
                let mut unique = BTreeSet::new();
                for item in items {
                    if item.id.is_nil()
                        || item.occurrence_id.is_nil()
                        || item.expected_revision == 0
                        || item.expected_revision > i64::MAX as u64
                        || item.queue_item_id.is_some_and(|id| id.is_nil())
                        || !unique.insert((item.occurrence_id, item.queue_item_id))
                    {
                        return Err("clipboard drag selection is invalid");
                    }
                }
            }
            Self::PresentationDragStatus { operation_id }
            | Self::PresentationDragCancel { operation_id } => {
                if operation_id.is_nil() {
                    return Err("clipboard drag operation is invalid");
                }
            }
            Self::SettingsRead => {}
            Self::SettingsValidate {
                expected_revision,
                patch,
            } => {
                if !settings_hash_valid(expected_revision) {
                    return Err("native settings revision is invalid");
                }
                patch.validate()?;
            }
            Self::SettingsPrepare {
                operation_id,
                expected_revision,
                patch,
                digest,
            } => {
                if operation_id.is_nil()
                    || !settings_hash_valid(expected_revision)
                    || !settings_hash_valid(digest)
                {
                    return Err("native settings prepare identity is invalid");
                }
                patch.validate()?;
            }
            Self::SettingsCommit {
                operation_id,
                digest,
            }
            | Self::SettingsStatus {
                operation_id,
                digest,
            }
            | Self::SettingsCompensate {
                operation_id,
                digest,
            } => {
                if operation_id.is_nil() || !settings_hash_valid(digest) {
                    return Err("native settings operation identity is invalid");
                }
            }
            Self::PresentationHotkeyState => {}
            Self::PresentationFavorites { .. } => {}
            Self::PresentationSwapFavorites {
                operation_id,
                first_slot,
                first_expected_revision,
                second_slot,
                second_expected_revision,
                ..
            } => {
                if operation_id.is_nil()
                    || !(1..=10).contains(first_slot)
                    || !(1..=10).contains(second_slot)
                    || first_slot == second_slot
                    || *first_expected_revision == 0
                    || *first_expected_revision > i64::MAX as u64
                    || *second_expected_revision == 0
                    || *second_expected_revision > i64::MAX as u64
                {
                    return Err("favorite swap scope is invalid");
                }
            }
            Self::PresentationCustomizeFavorite {
                operation_id,
                slot,
                expected_revision,
                title_override,
                icon_token,
                color_token,
                ..
            } => {
                if operation_id.is_nil()
                    || !(1..=10).contains(slot)
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                {
                    return Err("favorite customization scope is invalid");
                }
                validate_favorite_customization(
                    title_override.as_deref(),
                    icon_token.as_deref(),
                    color_token.as_deref(),
                )?;
            }
            Self::PresentationArchiveStart {
                operation_id,
                action,
                clips,
                ..
            } => {
                if operation_id.is_nil()
                    || !matches!(action.as_str(), "export" | "import")
                    || (action == "import" && !clips.is_empty())
                    || (action == "export" && clips.is_empty())
                    || clips
                        .iter()
                        .map(|clip| clip.id)
                        .collect::<BTreeSet<_>>()
                        .len()
                        != clips.len()
                {
                    return Err("native archive operation scope is invalid");
                }
                validate_draft_clips(clips, true)?;
            }
            Self::PresentationArchiveStatus { operation_id }
            | Self::PresentationArchiveCancel { operation_id }
            | Self::PresentationArchiveCommit { operation_id, .. } => {
                if operation_id.is_nil() {
                    return Err("native archive operation identity is invalid");
                }
            }
            Self::PresentationCapturedFiles {
                clip_id,
                expected_revision,
                offset,
                limit,
                ..
            } => {
                if clip_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                    || *offset > 1000
                    || !(1..=100).contains(limit)
                {
                    return Err("captured file page identity or bounds are invalid");
                }
            }
            Self::PresentationCreateFileSubset {
                clip_id,
                expected_revision,
                ordinals,
                ..
            } => {
                if clip_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                    || ordinals.is_empty()
                    || ordinals.len() > 1000
                    || ordinals.iter().any(|v| *v >= 1000)
                    || ordinals.iter().collect::<BTreeSet<_>>().len() != ordinals.len()
                {
                    return Err("captured file subset identity or bounds are invalid");
                }
            }
            Self::PresentationDrafts { .. } => {}
            Self::PresentationReadDraft {
                draft_id,
                expected_revision,
                offset,
                ..
            } => {
                if draft_id.is_nil()
                    || expected_revision.is_some() != offset.is_some()
                    || expected_revision.is_some_and(|v| v == 0 || v > i64::MAX as u64)
                    || offset.is_some_and(|v| v > 1024 * 1024)
                {
                    return Err("draft identity is invalid");
                }
            }
            Self::PresentationEditDraft {
                draft_id,
                expected_revision,
                operation_id,
                offset,
                total_bytes,
                representation_revision,
                text,
                ..
            } => {
                if draft_id.is_nil()
                    || operation_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                    || *total_bytes > 1024 * 1024
                    || text.len() > 65536
                    || text.contains('\0')
                    || u64::from(*offset) + text.len() as u64 > u64::from(*total_bytes)
                    || (text.is_empty() && *total_bytes != 0)
                    || representation_revision.len() != 71
                    || !representation_revision.starts_with("sha256:")
                    || !settings_hash_valid(&representation_revision[7..])
                {
                    return Err("draft edit identity or chunk bounds are invalid");
                }
            }
            Self::PresentationPublishDraft {
                draft_id,
                expected_revision,
                operation_id,
                paste,
                start,
                end,
                representation_revision,
                ..
            } => {
                if draft_id.is_nil()
                    || operation_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                    || start.is_some() != end.is_some()
                    || start.is_some() != representation_revision.is_some()
                    || start
                        .zip(*end)
                        .is_some_and(|(s, e)| *paste || s >= e || e > 1024 * 1024)
                    || representation_revision.as_ref().is_some_and(|v| {
                        v.len() != 71 || !v.starts_with("sha256:") || !settings_hash_valid(&v[7..])
                    })
                {
                    return Err("draft publication identity or selection is invalid");
                }
            }
            Self::PresentationStartDraft {
                name,
                separator,
                clips,
                ..
            } => {
                if name.trim().is_empty()
                    || name.len() > 256
                    || name.contains('\0')
                    || separator.len() > 256
                    || separator.contains('\0')
                {
                    return Err("draft options exceed their bounds");
                }
                validate_draft_clips(clips, true)?;
            }
            Self::PresentationAppendDraft {
                draft_id,
                expected_revision,
                clips,
                ..
            } => {
                if draft_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                {
                    return Err("draft identity is invalid");
                }
                validate_draft_clips(clips, false)?;
            }
            Self::PresentationUndoDraft {
                draft_id,
                expected_revision,
                ..
            }
            | Self::PresentationStopDraft {
                draft_id,
                expected_revision,
                ..
            }
            | Self::PresentationFinishDraft {
                draft_id,
                expected_revision,
                ..
            } => {
                if draft_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                {
                    return Err("draft identity is invalid");
                }
            }
            Self::PresentationCaptureSessions { .. } => {}
            Self::PresentationStartCaptureSession {
                pack_id,
                pack_revision,
                inactivity_timeout_seconds,
                ..
            } => {
                if pack_id.is_some() != pack_revision.is_some()
                    || pack_id.is_some_and(|id| id.is_nil())
                    || pack_revision.is_some_and(|v| v == 0 || v > i64::MAX as u64)
                    || inactivity_timeout_seconds.is_some_and(|s| !(60..=86400).contains(&s))
                {
                    return Err("capture session options are invalid");
                }
            }
            Self::PresentationStopCaptureSession {
                session_id,
                expected_revision,
                ..
            } => {
                if session_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                {
                    return Err("capture session identity is invalid");
                }
            }
            Self::PresentationMaterializeSession {
                session_id,
                expected_revision,
                name,
                target,
                mode,
                ..
            } => {
                if session_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                    || name.trim().is_empty()
                    || name.len() > 256
                    || !matches!(target.as_str(), "pack" | "queue")
                    || !matches!(mode.as_str(), "fifo" | "lifo" | "manual")
                {
                    return Err("capture session output is invalid");
                }
            }
            Self::PresentationListSmartPacks { .. } => {}
            Self::PresentationQueueCurrent { queue_id, .. } => {
                if queue_id.is_nil() {
                    return Err("queue identity is invalid");
                }
            }
            Self::PresentationDeleteSmartPack {
                pack_id,
                expected_revision,
                ..
            } => {
                if pack_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                {
                    return Err("smart pack identity is invalid");
                }
            }
            Self::PresentationSaveSmartPack {
                pack_id,
                expected_revision,
                name,
                filter,
                ..
            } => {
                if name.trim().is_empty()
                    || name.len() > 256
                    || pack_id.is_some() != expected_revision.is_some()
                    || pack_id.is_some_and(|id| id.is_nil())
                    || expected_revision.is_some_and(|v| v == 0 || v > i64::MAX as u64)
                {
                    return Err("smart pack identity is invalid");
                }
                filter.validate()?;
            }
            Self::PresentationBegin {
                window_label,
                target_window,
            } => {
                if !matches!(window_label.as_str(), "main" | "quick")
                    || *target_window > i64::MAX as u64
                {
                    return Err("presentation window is invalid");
                }
            }
            Self::PresentationQuery {
                view_id,
                generation,
                query,
                mode,
                kinds,
                clip_ids,
                legacy_group_id,
                owner_scope,
                pack_id,
                queue_id,
                smart_pack_id,
                capture_session_id,
                related_tags,
                related_group_id,
                source_app,
                after_utc,
                before_utc,
                limit,
                before_sequence,
                around_occurrence,
                pinned_only: _,
                include_color_labels: _,
            } => {
                if view_id.is_nil()
                    || *generation > i64::MAX as u64
                    || query.len() > 2048
                    || !matches!(
                        mode.as_str(),
                        "all_words" | "literal" | "source_phrase" | "prefix"
                    )
                    || kinds.len() > 8
                    || clip_ids.len() > 100
                    || clip_ids.iter().any(Uuid::is_nil)
                    || legacy_group_id.is_some_and(|id| id > 9007199254740991)
                    || owner_scope
                        .as_ref()
                        .is_some_and(|s| !matches!(s.as_str(), "packs" | "queue"))
                    || pack_id.is_some_and(|id| id.is_nil())
                    || queue_id.is_some_and(|id| id.is_nil())
                    || (pack_id.is_some() && queue_id.is_some())
                    || ((pack_id.is_some() || queue_id.is_some())
                        && (*related_tags
                            || smart_pack_id.is_some()
                            || around_occurrence.is_some()))
                    || smart_pack_id.is_some_and(|id| id.is_nil())
                    || capture_session_id.is_some_and(|id| id.is_nil())
                    || related_group_id.as_ref().is_some_and(|id| {
                        !*related_tags
                            || id.len() != 64
                            || !id.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                    || !(1..=CLIPBOARD_PRESENTATION_MAX_ITEMS).contains(limit)
                    || source_app.as_ref().is_some_and(|s| s.len() > 256)
                    || before_sequence.is_some_and(|v| v > i64::MAX as u64)
                    || around_occurrence.is_some_and(|v| v.is_nil())
                    || after_utc.is_some_and(|v| v < 0)
                    || before_utc.is_some_and(|v| v < 0)
                    || matches!((after_utc, before_utc), (Some(a),Some(b)) if a > b)
                    || kinds.iter().any(|v| {
                        !matches!(
                            v.as_str(),
                            "text"
                                | "image"
                                | "file"
                                | "files"
                                | "url"
                                | "audio"
                                | "video"
                                | "other"
                        )
                    })
                {
                    return Err("presentation query exceeds its bounds");
                }
            }
            Self::PresentationRevoke { view_id } | Self::PresentationRenew { view_id } => {
                if view_id.is_nil() {
                    return Err("presentation view is invalid");
                }
            }
            Self::PresentationPublish {
                view_id,
                clip_id,
                operation_id,
                expected_revision,
                paste,
                queue_id,
                queue_revision,
                queue_item_id,
                ..
            } => {
                if view_id.is_nil()
                    || clip_id.is_nil()
                    || operation_id.is_nil()
                    || *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                {
                    return Err("presentation publication identity is invalid");
                }
                if !matches!(
                    (queue_id, queue_revision, queue_item_id),
                    (None, None, None) | (Some(_), Some(_), Some(_))
                ) || (!*paste && queue_id.is_some())
                    || queue_id.is_some_and(|id| id.is_nil())
                    || queue_item_id.is_some_and(|id| id.is_nil())
                    || queue_revision
                        .is_some_and(|revision| revision == 0 || revision > i64::MAX as u64)
                {
                    return Err("presentation queue publication identity is invalid");
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ClipboardPresentationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClipboardPresentationCommand([private])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationView {
    #[serde(default)]
    pub open_intent: Option<ClipboardOpenIntent>,
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub snapshot_sequence: u64,
    pub target_available: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardOpenIntent {
    pub action: String,
    pub query: String,
    pub mode: String,
    pub section: String,
    pub clip_id: Option<Uuid>,
    pub expected_revision: Option<u64>,
    pub occurrence_id: Option<Uuid>,
    pub legacy_group_id: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardTextHighlight {
    pub start: u64,
    pub end: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSearchMatch {
    pub matched_query: String,
    pub query_mode: String,
    pub typo: bool,
    #[serde(default)]
    pub match_kind: Option<String>,
    pub field_id: String,
    pub representation_revision: String,
    pub start: u64,
    pub end: u64,
    pub highlights: Vec<ClipboardTextHighlight>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationItem {
    #[serde(default)]
    pub color_token: Option<String>,
    #[serde(default)]
    pub membership_ordinal: Option<u64>,
    #[serde(default)]
    pub queue_item_id: Option<Uuid>,
    #[serde(default)]
    pub queue_item_state: Option<String>,
    #[serde(default)]
    pub search_match: Option<ClipboardSearchMatch>,
    pub id: Uuid,
    pub revision: u64,
    pub occurrence_id: Uuid,
    pub capture_sequence: u64,
    pub copied_at: DateTime<Utc>,
    pub legacy_estimate: bool,
    pub kind: String,
    pub excerpt: String,
    pub source_application: Option<String>,
    #[serde(default)]
    pub source_executable_path: Option<String>,
    #[serde(default)]
    pub source_attribution_confidence: Option<String>,
    pub pinned: bool,
    pub copy_count: u64,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub tag_group_id: Option<String>,
    #[serde(default)]
    pub related_group: Option<ClipboardPresentationRelatedGroup>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationRelatedGroup {
    pub id: String,
    pub seed_clip_id: Uuid,
    pub matching_clips: u64,
    pub matching_occurrences: u64,
}

fn approximate_unavailable() -> String {
    "unavailable".into()
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationSearchProgress {
    pub stage: String,
    pub indexed_clips: u64,
    pub total_clips: u64,
    pub limited_clips: u64,
    #[serde(default = "approximate_unavailable")]
    pub approximate_coverage: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationPage {
    pub generation: u64,
    pub snapshot_sequence: u64,
    pub items: Vec<ClipboardPresentationItem>,
    pub has_more: bool,
    #[serde(default)]
    pub search_progress: Option<ClipboardPresentationSearchProgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardPublicationState {
    Published,
    InputDispatched,
    Blocked,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPublicationReceipt {
    pub operation_id: Uuid,
    pub state: ClipboardPublicationState,
    pub clipboard_sequence: u32,
    #[serde(default)]
    pub queue_advanced: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationHotkeyState {
    pub session_id: Uuid,
    pub revision: u64,
    pub cycle_offset: i32,
    pub cycle_count: u32,
    pub released: bool,
    pub cancelled: bool,
    // Native Spiffy Clipboard sets this when an already-open picker is
    // navigating without a pending implicit paste. The strict response
    // decoder must accept it; previous builds rejected the entire Win+V
    // update as an unexpected field. Old peers omit it.
    #[serde(default)]
    pub browse_only: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationQueueCurrent {
    pub queue_id: Uuid,
    pub queue_revision: u64,
    pub item_id: Option<Uuid>,
    pub clip_id: Option<Uuid>,
    pub state: String,
    pub mode: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationSmartPack {
    pub id: Uuid,
    pub revision: u64,
    pub name: String,
    pub filter: ClipboardPresentationSmartPackFilter,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationCaptureSession {
    pub id: Uuid,
    pub revision: u64,
    pub pack_id: Option<Uuid>,
    pub state: String,
    pub started_at: DateTime<Utc>,
    pub last_capture_at: Option<DateTime<Utc>>,
    pub capture_count: u64,
    pub inactivity_timeout_seconds: Option<u32>,
    pub persist_across_restart: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationSessionOutput {
    pub id: Uuid,
    pub revision: u64,
    pub kind: String,
    pub item_count: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationClipRevision {
    pub id: Uuid,
    pub revision: u64,
}

fn validate_draft_clips(
    clips: &[ClipboardPresentationClipRevision],
    empty_ok: bool,
) -> Result<(), &'static str> {
    if (!empty_ok && clips.is_empty())
        || clips.len() > 100
        || clips
            .iter()
            .any(|c| c.id.is_nil() || c.revision == 0 || c.revision > i64::MAX as u64)
    {
        return Err("draft source references exceed their bounds");
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationDraft {
    pub id: Uuid,
    pub revision: u64,
    pub name: String,
    pub state: String,
    pub separator: String,
    pub fragment_count: u32,
    pub published_clip_id: Option<Uuid>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationDraftPreview {
    pub draft_id: Uuid,
    pub content_state: String,
    pub excerpt: String,
    pub byte_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub representation_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationCapturedFile {
    pub ordinal: u32,
    pub path: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationCapturedFiles {
    pub clip_id: Uuid,
    pub revision: u64,
    pub total_files: u32,
    pub offset: u32,
    pub items: Vec<ClipboardPresentationCapturedFile>,
    pub next_offset: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationCreatedClip {
    pub id: Uuid,
    pub revision: u64,
    pub source_clip_id: Uuid,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationArchiveOperation {
    pub operation_id: Uuid,
    pub action: String,
    pub state: String,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub clip_count: u32,
    pub format_count: u32,
    pub byte_count: u64,
    pub error_code: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationFavorite {
    pub slot: u8,
    pub revision: u64,
    pub clip_id: Option<Uuid>,
    pub title_override: Option<String>,
    pub icon_token: Option<String>,
    pub color_token: Option<String>,
}

fn validate_favorite_customization(
    title: Option<&str>,
    icon: Option<&str>,
    color: Option<&str>,
) -> Result<(), &'static str> {
    if title.is_some_and(|value| value.chars().count() > 80 || value.chars().any(char::is_control))
        || icon.is_some_and(|value| {
            !matches!(
                value,
                "star"
                    | "bookmark"
                    | "link"
                    | "text"
                    | "code"
                    | "folder"
                    | "image"
                    | "music"
                    | "video"
                    | "bolt"
                    | "heart"
                    | "check"
            )
        })
        || color.is_some_and(|value| {
            value.len() != 7
                || !value.starts_with('#')
                || !value[1..].bytes().all(|c| c.is_ascii_hexdigit())
        })
    {
        return Err("favorite customization exceeds its bounds");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardPreviewPurpose {
    Thumbnail,
    Inspector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPreviewItem {
    pub clip_id: Uuid,
    pub occurrence_id: Uuid,
    pub expected_revision: u64,
    pub queue_item_id: Option<Uuid>,
    pub file_ordinal: Option<u16>,
    pub purpose: ClipboardPreviewPurpose,
}

impl ClipboardPreviewItem {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.clip_id.is_nil()
            || self.occurrence_id.is_nil()
            || self.expected_revision == 0
            || self.expected_revision > i64::MAX as u64
            || self.queue_item_id.is_some_and(|id| id.is_nil())
            || self.file_ordinal.is_some_and(|ordinal| ordinal >= 1000)
        {
            return Err("clipboard preview item identity is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPreviewCapabilities {
    pub version: u16,
    pub maximum_grants: u16,
    pub maximum_source_bytes: u64,
    pub maximum_chunk_bytes: u32,
    pub lease_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardPreviewImageEncoding {
    Png,
    Bmp,
}

/// Private to the authenticated native consumer; never projected to WebView.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClipboardPreviewSource {
    Image {
        encoding: ClipboardPreviewImageEncoding,
        total_bytes: u64,
        sha256: String,
        width: u32,
        height: u32,
    },
    File {
        path: String,
        identity: String,
        bytes: u64,
        modified_ns: u64,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPreviewGrant {
    pub grant_id: Uuid,
    pub operation_id: Uuid,
    pub view_id: Uuid,
    pub producer_pid: u32,
    pub producer_birth: u64,
    pub consumer_window: u64,
    pub item: ClipboardPreviewItem,
    pub file_count: Option<u16>,
    pub expires_at: DateTime<Utc>,
    pub source: ClipboardPreviewSource,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPreviewChunk {
    pub view_id: Uuid,
    pub grant_id: Uuid,
    pub offset: u64,
    pub total_bytes: u64,
    pub sha256: String,
    pub data_base64: String,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPreviewClosed {
    pub operation_id: Uuid,
    pub closed: bool,
}

fn preview_hash_valid(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ClipboardPreviewGrant {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.item.validate()?;
        if self.grant_id.is_nil()
            || self.operation_id.is_nil()
            || self.view_id.is_nil()
            || self.producer_pid == 0
            || self.producer_birth == 0
            || self.consumer_window == 0
            || self.consumer_window > i64::MAX as u64
        {
            return Err("clipboard preview grant identity is invalid");
        }
        match &self.source {
            ClipboardPreviewSource::Image {
                total_bytes,
                sha256,
                width,
                height,
                ..
            } => {
                if self.file_count.is_some()
                    || self.item.file_ordinal.is_some()
                    || !(1..=67108864).contains(total_bytes)
                    || !preview_hash_valid(sha256, 64)
                    || !(1..=32768).contains(width)
                    || !(1..=32768).contains(height)
                    || u64::from(*width) * u64::from(*height) > 32_000_000
                {
                    return Err("clipboard preview image exceeds its bounds");
                }
            }
            ClipboardPreviewSource::File {
                path,
                identity,
                bytes,
                ..
            } => {
                if path.is_empty()
                    || path.len() > 32767
                    || path.contains('\0')
                    || !preview_hash_valid(identity, 48)
                    || *bytes > i64::MAX as u64
                    || self
                        .file_count
                        .is_none_or(|count| !(1..=1000).contains(&count))
                    || self
                        .item
                        .file_ordinal
                        .is_none_or(|ordinal| self.file_count.is_none_or(|count| ordinal >= count))
                {
                    return Err("clipboard preview file exceeds its bounds");
                }
            }
        }
        Ok(())
    }
}

impl ClipboardPreviewChunk {
    pub fn validate(&self) -> Result<(), &'static str> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        if self.view_id.is_nil()
            || self.grant_id.is_nil()
            || !(1..=67108864).contains(&self.total_bytes)
            || self.offset >= self.total_bytes
            || !preview_hash_valid(&self.sha256, 64)
            || self.data_base64.len() > 87384
        {
            return Err("clipboard preview chunk exceeds its bounds");
        }
        let bytes = zeroize::Zeroizing::new(
            STANDARD
                .decode(&self.data_base64)
                .map_err(|_| "clipboard preview chunk is malformed")?,
        );
        let remaining = self.total_bytes - self.offset;
        if bytes.is_empty()
            || bytes.len() > 65536
            || bytes.len() as u64 > remaining
            || self.eof != (bytes.len() as u64 == remaining)
        {
            return Err("clipboard preview chunk end is invalid");
        }
        Ok(())
    }
}

/// Reference-only ordered drag selection. Distinct occurrences of one clip remain distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDragItem {
    pub id: Uuid,
    pub expected_revision: u64,
    pub occurrence_id: Uuid,
    #[serde(default)]
    pub queue_item_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDragCapabilities {
    pub version: u16,
    #[serde(default)]
    pub generated_offer_version: u16,
    pub maximum_items: u16,
    pub maximum_source_bytes: u64,
    pub file_lease_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDragReceipt {
    pub operation_id: Uuid,
    pub state: String,
    pub item_count: u16,
    pub revision: u64,
    pub mode: String,
    pub error_code: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub file_lease_seconds: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardGeneratedDragFile {
    pub ordinal: u16,
    pub identity: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardGeneratedDragSourceReference {
    pub ordinal: u16,
    pub clip_id: Uuid,
    pub occurrence_id: Uuid,
    pub expected_revision: u64,
    #[serde(default)]
    pub queue_item_id: Option<Uuid>,
}

fn generated_drag_offer_v1() -> u16 {
    1
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardGeneratedDragOffer {
    #[serde(default = "generated_drag_offer_v1")]
    pub generated_offer_version: u16,
    pub operation_id: Uuid,
    pub lease_id: Uuid,
    pub producer_pid: u32,
    pub producer_birth: u64,
    pub target_window: u64,
    pub offered_count: u16,
    pub expires_at: DateTime<Utc>,
    pub generated_files: Vec<ClipboardGeneratedDragFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_references: Vec<ClipboardGeneratedDragSourceReference>,
}

/// Byte ranges refer to the exact native plain-text representation. The view
/// remains the authorization session; each request validates source currentness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDocumentMatch {
    pub start: u64,
    pub end: u64,
    pub utf16_start: u64,
    pub utf16_end: u64,
    pub actual_text: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDocumentMatches {
    pub matches: Vec<ClipboardDocumentMatch>,
    pub has_more: bool,
    pub next_offset: Option<u64>,
    pub total_matches: u64,
    pub complete: bool,
    pub coordinate_unit: String,
    pub semantics_version: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDocumentFind {
    pub clip_id: Uuid,
    pub revision: u64,
    pub representation_revision: String,
    pub result: ClipboardDocumentMatches,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDocumentRange {
    pub clip_id: Uuid,
    pub revision: u64,
    pub representation_revision: String,
    pub total_bytes: u64,
    pub offset: u64,
    pub text: String,
    pub eof: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardOcrStatus {
    pub clip_id: Uuid,
    pub revision: u64,
    pub field_id: String,
    pub representation_revision: String,
    pub text_revision: String,
    pub document_bytes: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardQueueSelection {
    pub queue_id: Option<Uuid>,
    pub owner_revision: String,
    /// Runtime-local input interception. This is false after restart until
    /// explicitly enabled, even if the persisted active queue ID is retained.
    #[serde(default)]
    pub ctrl_v_armed: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardCollectionChange {
    pub operation_id: Uuid,
    pub id: Uuid,
    pub collection: String,
    pub revision: u64,
    pub deleted: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardClipMetadata {
    pub clip_id: Uuid,
    pub revision: u64,
    pub recall_name: String,
    pub note: String,
    pub recall_approved: bool,
    pub recall_current: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSourceReference {
    pub id: Uuid,
    pub label: String,
    pub owner_id: String,
    pub clip_id: Uuid,
    pub occurrence_id: Uuid,
    pub source_revision: u64,
    pub current_revision: Option<u64>,
    pub field_id: String,
    pub representation_revision: String,
    pub start: u64,
    pub end: u64,
    pub state: String,
}
impl ClipboardSourceReference {
    fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_nil()
            || self.clip_id.is_nil()
            || self.occurrence_id.is_nil()
            || self.owner_id != "spiffy.clipboard.windows.ditto"
            || self.source_revision == 0
            || self.source_revision > 9007199254740991
            || self
                .current_revision
                .is_some_and(|v| v == 0 || v > 9007199254740991)
            || self.label.len() > 320
            || self.label.chars().count() > 80
            || self.label.chars().any(char::is_control)
            || self.field_id.is_empty()
            || self.field_id.len() > 128
            || self.field_id.contains('\0')
            || self.representation_revision.len() != 71
            || !self.representation_revision.starts_with("sha256:")
            || !settings_hash_valid(&self.representation_revision[7..])
            || self.start >= self.end
            || self.end > 67108864
            || !matches!(self.state.as_str(), "current" | "changed" | "unavailable")
            || (self.state == "current" && self.current_revision.is_none())
        {
            return Err("invalid source reference identity or range");
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSourceReferences {
    pub pack_id: Uuid,
    pub pack_revision: u64,
    pub items: Vec<ClipboardSourceReference>,
    pub next_offset: Option<u32>,
    pub total: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSourceReferenceChange {
    pub pack_id: Uuid,
    pub pack_revision: u64,
    pub reference_id: Uuid,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardReuseSettings {
    pub enabled: bool,
    pub policy_epoch: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardReuseItem {
    pub id: Uuid,
    pub revision: u64,
    pub title: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardReuseOffer {
    pub id: String,
    pub candidate_id: String,
    pub kind: String,
    pub items: Vec<ClipboardReuseItem>,
    pub favorite_slot: u8,
    pub favorite_slot_revision: u64,
    pub policy_epoch: u64,
    pub uses: u32,
    pub local_dates: u32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardReuseAcceptance {
    pub favorite_slot: u8,
    pub pack_id: Option<Uuid>,
    pub pack_revision: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDeleteClip {
    pub clip_id: Uuid,
    pub occurrence_id: Uuid,
    pub expected_revision: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardColorChange {
    pub operation_id: Uuid,
    pub clip_ids: Vec<Uuid>,
    pub color_token: String,
}

pub fn clipboard_color_token_valid(value: &str) -> bool {
    matches!(
        value,
        "" | "#000000"
            | "#FF0000"
            | "#FFB400"
            | "#00C4FF"
            | "#FF1F8B"
            | "#8A30FF"
            | "#FFFFFF"
            | "#0038FF"
            | "#00D420"
            | "#001E9A"
            | "#FF6300"
            | "#6A2A10"
            | "#FF3700"
            | "#007F6A"
            | "#B06A28"
            | "#006214"
    )
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardDeletedClips {
    pub operation_id: Uuid,
    pub clip_ids: Vec<Uuid>,
    pub deleted_count: u32,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSemanticResult {
    pub clip_id: Uuid,
    pub occurrence_id: Uuid,
    pub revision: u64,
    pub field_id: String,
    pub representation_revision: String,
    pub start: u64,
    pub end: u64,
    pub score: f64,
    pub title: String,
    pub excerpt: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardSemanticState {
    pub operation_id: Uuid,
    pub generation_id: Option<Uuid>,
    pub state: String,
    pub model: String,
    pub encoding_fingerprint: Option<String>,
    pub scope_count: u32,
    pub completed_fields: u32,
    pub total_fields: u32,
    pub error_code: Option<String>,
    pub results: Vec<ClipboardSemanticResult>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardPresentationResponse {
    #[serde(default)]
    pub color_change: Option<ClipboardColorChange>,
    #[serde(default)]
    pub semantic: Option<ClipboardSemanticState>,
    #[serde(default)]
    pub deleted_clips: Option<ClipboardDeletedClips>,
    #[serde(default)]
    pub clip_metadata: Option<ClipboardClipMetadata>,
    #[serde(default)]
    pub source_references: Option<ClipboardSourceReferences>,
    #[serde(default)]
    pub source_reference_change: Option<ClipboardSourceReferenceChange>,
    #[serde(default)]
    pub source_location: Option<ClipboardSourceReference>,
    #[serde(default)]
    pub reuse_settings: Option<ClipboardReuseSettings>,
    #[serde(default)]
    pub reuse_offer: Option<ClipboardReuseOffer>,
    #[serde(default)]
    pub reuse_acceptance: Option<ClipboardReuseAcceptance>,
    #[serde(default)]
    pub collection_change: Option<ClipboardCollectionChange>,
    #[serde(default)]
    pub queue_selection: Option<ClipboardQueueSelection>,
    #[serde(default)]
    pub ocr_status: Option<ClipboardOcrStatus>,
    #[serde(default)]
    pub document_find: Option<ClipboardDocumentFind>,
    #[serde(default)]
    pub document_range: Option<ClipboardDocumentRange>,
    #[serde(default)]
    pub preview_capabilities: Option<ClipboardPreviewCapabilities>,
    #[serde(default)]
    pub preview_grant: Option<ClipboardPreviewGrant>,
    #[serde(default)]
    pub preview_chunk: Option<ClipboardPreviewChunk>,
    #[serde(default)]
    pub preview_closed: Option<ClipboardPreviewClosed>,
    #[serde(default)]
    pub drag_capabilities: Option<ClipboardDragCapabilities>,
    #[serde(default)]
    pub drag_receipt: Option<ClipboardDragReceipt>,
    #[serde(default)]
    pub generated_drag_offer: Option<ClipboardGeneratedDragOffer>,
    #[serde(default)]
    pub settings_snapshot: Option<ClipboardSettingsSnapshot>,
    #[serde(default)]
    pub settings_validation: Option<ClipboardSettingsValidation>,
    #[serde(default)]
    pub settings_receipt: Option<ClipboardSettingsReceipt>,
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub ok: bool,
    pub error_code: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub presentation_version: Option<u16>,
    #[serde(default)]
    pub view: Option<ClipboardPresentationView>,
    #[serde(default)]
    pub page: Option<ClipboardPresentationPage>,
    #[serde(default)]
    pub receipt: Option<ClipboardPublicationReceipt>,
    #[serde(default)]
    pub hotkey_state: Option<ClipboardPresentationHotkeyState>,
    #[serde(default)]
    pub queue_current: Option<ClipboardPresentationQueueCurrent>,
    #[serde(default)]
    pub smart_packs: Option<Vec<ClipboardPresentationSmartPack>>,
    #[serde(default)]
    pub capture_sessions: Option<Vec<ClipboardPresentationCaptureSession>>,
    #[serde(default)]
    pub session_output: Option<ClipboardPresentationSessionOutput>,
    #[serde(default)]
    pub drafts: Option<Vec<ClipboardPresentationDraft>>,
    #[serde(default)]
    pub draft_preview: Option<ClipboardPresentationDraftPreview>,
    #[serde(default)]
    pub captured_files: Option<ClipboardPresentationCapturedFiles>,
    #[serde(default)]
    pub created_clip: Option<ClipboardPresentationCreatedClip>,
    #[serde(default)]
    pub archive_operation: Option<ClipboardPresentationArchiveOperation>,
    #[serde(default)]
    pub favorite_slots: Option<Vec<ClipboardPresentationFavorite>>,
}

impl ClipboardPresentationResponse {
    pub fn validate_document_for(
        &self,
        command: &ClipboardPresentationCommand,
    ) -> Result<(), &'static str> {
        let projection = match command {
            ClipboardPresentationCommand::PresentationSetColor { .. } => Some("color_change"),
            ClipboardPresentationCommand::PresentationSemantic { .. } => Some("semantic"),
            ClipboardPresentationCommand::PresentationDeleteClips { .. } => Some("deleted_clips"),
            ClipboardPresentationCommand::PresentationClipMetadata { .. }
            | ClipboardPresentationCommand::PresentationEditClipMetadata { .. } => {
                Some("clip_metadata")
            }
            ClipboardPresentationCommand::PresentationSourceReferences { .. } => {
                Some("source_references")
            }
            ClipboardPresentationCommand::PresentationSaveSourceReference { .. }
            | ClipboardPresentationCommand::PresentationRemoveSourceReference { .. } => {
                Some("source_reference_change")
            }
            ClipboardPresentationCommand::PresentationResolveSourceReference { .. } => {
                Some("source_location")
            }
            ClipboardPresentationCommand::PresentationReadDraft { .. } => Some("draft_preview"),
            ClipboardPresentationCommand::PresentationEditDraft { .. } => Some("drafts"),
            ClipboardPresentationCommand::PresentationPublishDraft { .. }
            | ClipboardPresentationCommand::PresentationDocumentCopy { .. }
            | ClipboardPresentationCommand::PresentationPublish { .. } => Some("receipt"),
            ClipboardPresentationCommand::PresentationReuseSettings { .. }
            | ClipboardPresentationCommand::PresentationReuseSetEnabled { .. }
            | ClipboardPresentationCommand::PresentationReuseClearStatistics { .. }
            | ClipboardPresentationCommand::PresentationReuseResetDismissals { .. } => {
                Some("reuse_settings")
            }
            ClipboardPresentationCommand::PresentationReuseClaim { .. } => Some("reuse_offer"),
            ClipboardPresentationCommand::PresentationReuseRespond { .. } => {
                Some("reuse_acceptance")
            }
            ClipboardPresentationCommand::PresentationOcrCorrect { .. } => Some("ocr_status"),
            ClipboardPresentationCommand::PresentationOcrSaveText { .. } => Some("created_clip"),
            ClipboardPresentationCommand::PresentationOrganize { .. } => Some("collection_change"),
            ClipboardPresentationCommand::PresentationQueueSelection { .. }
            | ClipboardPresentationCommand::PresentationSelectQueue { .. } => {
                Some("queue_selection")
            }
            ClipboardPresentationCommand::PresentationQuery { .. } => Some("page"),
            ClipboardPresentationCommand::PresentationDocumentRead { .. } => Some("document_range"),
            ClipboardPresentationCommand::PresentationDocumentFind { .. } => Some("document_find"),
            ClipboardPresentationCommand::PresentationOcrStatus { .. }
            | ClipboardPresentationCommand::PresentationPreviewOcrAppend { .. } => {
                Some("ocr_status")
            }
            _ => None,
        };
        if let Some(expected) = projection {
            let encoded = serde_json::to_value(self).map_err(|_| "invalid document response")?;
            for (key, value) in encoded.as_object().ok_or("invalid document response")? {
                if !value.is_null()
                    && !matches!(
                        key.as_str(),
                        "protocol"
                            | "request_id"
                            | "ok"
                            | "error_code"
                            | "message"
                            | "presentation_version"
                    )
                    && (key != expected || !self.ok)
                {
                    return Err("document response contains unrelated content");
                }
            }
            if self.ok
                && matches!(
                    command,
                    ClipboardPresentationCommand::PresentationPreviewOcrAppend { eof: true, .. }
                )
                && self.ocr_status.is_none()
            {
                return Err("OCR commit receipt is missing");
            }
            if self.ok
                && matches!(
                    command,
                    ClipboardPresentationCommand::PresentationQuery { .. }
                )
                && self.page.is_none()
            {
                return Err("presentation query page is missing");
            }
        }

        if self.ok {
            if let ClipboardPresentationCommand::PresentationSetColor {
                operation_id,
                clips,
                color_token,
                ..
            } = command
            {
                let receipt = self
                    .color_change
                    .as_ref()
                    .ok_or("missing clipboard color receipt")?;
                if receipt.operation_id != *operation_id
                    || receipt.color_token != *color_token
                    || receipt.clip_ids != clips.iter().map(|clip| clip.clip_id).collect::<Vec<_>>()
                {
                    return Err("clipboard color receipt differs from requested selection");
                }
            }
            if let ClipboardPresentationCommand::PresentationSemantic {
                operation_id,
                generation_id,
                action,
                clip_ids,
                ..
            } = command
            {
                let semantic = self.semantic.as_ref().ok_or("missing semantic status")?;
                if semantic.operation_id != *operation_id
                    || semantic.generation_id.is_some_and(|id| id.is_nil())
                    || (generation_id.is_some()
                        && action != "clear"
                        && semantic.generation_id != *generation_id)
                    || !matches!(
                        semantic.state.as_str(),
                        "unprepared"
                            | "checking"
                            | "preparing"
                            | "ready"
                            | "searching"
                            | "complete"
                            | "cancelled"
                            | "blocked"
                    )
                    || semantic.model.len() > 256
                    || semantic.scope_count > 1000
                    || semantic.completed_fields > semantic.total_fields
                    || semantic.total_fields > 100000
                    || semantic
                        .encoding_fingerprint
                        .as_ref()
                        .is_some_and(|hash| !settings_hash_valid(hash))
                    || semantic.error_code.as_ref().is_some_and(|code| {
                        code.len() > 128
                            || !code
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    })
                    || semantic.results.len() > 20
                    || (!semantic.results.is_empty() && semantic.state != "complete")
                    || (matches!(semantic.state.as_str(), "ready" | "searching" | "complete")
                        && (semantic.generation_id.is_none()
                            || semantic.encoding_fingerprint.is_none()
                            || semantic.completed_fields != semantic.total_fields))
                    || (action == "prepare"
                        && semantic.state != "blocked"
                        && clip_ids
                            .as_ref()
                            .is_some_and(|ids| semantic.scope_count as usize != ids.len()))
                    || semantic.results.iter().any(|result| {
                        result.clip_id.is_nil()
                            || result.occurrence_id.is_nil()
                            || result.revision == 0
                            || result.revision > 9007199254740991
                            || result.field_id.is_empty()
                            || result.field_id.len() > 128
                            || result.field_id == "recall_name"
                            || result.representation_revision.len() != 71
                            || !result.representation_revision.starts_with("sha256:")
                            || !settings_hash_valid(&result.representation_revision[7..])
                            || result.start > result.end
                            || result.end > 67108864
                            || result.end - result.start != result.excerpt.len() as u64
                            || !result.score.is_finite()
                            || !(-1.0..=1.0).contains(&result.score)
                            || result.title.chars().count() > 240
                            || result.excerpt.chars().count() > 240
                    })
                {
                    return Err("semantic reply is stale, incomplete or exceeds its source bounds");
                }
            }
            if let ClipboardPresentationCommand::PresentationDeleteClips {
                operation_id,
                clips,
                ..
            } = command
            {
                let receipt = self
                    .deleted_clips
                    .as_ref()
                    .ok_or("missing history deletion receipt")?;
                if receipt.operation_id != *operation_id
                    || receipt.deleted_count as usize != clips.len()
                    || receipt.clip_ids != clips.iter().map(|clip| clip.clip_id).collect::<Vec<_>>()
                {
                    return Err("history deletion receipt differs from requested sources");
                }
            }
            if let ClipboardPresentationCommand::PresentationClipMetadata {
                clip_id,
                expected_revision,
                ..
            }
            | ClipboardPresentationCommand::PresentationEditClipMetadata {
                clip_id,
                expected_revision,
                ..
            } = command
            {
                let metadata = self
                    .clip_metadata
                    .as_ref()
                    .ok_or("missing source metadata")?;
                if metadata.clip_id != *clip_id
                    || metadata.revision < *expected_revision
                    || metadata.revision > expected_revision + 1
                    || metadata.recall_name.len() > 320
                    || metadata.recall_name.chars().count() > 80
                    || metadata.recall_name.chars().any(char::is_control)
                    || metadata.note.len() > 8192
                    || metadata.note.contains('\0')
                    || metadata.recall_current && !metadata.recall_approved
                {
                    return Err("invalid source metadata response");
                }
                if matches!(
                    command,
                    ClipboardPresentationCommand::PresentationClipMetadata { .. }
                ) && metadata.revision != *expected_revision
                {
                    return Err("stale source metadata response");
                }
            }
            if let ClipboardPresentationCommand::PresentationSourceReferences {
                pack_id,
                expected_revision,
                offset,
                limit,
                ..
            } = command
            {
                let page = self
                    .source_references
                    .as_ref()
                    .ok_or("missing source references page")?;
                if page.pack_id != *pack_id
                    || page.pack_revision != *expected_revision
                    || page.items.len() > *limit as usize
                    || page.total > 100000
                    || *offset > page.total
                    || u64::from(*offset) + page.items.len() as u64 > u64::from(page.total)
                    || page
                        .next_offset
                        .is_some_and(|n| n <= *offset || n > page.total)
                    || (page.next_offset.is_none()
                        && u64::from(*offset) + (page.items.len() as u64) < u64::from(page.total))
                {
                    return Err("invalid source references page");
                }
                let mut ids = BTreeSet::new();
                for item in &page.items {
                    item.validate()?;
                    if !ids.insert(item.id) {
                        return Err("duplicate source reference");
                    }
                }
            }
            if let ClipboardPresentationCommand::PresentationSaveSourceReference {
                pack_id,
                expected_pack_revision,
                ..
            }
            | ClipboardPresentationCommand::PresentationRemoveSourceReference {
                pack_id,
                expected_pack_revision,
                ..
            } = command
            {
                let changed = self
                    .source_reference_change
                    .as_ref()
                    .ok_or("missing source reference mutation receipt")?;
                if changed.pack_id != *pack_id
                    || changed.pack_revision != expected_pack_revision + 1
                    || changed.reference_id.is_nil()
                {
                    return Err("invalid source reference mutation receipt");
                }
                if let ClipboardPresentationCommand::PresentationRemoveSourceReference {
                    reference_id,
                    ..
                } = command
                {
                    if changed.reference_id != *reference_id {
                        return Err("source reference removal mismatch");
                    }
                }
            }
            if let ClipboardPresentationCommand::PresentationResolveSourceReference {
                reference_id,
                ..
            } = command
            {
                let source = self
                    .source_location
                    .as_ref()
                    .ok_or("missing resolved source")?;
                source.validate()?;
                if source.id != *reference_id || source.state != "current" {
                    return Err("saved source is no longer current");
                }
            }
            if let ClipboardPresentationCommand::PresentationPublishDraft { operation_id, .. } =
                command
            {
                if self
                    .receipt
                    .as_ref()
                    .is_none_or(|r| r.operation_id != *operation_id || r.queue_advanced)
                {
                    return Err("draft publication receipt identity mismatch");
                }
            }
            if let ClipboardPresentationCommand::PresentationDocumentCopy { operation_id, .. } =
                command
            {
                let receipt = self
                    .receipt
                    .as_ref()
                    .ok_or("document copy publication receipt is missing")?;
                if receipt.operation_id != *operation_id
                    || matches!(receipt.state, ClipboardPublicationState::InputDispatched)
                    || (matches!(receipt.state, ClipboardPublicationState::Published)
                        && receipt.clipboard_sequence == 0)
                    || receipt.queue_advanced
                {
                    return Err("document copy publication receipt is invalid");
                }
            }
            if let ClipboardPresentationCommand::PresentationPublish {
                operation_id,
                paste,
                queue_id,
                ..
            } = command
            {
                if !*paste && queue_id.is_some() {
                    return Err("presentation copy cannot advance a paste queue");
                }
                let receipt = self
                    .receipt
                    .as_ref()
                    .ok_or("presentation publication receipt is missing")?;
                let publication_confirmed = matches!(
                    receipt.state,
                    ClipboardPublicationState::Published
                        | ClipboardPublicationState::InputDispatched
                );
                let state_matches_request = matches!(
                    (*paste, receipt.state),
                    (false, ClipboardPublicationState::Published)
                        | (true, ClipboardPublicationState::InputDispatched)
                        | (_, ClipboardPublicationState::Blocked)
                        | (_, ClipboardPublicationState::Unknown)
                );
                let queue_advance_expected = *paste && queue_id.is_some() && publication_confirmed;
                if receipt.operation_id != *operation_id
                    || !state_matches_request
                    || (publication_confirmed && receipt.clipboard_sequence == 0)
                    || receipt.queue_advanced != queue_advance_expected
                {
                    return Err("presentation publication receipt is invalid for its request");
                }
            }
            if let ClipboardPresentationCommand::PresentationReadDraft {
                draft_id,
                expected_revision,
                offset,
                ..
            } = command
            {
                let page = self
                    .draft_preview
                    .as_ref()
                    .ok_or("missing draft reader response")?;
                if page.draft_id != *draft_id {
                    return Err("draft reader identity mismatch");
                }
                if let (Some(expected), Some(start)) = (expected_revision, offset) {
                    if matches!(page.content_state.as_str(), "ready" | "empty")
                        && (page.revision != Some(*expected)
                            || page.offset != Some(*start)
                            || page.text.is_none())
                    {
                        return Err("draft reader revision or range mismatch");
                    }
                } else if page.text.is_some() {
                    return Err("metadata draft request returned unrequested content");
                }
            }
            if let ClipboardPresentationCommand::PresentationEditDraft {
                draft_id,
                expected_revision,
                offset,
                total_bytes,
                text,
                ..
            } = command
            {
                let rows = self.drafts.as_ref().ok_or("missing draft edit receipt")?;
                if rows.len() != 1
                    || rows[0].id != *draft_id
                    || rows[0].revision < *expected_revision
                    || rows[0].revision > expected_revision + 1
                    || (u64::from(*offset) + (text.len() as u64) < u64::from(*total_bytes)
                        && rows[0].revision != *expected_revision)
                {
                    return Err("draft edit receipt identity mismatch");
                }
            }
            if matches!(
                command,
                ClipboardPresentationCommand::PresentationReuseSettings { .. }
                    | ClipboardPresentationCommand::PresentationReuseSetEnabled { .. }
                    | ClipboardPresentationCommand::PresentationReuseClearStatistics { .. }
                    | ClipboardPresentationCommand::PresentationReuseResetDismissals { .. }
            ) && self.reuse_settings.is_none()
            {
                return Err("missing reuse settings receipt");
            }
            if matches!(
                command,
                ClipboardPresentationCommand::PresentationReuseRespond { .. }
            ) && self.reuse_acceptance.is_none()
            {
                return Err("missing reuse response receipt");
            }
            if let ClipboardPresentationCommand::PresentationOcrCorrect {
                clip_id,
                expected_revision,
                ..
            } = command
            {
                if self
                    .ocr_status
                    .as_ref()
                    .is_none_or(|s| s.clip_id != *clip_id || s.revision != *expected_revision)
                {
                    return Err("missing OCR correction receipt");
                }
            }
            if let ClipboardPresentationCommand::PresentationOcrSaveText { clip_id, .. } = command {
                if self
                    .created_clip
                    .as_ref()
                    .is_none_or(|s| s.source_clip_id != *clip_id)
                {
                    return Err("missing saved OCR text identity");
                }
            }
            if let ClipboardPresentationCommand::PresentationOrganize {
                operation_id,
                collection_id,
                collection,
                action,
                ..
            } = command
            {
                let changed = self
                    .collection_change
                    .as_ref()
                    .ok_or("missing collection receipt")?;
                if changed.operation_id != *operation_id
                    || changed.id.is_nil()
                    || changed.collection
                        != (if action == "from_pack" {
                            "queue"
                        } else {
                            collection
                        })
                    || (action != "create"
                        && action != "from_pack"
                        && Some(changed.id) != *collection_id)
                    || changed.deleted != (action == "delete")
                    || (changed.revision == 0) != changed.deleted
                {
                    return Err("collection receipt identity mismatch");
                }
            }
            if matches!(
                command,
                ClipboardPresentationCommand::PresentationQueueSelection { .. }
                    | ClipboardPresentationCommand::PresentationSelectQueue { .. }
            ) && self.queue_selection.is_none()
            {
                return Err("missing queue selection receipt");
            }
            if let ClipboardPresentationCommand::PresentationSelectQueue { queue_id, .. } = command
            {
                if self.queue_selection.as_ref().and_then(|s| s.queue_id) != Some(*queue_id) {
                    return Err("queue selection identity mismatch");
                }
            }
        }

        if let Some(ocr) = &self.ocr_status {
            if !self.ok
                || ocr.clip_id.is_nil()
                || ocr.revision == 0
                || ocr.revision > 9007199254740991
                || !ocr.field_id.starts_with("ocr:")
                || ocr.field_id.len() > 96
                || ocr.document_bytes > 33554432
                || [&ocr.representation_revision, &ocr.text_revision]
                    .iter()
                    .any(|r| {
                        r.len() != 71
                            || !r.starts_with("sha256:")
                            || !r[7..].bytes().all(|b| b.is_ascii_hexdigit())
                    })
            {
                return Err("invalid OCR artifact identity");
            }
            match command {
                ClipboardPresentationCommand::PresentationOcrCorrect {
                    clip_id,
                    expected_revision,
                    ..
                } if ocr.clip_id == *clip_id && ocr.revision == *expected_revision => {}
                ClipboardPresentationCommand::PresentationOcrStatus {
                    clip_id,
                    expected_revision,
                    ..
                } if ocr.clip_id == *clip_id && ocr.revision == *expected_revision => {}
                ClipboardPresentationCommand::PresentationPreviewOcrAppend {
                    eof: true, ..
                } => {}
                _ => return Err("unrelated OCR artifact projection"),
            }
        }

        if let ClipboardPresentationCommand::PresentationDocumentFind {
            clip_id,
            expected_revision,
            representation_revision,
            after_utf8,
            before_utf8,
            ..
        } = command
        {
            if self.document_range.is_some() {
                return Err("find contains unrelated text projection");
            }
            if !self.ok {
                return if self.document_find.is_none() {
                    Ok(())
                } else {
                    Err("document error contains content")
                };
            }
            let found = self
                .document_find
                .as_ref()
                .ok_or("missing document find response")?;
            let result = &found.result;
            if found.clip_id != *clip_id
                || found.revision != *expected_revision
                || found.representation_revision.len() != 71
                || !found.representation_revision.starts_with("sha256:")
                || !found.representation_revision[7..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                || representation_revision
                    .as_ref()
                    .is_some_and(|r| r != &found.representation_revision)
                || result.matches.len() > 32
                || !result.complete
                || result.coordinate_unit != "utf8_bytes"
                || result.semantics_version != "1"
                || result.has_more != result.next_offset.is_some()
                || result.next_offset.is_some_and(|n| {
                    n > 67108864 || before_utf8.map_or(n <= *after_utf8, |before| n >= before)
                })
                || result.matches.iter().any(|m| {
                    before_utf8.map_or(m.start < *after_utf8, |before| m.start >= before)
                        || m.start >= m.end
                        || m.end > 67108864
                        || m.utf16_start >= m.utf16_end
                        || m.utf16_end > 67108864
                        || m.actual_text.len() as u64 != m.end - m.start
                })
                || result.matches.windows(2).any(|m| {
                    if before_utf8.is_some() {
                        m[1].start > m[0].start
                    } else {
                        m[1].start < m[0].start
                    }
                })
            {
                return Err("invalid document find ranges or identity");
            }
            return Ok(());
        }
        if self.document_find.is_some() {
            return Err("unrelated find projection");
        }
        let ClipboardPresentationCommand::PresentationDocumentRead {
            clip_id,
            expected_revision,
            offset,
            max_bytes,
            representation_revision,
            ..
        } = command
        else {
            return if self.document_range.is_some() {
                Err("unrelated document projection")
            } else {
                Ok(())
            };
        };
        if !self.ok {
            return if self.document_range.is_none() {
                Ok(())
            } else {
                Err("document error contains content")
            };
        }
        let range = self
            .document_range
            .as_ref()
            .ok_or("document response is missing")?;
        if range.clip_id != *clip_id
            || range.revision != *expected_revision
            || range.offset != *offset
            || range.total_bytes > 67108864
            || range.text.len() > *max_bytes as usize
            || range
                .offset
                .checked_add(range.text.len() as u64)
                .is_none_or(|end| {
                    end > range.total_bytes || range.eof != (end == range.total_bytes)
                })
            || (range.text.is_empty() && !range.eof)
            || range.representation_revision.len() != 71
            || !range.representation_revision.starts_with("sha256:")
            || !range.representation_revision[7..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || representation_revision
                .as_ref()
                .is_some_and(|expected| expected != &range.representation_revision)
        {
            return Err("document response identity or range is invalid");
        }
        Ok(())
    }
    pub fn has_preview_projection(&self) -> bool {
        self.preview_capabilities.is_some()
            || self.preview_grant.is_some()
            || self.preview_chunk.is_some()
            || self.preview_closed.is_some()
    }

    /// Exact command projection prevents unrelated private fields crossing a
    /// metadata-only close/capability route, including future additive fields.
    pub fn validate_preview_for(
        &self,
        command: &ClipboardPresentationCommand,
        request_id: Uuid,
    ) -> Result<(), &'static str> {
        command.validate()?;
        self.validate_for(request_id)?;
        if self.message.is_some()
            || self.error_code.as_ref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 96
                    || !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            })
        {
            return Err("clipboard preview response contains non-machine diagnostics");
        }
        if !command.is_preview_command() {
            return Err("clipboard preview command is invalid");
        }
        let encoded =
            serde_json::to_value(self).map_err(|_| "clipboard preview response is invalid")?;
        for (key, value) in encoded
            .as_object()
            .ok_or("clipboard preview response is invalid")?
        {
            if !value.is_null()
                && !matches!(
                    key.as_str(),
                    "protocol"
                        | "request_id"
                        | "ok"
                        | "error_code"
                        | "message"
                        | "presentation_version"
                        | "preview_capabilities"
                        | "preview_grant"
                        | "preview_chunk"
                        | "preview_closed"
                )
            {
                return Err("clipboard preview response contains unrelated content");
            }
        }
        if !self.ok {
            if self.has_preview_projection() {
                return Err("clipboard preview error contains a success projection");
            }
            return Ok(());
        }
        let projection = (
            self.preview_capabilities.is_some(),
            self.preview_grant.is_some(),
            self.preview_chunk.is_some(),
            self.preview_closed.is_some(),
        );
        let expected = match command {
            ClipboardPresentationCommand::PresentationPreviewCapabilities => {
                (true, false, false, false)
            }
            ClipboardPresentationCommand::PresentationPreviewOpen { .. }
            | ClipboardPresentationCommand::PresentationPreviewValidate { .. } => {
                (false, true, false, false)
            }
            ClipboardPresentationCommand::PresentationPreviewRead { .. } => {
                (false, false, true, false)
            }
            ClipboardPresentationCommand::PresentationPreviewClose { .. } => {
                (false, false, false, true)
            }
            _ => return Err("clipboard preview command is invalid"),
        };
        if projection != expected {
            return Err("clipboard preview response projection is invalid");
        }
        match command {
            ClipboardPresentationCommand::PresentationPreviewOpen {
                view_id,
                operation_id,
                consumer_window,
                item,
            } => {
                let grant = self
                    .preview_grant
                    .as_ref()
                    .ok_or("clipboard preview grant is missing")?;
                if grant.view_id != *view_id
                    || grant.operation_id != *operation_id
                    || grant.consumer_window != *consumer_window
                    || grant.item != *item
                {
                    return Err("clipboard preview grant does not match its request");
                }
            }
            ClipboardPresentationCommand::PresentationPreviewValidate { view_id, grant_id } => {
                let grant = self
                    .preview_grant
                    .as_ref()
                    .ok_or("clipboard preview grant is missing")?;
                if grant.view_id != *view_id || grant.grant_id != *grant_id {
                    return Err("clipboard preview validation identity changed");
                }
            }
            ClipboardPresentationCommand::PresentationPreviewRead {
                view_id,
                grant_id,
                offset,
                max_bytes,
            } => {
                use base64::{engine::general_purpose::STANDARD, Engine};
                let chunk = self
                    .preview_chunk
                    .as_ref()
                    .ok_or("clipboard preview chunk is missing")?;
                if chunk.view_id != *view_id
                    || chunk.grant_id != *grant_id
                    || chunk.offset != *offset
                {
                    return Err("clipboard preview chunk identity changed");
                }
                let bytes = zeroize::Zeroizing::new(
                    STANDARD
                        .decode(&chunk.data_base64)
                        .map_err(|_| "clipboard preview chunk is malformed")?,
                );
                if bytes.len() as u64 != u64::from(*max_bytes).min(chunk.total_bytes - chunk.offset)
                {
                    return Err(
                        "clipboard preview chunk does not satisfy its exact requested range",
                    );
                }
            }
            ClipboardPresentationCommand::PresentationPreviewClose { operation_id } => {
                if self
                    .preview_closed
                    .as_ref()
                    .is_none_or(|closed| closed.operation_id != *operation_id || !closed.closed)
                {
                    return Err("clipboard preview close identity changed");
                }
            }
            ClipboardPresentationCommand::PresentationPreviewCapabilities => {}
            _ => return Err("clipboard preview command is invalid"),
        }
        Ok(())
    }

    /// Drag control replies never carry presentation bodies, paths or titles,
    /// including after ordinary view blur. Check future additive fields too.
    pub fn validate_drag_for(
        &self,
        command: &ClipboardPresentationCommand,
        request_id: Uuid,
    ) -> Result<(), &'static str> {
        self.validate_for(request_id)?;
        let expected = match command {
            ClipboardPresentationCommand::PresentationDragCapabilities
            | ClipboardPresentationCommand::PresentationDragProvenanceCapabilities => None,
            ClipboardPresentationCommand::PresentationDragStart { operation_id, .. }
            | ClipboardPresentationCommand::PresentationDragStatus { operation_id }
            | ClipboardPresentationCommand::PresentationDragCancel { operation_id }
            | ClipboardPresentationCommand::PresentationDragVerifyOffer { operation_id, .. } => {
                Some(*operation_id)
            }
            _ => return Err("clipboard drag command is invalid"),
        };
        let encoded =
            serde_json::to_value(self).map_err(|_| "clipboard drag response is invalid")?;
        for (key, value) in encoded
            .as_object()
            .ok_or("clipboard drag response is invalid")?
        {
            if !value.is_null()
                && !matches!(
                    key.as_str(),
                    "protocol"
                        | "request_id"
                        | "ok"
                        | "error_code"
                        | "message"
                        | "presentation_version"
                        | "drag_capabilities"
                        | "drag_receipt"
                        | "generated_drag_offer"
                )
            {
                return Err("clipboard drag response contains unrelated content");
            }
        }
        if self.ok {
            if let ClipboardPresentationCommand::PresentationDragVerifyOffer {
                operation_id,
                lease_id,
                target_window,
                paths,
            } = command
            {
                if self.drag_capabilities.is_some()
                    || self.drag_receipt.is_some()
                    || self.generated_drag_offer.as_ref().is_none_or(|offer| {
                        offer.operation_id != *operation_id
                            || offer.lease_id != *lease_id
                            || offer.target_window != *target_window
                            || usize::from(offer.offered_count) != paths.len()
                    })
                {
                    return Err("generated drag offer identity is invalid");
                }
                return Ok(());
            }
            if self.generated_drag_offer.is_some() {
                return Err("clipboard drag reply contains an unrelated offer");
            }
            if let Some(operation_id) = expected {
                if self
                    .drag_receipt
                    .as_ref()
                    .is_none_or(|r| r.operation_id != operation_id)
                    || self.drag_capabilities.is_some()
                {
                    return Err("clipboard drag receipt identity is invalid");
                }
            } else if self.drag_capabilities.is_none() || self.drag_receipt.is_some() {
                return Err("clipboard drag capability projection is invalid");
            }
        } else if self.drag_capabilities.is_some()
            || self.drag_receipt.is_some()
            || self.generated_drag_offer.is_some()
        {
            return Err("clipboard drag error contains a success projection");
        }
        Ok(())
    }
    /// Settings transport never admits clipboard presentation data, even if a
    /// future provider accidentally attaches an otherwise valid content field.
    pub fn validate_settings_for(
        &self,
        command: &ClipboardPresentationCommand,
        request_id: Uuid,
    ) -> Result<(), &'static str> {
        self.validate_for(request_id)?;
        if !command.is_settings_command()
            || self.has_preview_projection()
            || self.view.is_some()
            || self.page.is_some()
            || self.receipt.is_some()
            || self.hotkey_state.is_some()
            || self.queue_current.is_some()
            || self.queue_selection.is_some()
            || self.collection_change.is_some()
            || self.reuse_settings.is_some()
            || self.reuse_offer.is_some()
            || self.reuse_acceptance.is_some()
            || self.smart_packs.is_some()
            || self.capture_sessions.is_some()
            || self.session_output.is_some()
            || self.drafts.is_some()
            || self.draft_preview.is_some()
            || self.clip_metadata.is_some()
            || self.source_references.is_some()
            || self.source_reference_change.is_some()
            || self.source_location.is_some()
            || self.deleted_clips.is_some()
            || self.color_change.is_some()
            || self.semantic.is_some()
            || self.captured_files.is_some()
            || self.created_clip.is_some()
            || self.archive_operation.is_some()
            || self.favorite_slots.is_some()
            || self.drag_capabilities.is_some()
            || self.drag_receipt.is_some()
            || self.generated_drag_offer.is_some()
        {
            return Err("settings response contains unrelated presentation data");
        }
        let expected = if !self.ok {
            (false, false, false)
        } else {
            match command {
                ClipboardPresentationCommand::SettingsRead => (true, false, false),
                ClipboardPresentationCommand::SettingsValidate { .. } => (false, true, false),
                ClipboardPresentationCommand::SettingsPrepare { .. }
                | ClipboardPresentationCommand::SettingsCommit { .. }
                | ClipboardPresentationCommand::SettingsStatus { .. }
                | ClipboardPresentationCommand::SettingsCompensate { .. } => (false, false, true),
                _ => return Err("settings command is invalid"),
            }
        };
        if (
            self.settings_snapshot.is_some(),
            self.settings_validation.is_some(),
            self.settings_receipt.is_some(),
        ) != expected
        {
            return Err("settings response projection does not match its command");
        }
        if let (
            Some(receipt),
            ClipboardPresentationCommand::SettingsPrepare {
                operation_id,
                digest,
                ..
            }
            | ClipboardPresentationCommand::SettingsCommit {
                operation_id,
                digest,
            }
            | ClipboardPresentationCommand::SettingsStatus {
                operation_id,
                digest,
            }
            | ClipboardPresentationCommand::SettingsCompensate {
                operation_id,
                digest,
            },
        ) = (&self.settings_receipt, command)
        {
            if receipt.operation_id != *operation_id || receipt.digest != *digest {
                return Err("settings receipt operation does not match its command");
            }
        }
        Ok(())
    }

    pub fn validate_for(&self, request_id: Uuid) -> Result<(), &'static str> {
        if self.preview_capabilities.as_ref().is_some_and(|caps| {
            caps.version != 1
                || caps.maximum_grants != 2
                || caps.maximum_source_bytes != 67108864
                || caps.maximum_chunk_bytes != 65536
                || caps.lease_seconds != 30
        }) {
            return Err("clipboard preview capabilities exceed their bounds");
        }
        if let Some(grant) = &self.preview_grant {
            grant.validate()?;
        }
        if let Some(chunk) = &self.preview_chunk {
            chunk.validate()?;
        }
        if self
            .preview_closed
            .as_ref()
            .is_some_and(|closed| closed.operation_id.is_nil() || !closed.closed)
        {
            return Err("clipboard preview close is invalid");
        }
        if let Some(offer) = &self.generated_drag_offer {
            let mut ordinals = BTreeSet::new();
            let mut source_ordinals = BTreeSet::new();
            if offer.operation_id.is_nil()
                || offer.lease_id.is_nil()
                || offer.producer_pid == 0
                || offer.producer_birth == 0
                || offer.target_window == 0
                || offer.target_window > i64::MAX as u64
                || !(1..=500).contains(&offer.offered_count)
                || offer.generated_files.is_empty()
                || offer.generated_files.len() > usize::from(offer.offered_count)
                || offer.generated_files.iter().any(|file| {
                    file.ordinal >= offer.offered_count
                        || !ordinals.insert(file.ordinal)
                        || file.bytes > 67108864
                        || file.identity.len() != 48
                        || !file.identity.bytes().all(|b| b.is_ascii_hexdigit())
                })
                || offer
                    .generated_files
                    .iter()
                    .map(|file| file.bytes)
                    .sum::<u64>()
                    > 67108864
                || !(1..=2).contains(&offer.generated_offer_version)
                || (offer.generated_offer_version == 1 && !offer.source_references.is_empty())
                || (offer.generated_offer_version == 2
                    && (offer.source_references.len() != offer.generated_files.len()
                        || offer.source_references.iter().any(|source| {
                            source.ordinal >= offer.offered_count
                                || !source_ordinals.insert(source.ordinal)
                                || source.clip_id.is_nil()
                                || source.occurrence_id.is_nil()
                                || source.expected_revision == 0
                                || source.expected_revision > i64::MAX as u64
                                || source.queue_item_id.is_some_and(|id| id.is_nil())
                        })
                        || source_ordinals != ordinals))
            {
                return Err("generated drag offer bounds are invalid");
            }
        }
        if self.drag_capabilities.as_ref().is_some_and(|c| {
            c.version != 1
                || c.maximum_items != 100
                || c.maximum_source_bytes != 67108864
                || c.file_lease_seconds != 3600
        }) {
            return Err("clipboard drag capability bounds are invalid");
        }
        if self.drag_receipt.as_ref().is_some_and(|r| {
            r.operation_id.is_nil()
                || r.revision == 0
                || !(1..=100).contains(&r.item_count)
                || r.file_lease_seconds != 3600
                || !matches!(
                    r.state.as_str(),
                    "queued" | "dragging" | "dropped" | "cancelled" | "failed" | "expired"
                )
                || !matches!(
                    r.mode.as_str(),
                    "text_only" | "files_only" | "native" | "text_and_files"
                )
                || r.error_code.as_ref().is_some_and(|s| {
                    s.is_empty()
                        || s.len() > 96
                        || !s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })
                || (r.state == "failed") != r.error_code.is_some()
        }) {
            return Err("clipboard drag receipt bounds are invalid");
        }
        if self.request_id != request_id
            || !self
                .protocol
                .is_compatible_with(CLIPBOARD_PROVIDER_PROTOCOL_VERSION)
            || (self.ok
                && (self.presentation_version != Some(CLIPBOARD_PRESENTATION_VERSION)
                    || self.error_code.is_some()))
            || (!self.ok && self.error_code.as_deref().is_none_or(str::is_empty))
        {
            return Err("presentation response identity is invalid");
        }
        if let Some(view) = &self.view {
            if view.id.is_nil() {
                return Err("presentation grant identity is invalid");
            }
            if view.open_intent.as_ref().is_some_and(|intent| {
                !matches!(intent.action.as_str(), "search" | "read" | "copy")
                    || intent.mode != "all_words"
                    || intent.query.len() > 2048
                    || !matches!(
                        intent.section.as_str(),
                        "recent" | "pinned" | "packs" | "queue"
                    )
                    || intent.clip_id.is_some_and(|id| id.is_nil())
                    || intent.occurrence_id.is_some_and(|id| id.is_nil())
                    || intent.clip_id.is_some() != intent.expected_revision.is_some()
                    || intent
                        .expected_revision
                        .is_some_and(|r| r == 0 || r > 9007199254740991)
                    || intent
                        .legacy_group_id
                        .is_some_and(|id| id > 9007199254740991)
                    || (intent.action != "search"
                        && (intent.clip_id.is_none() || intent.occurrence_id.is_none()))
            }) {
                return Err("native search handoff is invalid");
            }
        }
        if let Some(snapshot) = &self.settings_snapshot {
            snapshot.validate()?;
        }
        if let Some(validation) = &self.settings_validation {
            if !settings_hash_valid(&validation.digest)
                || !settings_hash_valid(&validation.current_revision)
                || validation.errors.len() > 16
                || validation.valid != validation.errors.is_empty()
                || validation
                    .errors
                    .iter()
                    .any(|e| e.setting_id.len() > 64 || e.code != "invalid_value")
            {
                return Err("native settings validation identity is invalid");
            }
            validation.normalized_patch.validate()?;
        }
        if let Some(receipt) = &self.settings_receipt {
            receipt.validate()?;
        }
        if let Some(slots) = &self.favorite_slots {
            if slots.len() != 10
                || slots.iter().enumerate().any(|(i, slot)| {
                    slot.slot as usize != i + 1
                        || slot.revision == 0
                        || slot.clip_id.is_some_and(|id| id.is_nil())
                        || validate_favorite_customization(
                            slot.title_override.as_deref(),
                            slot.icon_token.as_deref(),
                            slot.color_token.as_deref(),
                        )
                        .is_err()
                })
            {
                return Err("favorite projection is invalid");
            }
        }
        if self.archive_operation.as_ref().is_some_and(|o| {
            o.operation_id.is_nil()
                || o.revision == 0
                || !matches!(o.action.as_str(), "import" | "export")
                || !matches!(
                    o.state.as_str(),
                    "choosing"
                        | "awaiting_authorization"
                        | "queued"
                        | "working"
                        | "completed"
                        | "cancelled"
                        | "failed"
                        | "expired"
                )
                || o.clip_count > 100
                || o.format_count > 12800
                || o.byte_count > 64 * 1024 * 1024
                || o.error_code.as_ref().is_some_and(|code| {
                    code.len() > 64 || !code.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                })
        }) {
            return Err("native archive operation status exceeds its bounds");
        }
        if let Some(page) = &self.captured_files {
            let end = page.offset.saturating_add(page.items.len() as u32);
            if page.clip_id.is_nil()
                || page.revision == 0
                || page.total_files == 0
                || page.total_files > 1000
                || page.offset > page.total_files
                || end > page.total_files
                || page.items.len() > 100
                || (page.items.is_empty() && page.offset < page.total_files)
                || page.next_offset != (end < page.total_files).then_some(end)
                || page.items.iter().enumerate().any(|(i, f)| {
                    f.ordinal != page.offset + i as u32
                        || f.path.is_empty()
                        || f.path.contains('\0')
                        || f.path.chars().count() > 32767
                })
                || page.items.iter().map(|f| f.path.len()).sum::<usize>() > 200000
            {
                return Err("captured file page exceeds its bounds");
            }
        }
        if self.created_clip.as_ref().is_some_and(|c| {
            c.id.is_nil()
                || c.source_clip_id.is_nil()
                || c.revision == 0
                || c.id == c.source_clip_id
        }) {
            return Err("created native clip identity is invalid");
        }
        if self.drafts.as_ref().is_some_and(|drafts| {
            drafts.len() > 100
                || drafts.iter().any(|d| {
                    d.id.is_nil()
                        || d.revision == 0
                        || d.name.len() > 256
                        || d.separator.len() > 256
                        || d.fragment_count > 1000
                        || d.published_clip_id.is_some_and(|id| id.is_nil())
                        || !matches!(
                            d.state.as_str(),
                            "active" | "stopped" | "published" | "archived"
                        )
                })
        }) {
            return Err("draft summaries exceed their bounds");
        }
        if self.draft_preview.as_ref().is_some_and(|p| {
            p.draft_id.is_nil()
                || p.excerpt.chars().count() > 240
                || p.byte_count > 1024 * 1024
                || !matches!(
                    p.content_state.as_str(),
                    "ready"
                        | "empty"
                        | "source_unavailable"
                        | "source_changed"
                        | "unsupported"
                        | "too_large"
                )
                || (p.content_state != "ready" && (!p.excerpt.is_empty() || p.byte_count != 0))
        }) {
            return Err("draft preview exceeds its bounds");
        }
        if let Some(p) = &self.draft_preview {
            if let Some(text) = &p.text {
                let start = p.offset.ok_or("missing draft chunk offset")?;
                let end = u64::from(start) + text.len() as u64;
                if p.revision.is_none_or(|v| v == 0 || v > i64::MAX as u64)
                    || text.len() > 65536
                    || text.contains('\0')
                    || end > u64::from(p.byte_count)
                    || !matches!(p.content_state.as_str(), "ready" | "empty")
                    || p.next_offset.map(u64::from)
                        != (if end < u64::from(p.byte_count) {
                            Some(end)
                        } else {
                            None
                        })
                    || (text.is_empty() && end < u64::from(p.byte_count))
                    || p.representation_revision.as_ref().is_none_or(|v| {
                        v.len() != 71 || !v.starts_with("sha256:") || !settings_hash_valid(&v[7..])
                    })
                {
                    return Err("draft chunk bounds or identity are invalid");
                }
            } else if p.revision.is_some()
                || p.representation_revision.is_some()
                || p.offset.is_some()
                || p.next_offset.is_some()
            {
                return Err("draft metadata contains partial reader authority");
            }
        }
        if self.capture_sessions.as_ref().is_some_and(|sessions| {
            sessions.len() > 100
                || sessions.iter().any(|s| {
                    s.id.is_nil()
                        || s.revision == 0
                        || s.pack_id.is_some_and(|id| id.is_nil())
                        || !matches!(s.state.as_str(), "active" | "stopped" | "expired")
                        || s.inactivity_timeout_seconds
                            .is_some_and(|v| !(60..=86400).contains(&v))
                })
        }) {
            return Err("capture sessions exceed their bounds");
        }
        if self.session_output.as_ref().is_some_and(|o| {
            o.id.is_nil()
                || o.revision == 0
                || !matches!(o.kind.as_str(), "pack" | "queue")
                || !(1..=1000).contains(&o.item_count)
        }) {
            return Err("capture session output is invalid");
        }
        if let Some(packs) = &self.smart_packs {
            if packs.len() > 100
                || packs.iter().any(|p| {
                    p.id.is_nil()
                        || p.revision == 0
                        || p.name.len() > 256
                        || p.filter.validate().is_err()
                })
            {
                return Err("smart packs exceed their bounds");
            }
        }
        if self
            .reuse_settings
            .as_ref()
            .is_some_and(|s| s.policy_epoch == 0 || s.policy_epoch > 9007199254740991)
            || self.reuse_acceptance.as_ref().is_some_and(|a| {
                a.favorite_slot > 10
                    || a.pack_id.is_some_and(|id| id.is_nil())
                    || a.pack_id.is_some() != (a.pack_revision > 0)
                    || (a.favorite_slot > 0 && a.pack_id.is_some())
            })
            || self.reuse_offer.as_ref().is_some_and(|o| {
                o.id.len() != 32
                    || !o.id.bytes().all(|b| b.is_ascii_hexdigit())
                    || o.candidate_id.is_empty()
                    || o.candidate_id.len() > 128
                    || !matches!(o.kind.as_str(), "favorite" | "pack")
                    || o.policy_epoch == 0
                    || o.policy_epoch > 9007199254740991
                    || o.favorite_slot > 10
                    || o.local_dates < 3
                    || (o.kind == "favorite"
                        && (o.items.len() != 1
                            || o.favorite_slot == 0
                            || o.favorite_slot_revision == 0
                            || o.uses < 5))
                    || (o.kind == "pack"
                        && (!(2..=6).contains(&o.items.len())
                            || o.favorite_slot != 0
                            || o.uses < 3))
                    || o.items.iter().any(|i| {
                        i.id.is_nil()
                            || i.revision == 0
                            || i.title.chars().count() > 80
                            || i.title.len() > 320
                    })
            })
        {
            return Err("reuse projection exceeds its qualified bounds");
        }
        if let Some(selection) = &self.queue_selection {
            if selection.queue_id.is_some_and(|id| id.is_nil())
                || !settings_hash_valid(&selection.owner_revision)
            {
                return Err("active queue selection is invalid");
            }
        }
        if let Some(queue) = &self.queue_current {
            if queue.queue_id.is_nil()
                || queue.queue_revision == 0
                || queue.item_id.is_some() != queue.clip_id.is_some()
                || queue.item_id.is_some_and(|id| id.is_nil())
                || queue.clip_id.is_some_and(|id| id.is_nil())
                || !matches!(
                    queue.state.as_str(),
                    "active" | "paused" | "completed" | "archived"
                )
                || !matches!(queue.mode.as_str(), "fifo" | "lifo" | "manual")
            {
                return Err("current queue identity is invalid");
            }
        }
        if let Some(receipt) = &self.receipt {
            if receipt.operation_id.is_nil()
                || (receipt.queue_advanced
                    && !matches!(
                        receipt.state,
                        ClipboardPublicationState::Published
                            | ClipboardPublicationState::InputDispatched
                    ))
            {
                return Err("presentation publication receipt is invalid");
            }
        }
        if let Some(page) = &self.page {
            if page.search_progress.as_ref().is_some_and(|p| {
                !matches!(p.stage.as_str(), "indexing" | "grouping" | "ready")
                    || !matches!(
                        p.approximate_coverage.as_str(),
                        "ready" | "limited" | "unavailable"
                    )
                    || p.indexed_clips > p.total_clips
                    || p.total_clips > 100_000
                    || p.limited_clips > p.indexed_clips
                    || (p.stage == "ready" && p.indexed_clips != p.total_clips)
                    || (p.stage != "ready"
                        && (page.has_more || (!page.items.is_empty() && p.indexed_clips == 0)))
            }) {
                return Err("presentation search progress is invalid");
            }
            if page.items.len() > CLIPBOARD_PRESENTATION_MAX_ITEMS as usize
                || page.items.iter().any(|i| {
                    i.id.is_nil()
                        || i.queue_item_id.is_some_and(|id| id.is_nil())
                        || i.queue_item_id.is_some() != i.queue_item_state.is_some()
                        || i.queue_item_state.as_ref().is_some_and(|s| {
                            !matches!(s.as_str(), "pending" | "active" | "completed" | "skipped")
                        })
                        || i.occurrence_id.is_nil()
                        || i.revision == 0
                        || i.excerpt.chars().count() > 240
                        || i.search_match.as_ref().is_some_and(|m| {
                            m.matched_query.len() > 16384
                                || m.match_kind.as_ref().is_some_and(|kind| {
                                    !matches!(kind.as_str(), "source" | "recall_name" | "typo")
                                        || (kind == "recall_name"
                                            && (m.field_id != "recall_name"
                                                || m.query_mode != "all_words"
                                                || m.typo))
                                        || (kind == "typo" && !m.typo)
                                })
                                || !matches!(
                                    m.query_mode.as_str(),
                                    "all_words" | "literal" | "source_phrase" | "prefix"
                                )
                                || m.field_id.is_empty()
                                || m.field_id.len() > 128
                                || m.representation_revision.len() != 71
                                || !m.representation_revision.starts_with("sha256:")
                                || !m.representation_revision[7..]
                                    .bytes()
                                    .all(|b| b.is_ascii_hexdigit())
                                || m.start > m.end
                                || m.end > 67108864
                                || m.end - m.start != i.excerpt.len() as u64
                                || m.highlights.len() > 32
                                || m.highlights.iter().any(|h| {
                                    h.start >= h.end
                                        || h.end > i.excerpt.len() as u64
                                        || !i.excerpt.is_char_boundary(h.start as usize)
                                        || !i.excerpt.is_char_boundary(h.end as usize)
                                })
                        })
                        || i.kind.len() > 64
                        || i.tags.len() > 32
                        || i.tags.iter().any(|tag| tag.chars().count() > 64)
                        || i.tag_group_id.as_ref().is_some_and(|id| {
                            id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                        || i.related_group.as_ref().is_some_and(|g| {
                            g.id.len() != 64
                                || !g.id.bytes().all(|b| b.is_ascii_hexdigit())
                                || g.seed_clip_id.is_nil()
                                || g.matching_clips == 0
                                || g.matching_clips > g.matching_occurrences
                                || g.matching_occurrences > page.snapshot_sequence
                        })
                        || i.source_application
                            .as_ref()
                            .is_some_and(|s| s.chars().count() > 256)
                        || i.source_executable_path
                            .as_ref()
                            .is_some_and(|s| s.len() > 4096 || s.chars().any(char::is_control))
                        || i.source_attribution_confidence.as_deref().is_some_and(|v| {
                            !matches!(v, "unknown" | "exact_owner" | "foreground_candidate")
                        })
                        || (i.source_attribution_confidence.as_deref() == Some("unknown")
                            && i.source_executable_path.is_some())
                })
            {
                return Err("presentation page exceeds its bounds");
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ClipboardPresentationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardPresentationResponse")
            .field("ok", &self.ok)
            .field("item_count", &self.page.as_ref().map(|p| p.items.len()))
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardProviderSection {
    Recent,
    Pinned,
    Pack,
    Queue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasteQueueMode {
    Fifo,
    Lifo,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasteQueueAction {
    Pause,
    Resume,
    Back,
    Skip,
    Loop,
    Stop,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClipboardProviderCommand {
    Health,
    // Explicit opt-in: the legacy health response must remain byte-shape
    // compatible with older strict Shelf clients during paired upgrades.
    HealthQueueCapabilities,
    ListRecent {
        section: ClipboardProviderSection,
        query: Option<String>,
        pack_id: Option<Uuid>,
        queue_id: Option<Uuid>,
        limit: u16,
    },
    ListFavorites,
    ListPacks,
    ListQueues,
    SetPin {
        clip_id: Uuid,
        expected_revision: u64,
        value: bool,
    },
    SetFavorite {
        slot: u8,
        expected_revision: u64,
        clip_id: Option<Uuid>,
    },
    CreatePack {
        name: String,
    },
    AddToPack {
        pack_id: Uuid,
        expected_revision: u64,
        clip_ids: Vec<Uuid>,
    },
    CreateQueue {
        name: Option<String>,
        mode: PasteQueueMode,
        clip_ids: Vec<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<Uuid>,
    },
    QueueControl {
        queue_id: Uuid,
        expected_revision: u64,
        item_id: Option<Uuid>,
        action: PasteQueueAction,
        value: Option<bool>,
    },
    PublishClipboard {
        clip_id: Uuid,
        expected_revision: u64,
        value: bool,
    },
    OpenQuickPaste,
    PauseCapture {
        value: bool,
        duration_seconds: Option<u32>,
    },
    IgnoreNextCopy {
        value: bool,
        expected_revision: u64,
        operation_id: Uuid,
    },
}

impl ClipboardProviderCommand {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Health
            | Self::HealthQueueCapabilities
            | Self::ListFavorites
            | Self::ListPacks
            | Self::ListQueues
            | Self::OpenQuickPaste => Ok(()),
            Self::ListRecent {
                section,
                query,
                pack_id,
                queue_id,
                limit,
            } => {
                if !(1..=CLIPBOARD_PROVIDER_MAX_PAGE_ITEMS).contains(limit) {
                    return Err("clipboard provider page limit must be between 1 and 500");
                }
                if query
                    .as_ref()
                    .is_some_and(|value| value.chars().count() > CLIPBOARD_PROVIDER_MAX_QUERY_CHARS)
                {
                    return Err("clipboard provider query exceeds 1024 characters");
                }
                match section {
                    ClipboardProviderSection::Recent | ClipboardProviderSection::Pinned
                        if pack_id.is_none() && queue_id.is_none() =>
                    {
                        Ok(())
                    }
                    ClipboardProviderSection::Pack
                        if pack_id.is_some_and(|id| !id.is_nil()) && queue_id.is_none() =>
                    {
                        Ok(())
                    }
                    ClipboardProviderSection::Queue
                        if queue_id.is_some_and(|id| !id.is_nil()) && pack_id.is_none() =>
                    {
                        Ok(())
                    }
                    _ => Err("clipboard provider section filter IDs are inconsistent"),
                }
            }
            Self::SetPin { clip_id, .. } | Self::PublishClipboard { clip_id, .. } => {
                validate_uuid(*clip_id, "clipboard clip ID")
            }
            Self::SetFavorite { slot, clip_id, .. } => {
                if !(1..=10).contains(slot) {
                    return Err("Quick Favorite slot must be between 1 and 10");
                }
                if clip_id.is_some_and(|id| id.is_nil()) {
                    return Err("clipboard clip ID must not be nil");
                }
                Ok(())
            }
            Self::CreatePack { name } => validate_name(name, "Clipboard Creator Pack name"),
            Self::AddToPack {
                pack_id, clip_ids, ..
            } => {
                validate_uuid(*pack_id, "Clipboard Creator Pack ID")?;
                validate_clip_ids(clip_ids)
            }
            Self::CreateQueue {
                name,
                clip_ids,
                operation_id,
                ..
            } => {
                if let Some(value) = name {
                    validate_name(value, "Paste Queue name")?;
                }
                if operation_id.is_some_and(|id| id.is_nil()) {
                    return Err("Paste Queue operation ID must not be nil");
                }
                validate_queue_clip_ids(clip_ids)
            }
            Self::QueueControl {
                queue_id,
                item_id,
                action,
                value,
                ..
            } => {
                validate_uuid(*queue_id, "Paste Queue ID")?;
                if item_id.is_some_and(|id| id.is_nil()) {
                    return Err("Paste Queue item ID must not be nil");
                }
                if matches!(action, PasteQueueAction::Skip) && item_id.is_none() {
                    return Err("Paste Queue skip requires an item ID");
                }
                if matches!(action, PasteQueueAction::Loop) && value.is_none() {
                    return Err("Paste Queue loop requires a value");
                }
                Ok(())
            }
            Self::PauseCapture {
                value,
                duration_seconds,
            } => {
                if !value && duration_seconds.is_some() {
                    return Err("capture resume must not include a duration");
                }
                if duration_seconds.is_some_and(|seconds| !(1..=86_400).contains(&seconds)) {
                    return Err("capture pause duration must be between 1 second and 24 hours");
                }
                Ok(())
            }
            Self::IgnoreNextCopy {
                expected_revision,
                operation_id,
                ..
            } => {
                if *expected_revision == 0
                    || *expected_revision > i64::MAX as u64
                    || operation_id.is_nil()
                {
                    return Err("ignore-next capture identity is invalid");
                }
                Ok(())
            }
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::HealthQueueCapabilities => "health_queue_capabilities",
            Self::ListRecent { .. } => "list_recent",
            Self::ListFavorites => "list_favorites",
            Self::ListPacks => "list_packs",
            Self::ListQueues => "list_queues",
            Self::SetPin { .. } => "set_pin",
            Self::SetFavorite { .. } => "set_favorite",
            Self::CreatePack { .. } => "create_pack",
            Self::AddToPack { .. } => "add_to_pack",
            Self::CreateQueue { .. } => "create_queue",
            Self::QueueControl { .. } => "queue_control",
            Self::PublishClipboard { .. } => "publish_clipboard",
            Self::OpenQuickPaste => "open_quick_paste",
            Self::PauseCapture { .. } => "pause_capture",
            Self::IgnoreNextCopy { .. } => "ignore_next_copy",
        }
    }
}

impl fmt::Debug for ClipboardProviderCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardProviderCommand")
            .field("kind", &self.kind_name())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardCapturePipelineStatus {
    pub loaded: u64,
    pub enqueued: u64,
    pub ignored: u64,
    pub save_attempts: u64,
    pub save_successes: u64,
    pub occurrence_commits: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProviderStatus {
    pub provider_id: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub process_id: u32,
    pub session_id: String,
    pub provider_revision: u64,
    pub capture_paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_create_idempotent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_pipeline: Option<ClipboardCapturePipelineStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_next_copy: Option<ClipboardIgnoreNextState>,
    pub database_healthy: bool,
    pub locked: bool,
    pub captured_count: u64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardIgnoreNextState {
    pub armed: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<Uuid>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProviderClip {
    pub id: Uuid,
    pub revision: u64,
    pub content_digest: String,
    pub kind: String,
    pub title: String,
    pub source_application: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub use_count: u64,
    pub copy_count: u64,
    pub sensitivity: String,
    pub missing_source: String,
    pub pinned_ordinal: Option<i64>,
    pub quick_favorite_slot: Option<u8>,
    pub root_original_id: Option<Uuid>,
    pub immediate_parent_id: Option<Uuid>,
    pub preferred_variant_id: Option<Uuid>,
    pub membership_ordinal: Option<i64>,
    pub queue_item_id: Option<Uuid>,
    pub queue_item_state: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProviderFavorite {
    pub slot: u8,
    pub revision: u64,
    pub clip_id: Option<Uuid>,
    pub title_override: Option<String>,
    pub preferred_variant_id: Option<Uuid>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProviderPack {
    pub id: Uuid,
    pub revision: u64,
    pub name: String,
    pub paste_order: String,
    pub capture_mode: bool,
    pub member_count: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProviderQueue {
    pub id: Uuid,
    pub revision: u64,
    pub name: String,
    pub mode: PasteQueueMode,
    pub state: String,
    pub current_index: u64,
    pub item_count: u64,
    pub loops: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClipboardProviderResponse {
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub ok: bool,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub status: Option<ClipboardProviderStatus>,
    pub clips: Option<Vec<ClipboardProviderClip>>,
    pub favorites: Option<Vec<ClipboardProviderFavorite>>,
    pub packs: Option<Vec<ClipboardProviderPack>>,
    pub queues: Option<Vec<ClipboardProviderQueue>>,
    pub queue: Option<ClipboardProviderQueue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_next_copy: Option<ClipboardIgnoreNextState>,
}

impl ClipboardProviderResponse {
    pub fn validate_for(&self, request_id: Uuid) -> Result<(), &'static str> {
        if !self
            .protocol
            .is_compatible_with(CLIPBOARD_PROVIDER_PROTOCOL_VERSION)
        {
            return Err("clipboard provider response protocol is incompatible");
        }
        if self.request_id != request_id {
            return Err("clipboard provider response request ID does not match");
        }
        if self.ok && self.error_code.is_some() {
            return Err("successful clipboard provider response contains an error code");
        }
        for state in [
            self.ignore_next_copy.as_ref(),
            self.status
                .as_ref()
                .and_then(|s| s.ignore_next_copy.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            if state.revision == 0
                || state.revision > i64::MAX as u64
                || state.armed != state.expires_at.is_some()
                || state.operation_id.is_some_and(|id| id.is_nil())
            {
                return Err("invalid ignore-next capture state");
            }
        }
        if self.ignore_next_copy.is_some()
            && (!self.ok
                || self
                    .ignore_next_copy
                    .as_ref()
                    .is_some_and(|s| s.operation_id.is_none())
                || self.status.is_some()
                || self.clips.is_some()
                || self.favorites.is_some()
                || self.packs.is_some()
                || self.queues.is_some()
                || self.queue.is_some())
        {
            return Err("ignore-next capture receipt contains unrelated content");
        }
        if !self.ok && self.error_code.as_deref().is_none_or(str::is_empty) {
            return Err("failed clipboard provider response requires an error code");
        }
        if self
            .clips
            .as_ref()
            .is_some_and(|values| values.len() > CLIPBOARD_PROVIDER_MAX_PAGE_ITEMS as usize)
        {
            return Err("clipboard provider response exceeds the page item limit");
        }
        if self
            .favorites
            .as_ref()
            .is_some_and(|values| values.len() > 10)
        {
            return Err("clipboard provider response exceeds ten Quick Favorites");
        }
        Ok(())
    }
}

impl fmt::Debug for ClipboardProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardProviderResponse")
            .field("protocol", &self.protocol)
            .field("request_id", &self.request_id)
            .field("ok", &self.ok)
            .field("error_code", &self.error_code)
            .field("status", &self.status.as_ref().map(|_| "[status]"))
            .field("clip_count", &self.clips.as_ref().map(Vec::len))
            .field("favorite_count", &self.favorites.as_ref().map(Vec::len))
            .field("pack_count", &self.packs.as_ref().map(Vec::len))
            .field("queue_count", &self.queues.as_ref().map(Vec::len))
            .finish()
    }
}

fn validate_uuid(value: Uuid, label: &'static str) -> Result<(), &'static str> {
    if value.is_nil() {
        return Err(match label {
            "clipboard clip ID" => "clipboard clip ID must not be nil",
            "Clipboard Creator Pack ID" => "Clipboard Creator Pack ID must not be nil",
            "Paste Queue ID" => "Paste Queue ID must not be nil",
            _ => "clipboard provider ID must not be nil",
        });
    }
    Ok(())
}

fn validate_name(value: &str, label: &'static str) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.chars().count() > CLIPBOARD_PROVIDER_MAX_NAME_CHARS {
        return Err(match label {
            "Clipboard Creator Pack name" => {
                "Clipboard Creator Pack name must contain 1 to 256 characters"
            }
            _ => "Paste Queue name must contain 1 to 256 characters",
        });
    }
    Ok(())
}

fn validate_clip_ids(values: &[Uuid]) -> Result<(), &'static str> {
    if values.is_empty() || values.len() > CLIPBOARD_PROVIDER_MAX_MUTATION_ITEMS {
        return Err("clipboard provider mutation requires 1 to 500 clip IDs");
    }
    if values.iter().any(Uuid::is_nil) {
        return Err("clipboard provider clip IDs must not be nil");
    }
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err("clipboard provider clip IDs must be unique");
    }
    Ok(())
}

fn validate_queue_clip_ids(values: &[Uuid]) -> Result<(), &'static str> {
    if values.is_empty() || values.len() > CLIPBOARD_PROVIDER_MAX_MUTATION_ITEMS {
        return Err("clipboard provider mutation requires 1 to 500 clip IDs");
    }
    if values.iter().any(Uuid::is_nil) {
        return Err("clipboard provider clip IDs must not be nil");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn color_label_contract_requires_exact_bounded_selection_and_receipt() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let mut value = serde_json::json!({"kind":"presentation_set_color","view_id":Uuid::new_v4(),"operation_id":operation,"color_token":"#8A30FF","clips":[{"clip_id":first,"occurrence_id":Uuid::new_v4(),"expected_revision":1},{"clip_id":second,"occurrence_id":Uuid::new_v4(),"expected_revision":4}]});
        let command: super::ClipboardPresentationCommand =
            serde_json::from_value(value.clone()).unwrap();
        assert!(command.validate().is_ok());
        assert!(command.presentation_may_mutate());
        assert!(command.presentation_view_id().is_some());
        let mut reply: super::ClipboardPresentationResponse = serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":Uuid::new_v4(),"ok":true,"presentation_version":2,"color_change":{"operation_id":operation,"clip_ids":[first,second],"color_token":"#8A30FF"}})).unwrap();
        assert!(reply.validate_document_for(&command).is_ok());
        reply.color_change.as_mut().unwrap().clip_ids.reverse();
        assert!(reply.validate_document_for(&command).is_err());
        reply.color_change.as_mut().unwrap().clip_ids.reverse();
        reply.color_change.as_mut().unwrap().color_token = "#FF0000".into();
        assert!(reply.validate_document_for(&command).is_err());
        value["color_token"] = "url(untrusted)".into();
        assert!(
            serde_json::from_value::<super::ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["color_token"] = "".into();
        assert!(
            serde_json::from_value::<super::ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        value["clips"][1]["clip_id"] = first.to_string().into();
        assert!(
            serde_json::from_value::<super::ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["clips"] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<super::ClipboardPresentationCommand>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    use super::*;

    #[test]
    fn secure_copy_is_native_only_bounded_and_subject_complete() {
        let subject = ClipboardSecureCopySubject {
            shelf_id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            expected_revision: 1,
            lock_epoch: 2,
            security_generation: 3,
        };
        let command = ClipboardSecureCopyCommand::Publish {
            operation_id: Uuid::new_v4(),
            consumer_window: 123,
            subjects: vec![subject.clone()],
            lease: ClipboardSecureCopyLease::UntilLock,
            content: ClipboardSecureCopyContent {
                format: ClipboardSecureCopyFormat::TextUtf8,
                protected_data_base64: "sealedciphertext".into(),
            },
        };
        assert!(command.validate().is_ok());
        assert!(!format!("{command:?}").contains("sealedciphertext"));
        let wire = serde_json::to_value(&command).unwrap();
        assert_eq!(wire["kind"], "secure_copy_publish");
        assert_eq!(wire["lease"], "until_lock");
        assert!(serde_json::from_value::<ClipboardProviderCommand>(wire.clone()).is_err());
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(wire.clone()).is_err());
        let mut repeated = wire.clone();
        repeated["subjects"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(&subject).unwrap());
        assert!(
            serde_json::from_value::<ClipboardSecureCopyCommand>(repeated)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut unknown = wire;
        unknown["payload"] = "must never enter this protocol".into();
        assert!(serde_json::from_value::<ClipboardSecureCopyCommand>(unknown).is_err());
        let revoke = ClipboardSecureCopyCommand::Revoke {
            operation_id: Uuid::new_v4(),
            minimum_generation: 4,
            shelf_fences: vec![ClipboardSecureCopyFence {
                shelf_id: subject.shelf_id,
                minimum_lock_epoch: 3,
            }],
        };
        assert!(revoke.validate().is_ok());
    }

    #[test]
    fn secure_copy_receipts_preserve_pending_and_error_truth() {
        let request = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let command = ClipboardSecureCopyCommand::Status {
            operation_id: operation,
        };
        let fixture = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"secure_copy_version":1,
            "ok":true,"error_code":null,"message":null,"receipt":{"operation_id":operation,"state":"unknown","clipboard_sequence":44,
            "expires_at":null,"minimum_generation":3,"revocation_complete":false}});
        let response: ClipboardSecureCopyResponse =
            serde_json::from_value(fixture.clone()).unwrap();
        assert!(response.validate_for(&command, request).is_ok());
        let mut fabricated = fixture.clone();
        fabricated["receipt"]["revocation_complete"] = true.into();
        assert!(
            serde_json::from_value::<ClipboardSecureCopyResponse>(fabricated)
                .unwrap()
                .validate_for(&command, request)
                .is_err()
        );
        let mut leaked = fixture;
        leaked["items"] = serde_json::json!([]);
        assert!(serde_json::from_value::<ClipboardSecureCopyResponse>(leaked).is_err());
        let denied = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"secure_copy_version":1,
            "ok":false,"error_code":"secure_copy_peer_rejected","message":"Native Secure Copy could not complete safely."});
        assert!(
            serde_json::from_value::<ClipboardSecureCopyResponse>(denied)
                .unwrap()
                .validate_for(&command, request)
                .is_ok()
        );
        assert!(response.validate_for(&command, Uuid::new_v4()).is_err());
    }

    #[test]
    fn secure_copy_recovery_is_exact_exclusive_and_never_infers_empty_success() {
        let request = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let command = ClipboardSecureCopyCommand::RecoveryStatus {
            operation_id: operation,
        };
        let fixture = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,
            "secure_copy_version":1,"ok":true,"recovery":{"operation_id":operation,
            "producer_pid":12,"producer_birth":34,"settled":true,"pending_producers":0,
            "pending_publications":0,"journal_ready":true}});
        let validate = |value| {
            serde_json::from_value::<ClipboardSecureCopyResponse>(value)
                .is_ok_and(|response| response.validate_for(&command, request).is_ok())
        };
        assert!(validate(fixture.clone()));
        for (key, value) in [
            ("operation_id", serde_json::json!(Uuid::new_v4())),
            ("producer_pid", serde_json::json!(0)),
            ("producer_birth", serde_json::json!(0)),
            ("pending_producers", serde_json::json!(1)),
            ("pending_publications", serde_json::json!(1)),
            ("journal_ready", serde_json::json!(false)),
        ] {
            let mut invalid = fixture.clone();
            invalid["recovery"][key] = value;
            assert!(!validate(invalid));
        }
        let mut pending = fixture.clone();
        pending["recovery"]["settled"] = false.into();
        pending["recovery"]["pending_producers"] = 1.into();
        assert!(validate(pending));
        let mut mixed = fixture.clone();
        mixed["capabilities"] = serde_json::json!({});
        assert!(!validate(mixed));
        let response: ClipboardSecureCopyResponse =
            serde_json::from_value(fixture.clone()).unwrap();
        assert!(response
            .validate_for(
                &ClipboardSecureCopyCommand::Status {
                    operation_id: operation
                },
                request
            )
            .is_err());
        let mut denied = fixture;
        denied["ok"] = false.into();
        denied["error_code"] = "unavailable".into();
        assert!(!validate(denied));
        assert!(
            serde_json::from_value::<ClipboardSecureCopyCommand>(serde_json::json!({
            "kind":"secure_copy_recovery_status","operation_id":operation,"producer_pid":12}))
            .is_err()
        );
    }

    #[test]
    fn secure_copy_release_is_metadata_acknowledgement_not_revocation_proof() {
        let request = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let command = ClipboardSecureCopyCommand::ReleaseReceipt {
            operation_id: operation,
        };
        assert!(command.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&command).unwrap()["kind"],
            "secure_copy_release_receipt"
        );
        let fixture = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"secure_copy_version":1,
            "ok":true,"receipt":{"operation_id":operation,"state":"receipt_released","clipboard_sequence":0,
            "expires_at":null,"minimum_generation":3,"revocation_complete":false}});
        let response: ClipboardSecureCopyResponse =
            serde_json::from_value(fixture.clone()).unwrap();
        assert!(response.validate_for(&command, request).is_ok());
        for (state, complete) in [
            ("receipt_released", true),
            ("revoked", true),
            ("unknown", false),
        ] {
            let mut invalid = fixture.clone();
            invalid["receipt"]["state"] = state.into();
            invalid["receipt"]["revocation_complete"] = complete.into();
            assert!(
                serde_json::from_value::<ClipboardSecureCopyResponse>(invalid)
                    .unwrap()
                    .validate_for(&command, request)
                    .is_err()
            );
        }
    }

    #[test]
    fn native_settings_capabilities_distinguish_legacy_from_supported_empty_rules() {
        let legacy = serde_json::json!({"schema_version":1,"owner_revision":"a".repeat(64),"values":{
            "check_max_entries":false,"max_entries":500,"check_expired_entries":false,"expire_days":5,
            "allow_duplicates":false,"allow_consecutive_duplicates":false,"send_paste_after_selection":true,
            "update_order_on_paste":true,"save_multi_paste":false,"multi_paste_reverse":false,
            "multi_paste_separator":"[LF]","max_clip_bytes":0,"legacy_include_apps":"*",
            "legacy_exclude_apps":"","capture_to_group_timeout_ms":1000}});
        let mut snapshot: ClipboardSettingsSnapshot = serde_json::from_value(legacy).unwrap();
        assert!(snapshot.validate().is_ok());
        assert!(snapshot.values.capture_rules.is_empty());
        assert!(!snapshot.supports_field("capture_rules"));
        for field in &CLIPBOARD_SETTINGS_FIELDS[..15] {
            assert!(snapshot.supports_field(field));
        }
        assert!(!snapshot.supports_field("unknown_future_setting"));
        assert!(serde_json::to_value(&snapshot)
            .unwrap()
            .get("supported_fields")
            .is_none());
        snapshot.supported_fields = Some(
            CLIPBOARD_SETTINGS_FIELDS
                .iter()
                .map(|field| (*field).into())
                .collect(),
        );
        assert!(snapshot.validate().is_ok() && snapshot.supports_field("capture_rules"));
        let request_id = Uuid::new_v4();
        let wire = serde_json::json!({"protocol":{"major":1,"minor":0},"presentation_version":2,
            "request_id":request_id,"ok":true,"settings_snapshot":snapshot});
        let response: ClipboardPresentationResponse = serde_json::from_value(wire).unwrap();
        assert!(response
            .validate_settings_for(&ClipboardPresentationCommand::SettingsRead, request_id)
            .is_ok());
        snapshot.supported_fields = Some(vec![]);
        assert!(snapshot.validate().is_ok() && !snapshot.supports_field("max_entries"));
        snapshot.supported_fields = Some(vec!["capture_rules".into(), "capture_rules".into()]);
        assert!(snapshot.validate().is_err());
        snapshot.supported_fields = Some(vec!["secure_copy_enabled".into()]);
        assert!(snapshot.validate().is_err());
        snapshot.supported_fields = Some(vec!["capture_rules".into(); 17]);
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn native_capture_rules_are_bounded_exact_paths_and_redacted() {
        let rule = ClipboardCaptureRule {
            id: Uuid::new_v4(),
            enabled: true,
            priority: 10,
            executable_path: r"C:\SyntheticCreativeTools\Editor.exe".into(),
            content_types: 1,
            action: "exclude".into(),
        };
        let patch = ClipboardSettingsPatch {
            capture_rules: Some(vec![rule.clone()]),
            ..Default::default()
        };
        assert!(patch.validate().is_ok());
        assert!(!format!("{rule:?} {patch:?}").contains("SyntheticCreativeTools"));
        for path in [
            r"Editor.exe",
            r"C:Editor.exe",
            r"C:/Tools/Editor.exe",
            r"C:\Tools\..\Editor.exe",
            r"C:\Tools\\Editor.exe",
            r"C:\Tools.\Editor.exe",
            r"\\?\C:\Tools\Editor.exe",
            r"C:\Tools\*.exe",
        ] {
            assert!(ClipboardCaptureRule {
                executable_path: path.into(),
                ..rule.clone()
            }
            .validate()
            .is_err());
        }
        assert!(ClipboardCaptureRule {
            executable_path: r"\\SyntheticServer\CreativeShare\Editor.exe".into(),
            ..rule.clone()
        }
        .validate()
        .is_ok());
        assert!(validate_capture_rules(&[
            rule.clone(),
            ClipboardCaptureRule {
                id: Uuid::new_v4(),
                ..rule.clone()
            }
        ])
        .is_err());
        assert!(validate_capture_rules(&[
            rule.clone(),
            ClipboardCaptureRule {
                priority: 11,
                ..rule.clone()
            }
        ])
        .is_err());
        assert!(ClipboardCaptureRule {
            content_types: 0,
            ..rule.clone()
        }
        .validate()
        .is_err());
        assert!(ClipboardCaptureRule {
            content_types: 16,
            ..rule.clone()
        }
        .validate()
        .is_err());
        assert!(ClipboardCaptureRule {
            action: "allow".into(),
            ..rule
        }
        .validate()
        .is_err());
    }

    #[test]
    fn native_settings_require_separate_window_and_durable_operation_identity() {
        let operation_id = Uuid::new_v4();
        let patch = ClipboardSettingsPatch {
            max_entries: Some(800),
            legacy_exclude_apps: Some("SyntheticCreativeApp.exe".into()),
            ..Default::default()
        };
        let command = ClipboardPresentationCommand::SettingsPrepare {
            operation_id,
            expected_revision: "a".repeat(64),
            patch: patch.clone(),
            digest: "b".repeat(64),
        };
        assert!(command.validate().is_ok());
        assert!(command.is_settings_command());
        assert!(command.presentation_may_mutate());
        assert!(!command.presentation_allows_unfocused());
        assert_eq!(command.presentation_view_id(), None);
        assert!(!format!("{command:?} {patch:?}").contains("SyntheticCreativeApp"));
        let wire = serde_json::to_value(&command).unwrap();
        assert_eq!(wire["kind"], "settings_prepare");
        assert!(wire["patch"].get("expire_days").is_none());
        let mut invalid = wire;
        invalid["patch"]["secure_copy_enabled"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(invalid).is_err());
        assert!(ClipboardSettingsPatch {
            expire_days: Some(0),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ClipboardSettingsPatch {
            legacy_exclude_apps: Some("bad\nrule".into()),
            ..Default::default()
        }
        .validate()
        .is_err());
        let status = ClipboardPresentationCommand::SettingsStatus {
            operation_id,
            digest: "b".repeat(64),
        };
        assert!(status.presentation_may_mutate());
        assert!(!status.presentation_allows_unfocused());
    }

    #[test]
    fn native_settings_receipts_preserve_pending_and_compensation_truth() {
        let request_id = Uuid::new_v4();
        let mut value = serde_json::json!({
            "protocol":{"major":1,"minor":0},"request_id":request_id,
            "ok":true,"error_code":null,"message":null,"presentation_version":2,
            "settings_receipt":{
                "operation_id":Uuid::new_v4(),"digest":"b".repeat(64),
                "state":"pending_runtime","base_revision":"a".repeat(64),
                "applied_revision":"c".repeat(64),"current_revision":"c".repeat(64),
                "config_committed":true,"runtime_acknowledged":false,"error_code":null
            }
        });
        let decode = |v| serde_json::from_value::<ClipboardPresentationResponse>(v).unwrap();
        assert!(decode(value.clone()).validate_for(request_id).is_ok());
        let status = ClipboardPresentationCommand::SettingsStatus {
            operation_id: Uuid::parse_str(
                value["settings_receipt"]["operation_id"].as_str().unwrap(),
            )
            .unwrap(),
            digest: "b".repeat(64),
        };
        assert!(decode(value.clone())
            .validate_settings_for(&status, request_id)
            .is_ok());
        let mut mixed = value.clone();
        mixed["view"] = serde_json::json!({"id":Uuid::new_v4(),"expires_at":"2026-09-05T12:00:00Z","snapshot_sequence":1,"target_available":false});
        assert!(decode(mixed)
            .validate_settings_for(&status, request_id)
            .is_err());
        assert!(decode(value.clone())
            .validate_settings_for(&ClipboardPresentationCommand::SettingsRead, request_id)
            .is_err());
        value["settings_receipt"]["runtime_acknowledged"] = serde_json::json!(true);
        assert!(decode(value.clone()).validate_for(request_id).is_err());
        value["settings_receipt"]["state"] = serde_json::json!("compensating");
        value["settings_receipt"]["config_committed"] = serde_json::json!(false);
        value["settings_receipt"]["runtime_acknowledged"] = serde_json::json!(false);
        assert!(decode(value.clone()).validate_for(request_id).is_ok());
        value["settings_receipt"]["settings_path"] =
            serde_json::json!("C:/must-not-be-a-status-field");
        assert!(serde_json::from_value::<ClipboardPresentationResponse>(value).is_err());
    }

    #[test]
    fn command_fixture_is_strict_and_preserves_atomic_order() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let command = ClipboardProviderCommand::AddToPack {
            pack_id: Uuid::new_v4(),
            expected_revision: 7,
            clip_ids: vec![first, second],
        };
        assert!(command.validate().is_ok());
        let value = serde_json::to_value(&command).expect("serialize command");
        assert_eq!(value["kind"], "add_to_pack");
        assert_eq!(value["expected_revision"], 7);
        assert_eq!(value["clip_ids"][0], first.to_string());

        let mut invalid = value;
        invalid["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClipboardProviderCommand>(invalid).is_err());
    }

    #[test]
    fn revisions_and_filter_owners_are_mandatory() {
        let pack = Uuid::new_v4();
        let valid = ClipboardProviderCommand::ListRecent {
            section: ClipboardProviderSection::Pack,
            query: None,
            pack_id: Some(pack),
            queue_id: None,
            limit: 100,
        };
        assert!(valid.validate().is_ok());
        let invalid = ClipboardProviderCommand::ListRecent {
            section: ClipboardProviderSection::Pack,
            query: None,
            pack_id: None,
            queue_id: None,
            limit: 100,
        };
        assert!(invalid.validate().is_err());
        assert!(ClipboardProviderCommand::SetFavorite {
            slot: 0,
            expected_revision: 0,
            clip_id: None,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn multi_selection_keeps_pack_ids_unique_but_queue_occurrences_ordered() {
        let id = Uuid::new_v4();
        let duplicate_queue = ClipboardProviderCommand::CreateQueue {
            name: Some("Posting".to_string()),
            mode: PasteQueueMode::Fifo,
            clip_ids: vec![id, id],
            operation_id: Some(Uuid::new_v4()),
        };
        assert!(duplicate_queue.validate().is_ok());
        let duplicate_pack = ClipboardProviderCommand::AddToPack {
            pack_id: Uuid::new_v4(),
            expected_revision: 1,
            clip_ids: vec![id, id],
        };
        assert!(duplicate_pack.validate().is_err());

        let query = "private-query-body";
        let command = ClipboardProviderCommand::ListRecent {
            section: ClipboardProviderSection::Recent,
            query: Some(query.to_string()),
            pack_id: None,
            queue_id: None,
            limit: 50,
        };
        assert!(!format!("{command:?}").contains(query));
    }

    #[test]
    fn response_fixture_checks_request_identity_and_redacts_titles() {
        let request_id = Uuid::new_v4();
        let response = ClipboardProviderResponse {
            protocol: CLIPBOARD_PROVIDER_PROTOCOL_VERSION,
            request_id,
            ok: true,
            error_code: None,
            message: None,
            status: None,
            clips: Some(vec![ClipboardProviderClip {
                id: Uuid::new_v4(),
                revision: 1,
                content_digest: "a".repeat(64),
                kind: "text".to_string(),
                title: "private title".to_string(),
                source_application: None,
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                use_count: 0,
                copy_count: 1,
                sensitivity: "standard".to_string(),
                missing_source: "available".to_string(),
                pinned_ordinal: None,
                quick_favorite_slot: None,
                root_original_id: None,
                immediate_parent_id: None,
                preferred_variant_id: None,
                membership_ordinal: None,
                queue_item_id: None,
                queue_item_state: None,
            }]),
            favorites: None,
            packs: None,
            queues: None,
            queue: None,
            ignore_next_copy: None,
        };
        assert!(response.validate_for(request_id).is_ok());
        assert!(!format!("{response:?}").contains("private title"));
        assert!(response.validate_for(Uuid::new_v4()).is_err());
    }

    #[test]
    fn provider_health_accepts_capture_pipeline_diagnostics_without_relaxing_strictness() {
        let request_id = Uuid::new_v4();
        let mut value = serde_json::json!({
            "protocol": CLIPBOARD_PROVIDER_PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": true,
            "error_code": null,
            "message": null,
            "status": {
                "provider_id": "spiffy.clipboard.windows.ditto",
                "protocol_major": 1,
                "protocol_minor": 0,
                "process_id": 1234,
                "session_id": Uuid::new_v4().to_string(),
                "provider_revision": 31,
                "capture_paused": false,
                "capture_pipeline": {
                    "loaded": 10,
                    "enqueued": 9,
                    "ignored": 1,
                    "save_attempts": 8,
                    "save_successes": 7,
                    "occurrence_commits": 6
                },
                "ignore_next_copy": null,
                "database_healthy": true,
                "locked": false,
                "captured_count": 100,
                "generated_at": Utc::now()
            },
            "clips": null,
            "favorites": null,
            "packs": null,
            "queues": null,
            "queue": null
        });
        let response: ClipboardProviderResponse = serde_json::from_value(value.clone()).unwrap();
        assert!(response.validate_for(request_id).is_ok());
        let pipeline = response
            .status
            .as_ref()
            .and_then(|status| status.capture_pipeline.as_ref())
            .expect("capture pipeline diagnostics");
        assert_eq!(pipeline.save_successes, 7);

        value["status"]["capture_pipeline"]["private_path"] = serde_json::json!("redacted");
        assert!(serde_json::from_value::<ClipboardProviderResponse>(value).is_err());
    }

    #[test]
    fn queue_capability_health_is_explicit_opt_in_without_changing_legacy_health() {
        let legacy = serde_json::to_value(ClipboardProviderCommand::Health).unwrap();
        assert_eq!(legacy, serde_json::json!({"kind":"health"}));
        let capabilities = ClipboardProviderCommand::HealthQueueCapabilities;
        assert_eq!(
            serde_json::to_value(&capabilities).unwrap(),
            serde_json::json!({"kind":"health_queue_capabilities"})
        );
        assert!(capabilities.validate().is_ok());
        assert_eq!(
            serde_json::from_value::<ClipboardProviderCommand>(
                serde_json::json!({"kind":"health_queue_capabilities"})
            )
            .unwrap(),
            capabilities
        );
    }

    #[test]
    fn presentation_is_separate_strict_bounded_and_debug_redacted() {
        let query = serde_json::json!({"kind":"presentation_query","view_id":Uuid::new_v4(),
            "generation":7,"query":"private fixture","kinds":["text","image"],"limit":100});
        let command: ClipboardPresentationCommand = serde_json::from_value(query.clone()).unwrap();
        assert!(command.validate().is_ok());
        assert!(!format!("{command:?}").contains("private fixture"));
        assert!(serde_json::from_value::<ClipboardProviderCommand>(query.clone()).is_err());
        let mut oversized = query.clone();
        oversized["limit"] = 101.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(oversized)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut widened = query;
        widened["clipboard_body"] = "forbidden".into();
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(widened).is_err());
    }

    #[test]
    fn presentation_queue_clear_keeps_collection_identity_and_requires_empty_items() {
        let mut command = ClipboardPresentationCommand::PresentationOrganize {
            view_id: Uuid::new_v4(),
            collection: "queue".to_string(),
            collection_id: Some(Uuid::new_v4()),
            expected_revision: 4,
            action: "clear_members".to_string(),
            name: String::new(),
            items: Vec::new(),
            operation_id: Uuid::new_v4(),
        };
        assert!(command.validate().is_ok());
        if let ClipboardPresentationCommand::PresentationOrganize { items, .. } = &mut command {
            items.push(Uuid::new_v4());
        }
        assert!(command.validate().is_err());

        let pack = ClipboardPresentationCommand::PresentationOrganize {
            view_id: Uuid::new_v4(),
            collection: "pack".to_string(),
            collection_id: Some(Uuid::new_v4()),
            expected_revision: 4,
            action: "clear_members".to_string(),
            name: String::new(),
            items: Vec::new(),
            operation_id: Uuid::new_v4(),
        };
        assert!(pack.validate().is_err());
    }

    #[test]
    fn presentation_queue_publication_requires_a_complete_current_identity() {
        let mut value = serde_json::json!({"kind":"presentation_publish","view_id":Uuid::new_v4(),
            "clip_id":Uuid::new_v4(),"expected_revision":1,"plain_text":false,"paste":true,
            "operation_id":Uuid::new_v4()});
        let parse = |v| {
            serde_json::from_value::<ClipboardPresentationCommand>(v)
                .unwrap()
                .validate()
        };
        assert!(parse(value.clone()).is_ok());
        value["queue_id"] = serde_json::json!(Uuid::new_v4());
        assert!(parse(value.clone()).is_err());
        value["queue_revision"] = 1.into();
        value["queue_item_id"] = serde_json::json!(Uuid::new_v4());
        assert!(parse(value.clone()).is_ok());
        value["queue_revision"] = 0.into();
        assert!(parse(value).is_err());
    }

    #[test]
    fn smart_pack_commands_are_view_bound_and_revision_protected() {
        let view = Uuid::new_v4();
        let mut value = serde_json::json!({"kind":"presentation_save_smart_pack","view_id":view,
            "name":"Synthetic Pack","filter":{"query":"synthetic","kinds":["text"]}});
        let command: ClipboardPresentationCommand = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(command.presentation_view_id(), Some(view));
        assert!(command.validate().is_ok());
        assert!(!format!("{command:?}").contains("Synthetic Pack"));
        for mode in ["all_words", "source_phrase", "literal", "prefix"] {
            value["filter"]["mode"] = mode.into();
            let with_mode: ClipboardPresentationCommand =
                serde_json::from_value(value.clone()).unwrap();
            assert!(with_mode.validate().is_ok());
            assert_eq!(
                serde_json::to_value(with_mode).unwrap()["filter"]["mode"],
                mode
            );
        }
        value["filter"]["mode"] = "unsupported".into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["filter"]["mode"] = "all_words".into();
        value["pack_id"] = serde_json::json!(Uuid::new_v4());
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["expected_revision"] = 1.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        value["filter"]["kinds"] = serde_json::json!(["unsupported"]);
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn favorite_customization_is_fixed_slot_scoped_and_inert() {
        let view = Uuid::new_v4();
        let mut value = serde_json::json!({"kind":"presentation_customize_favorite","view_id":view,
            "operation_id":Uuid::new_v4(),"slot":10,"expected_revision":1,"title_override":"Secret custom title","icon_token":"code","color_token":"#01aBcD"});
        let command: ClipboardPresentationCommand = serde_json::from_value(value.clone()).unwrap();
        assert!(
            command.validate().is_ok()
                && command.presentation_may_mutate()
                && !command.presentation_allows_unfocused()
        );
        assert_eq!(command.presentation_view_id(), Some(view));
        assert!(!format!("{command:?}").contains("Secret custom title"));
        value["icon_token"] = "https://example.invalid/icon.svg".into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["icon_token"] = serde_json::Value::Null;
        value["title_override"] = "x".repeat(81).into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value)
                .unwrap()
                .validate()
                .is_err()
        );
        let swap = serde_json::json!({"kind":"presentation_swap_favorites","view_id":view,"operation_id":Uuid::new_v4(),"first_slot":1,"first_expected_revision":1,"second_slot":1,"second_expected_revision":1});
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(swap)
            .unwrap()
            .validate()
            .is_err());
        let request = Uuid::new_v4();
        let slots: Vec<_> = (1..=10).map(|slot| serde_json::json!({"slot":slot,"revision":1,"clip_id":null,"title_override":null,"icon_token":null,"color_token":null})).collect();
        let mut response = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"ok":true,"error_code":null,"message":null,"presentation_version":2,"favorite_slots":slots});
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(response.clone())
                .unwrap()
                .validate_for(request)
                .is_ok()
        );
        response["favorite_slots"][9]["slot"] = 9.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(response)
                .unwrap()
                .validate_for(request)
                .is_err()
        );
    }

    #[test]
    fn native_archive_controls_keep_unfocused_status_content_free() {
        let view = Uuid::new_v4();
        let operation = Uuid::new_v4();
        for kind in ["presentation_archive_status", "presentation_archive_cancel"] {
            let command: ClipboardPresentationCommand =
                serde_json::from_value(serde_json::json!({"kind":kind,"operation_id":operation}))
                    .unwrap();
            assert!(command.validate().is_ok() && command.presentation_allows_unfocused());
            assert_eq!(command.presentation_view_id(), None);
            assert!(!command.presentation_may_mutate());
        }
        let mut start = serde_json::json!({"kind":"presentation_archive_start","view_id":view,
            "operation_id":operation,"action":"export","clips":[{"id":Uuid::new_v4(),"revision":1}]});
        let command: ClipboardPresentationCommand = serde_json::from_value(start.clone()).unwrap();
        assert!(
            command.validate().is_ok()
                && command.presentation_may_mutate()
                && !command.presentation_allows_unfocused()
        );
        assert_eq!(command.presentation_view_id(), Some(view));
        start["action"] = "import".into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(start)
                .unwrap()
                .validate()
                .is_err()
        );
        let request = Uuid::new_v4();
        let mut status = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,
            "ok":true,"error_code":null,"message":null,"presentation_version":2,
            "archive_operation":{"operation_id":operation,"action":"export","state":"awaiting_authorization",
                "revision":2,"expires_at":"2026-09-05T12:00:00Z","clip_count":1,"format_count":0,"byte_count":0,"error_code":null}});
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(status.clone())
                .unwrap()
                .validate_for(request)
                .is_ok()
        );
        status["archive_operation"]["path"] = "C:\\SyntheticOnly\\hidden.dto".into();
        assert!(serde_json::from_value::<ClipboardPresentationResponse>(status.clone()).is_err());
        status["archive_operation"]
            .as_object_mut()
            .unwrap()
            .remove("path");
        status["archive_operation"]["byte_count"] = (64_u64 * 1024 * 1024 + 1).into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(status)
                .unwrap()
                .validate_for(request)
                .is_err()
        );
    }

    #[test]
    fn captured_file_subsets_are_scoped_and_paths_are_ephemeral() {
        let view = Uuid::new_v4();
        let mut command = serde_json::json!({"kind":"presentation_create_file_subset","view_id":view,
            "clip_id":Uuid::new_v4(),"expected_revision":1,"ordinals":[10,1,7]});
        let parsed: ClipboardPresentationCommand = serde_json::from_value(command.clone()).unwrap();
        assert!(parsed.validate().is_ok() && parsed.presentation_may_mutate());
        assert_eq!(parsed.presentation_view_id(), Some(view));
        command["ordinals"] = serde_json::json!([1, 1]);
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(command)
                .unwrap()
                .validate()
                .is_err()
        );
        let request = Uuid::new_v4();
        let mut value = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,
            "ok":true,"error_code":null,"message":null,"presentation_version":2,
            "captured_files":{"clip_id":Uuid::new_v4(),"revision":1,"total_files":12,"offset":5,
                "items":[{"ordinal":5,"path":"C:\\SyntheticOnly\\private-path.mov"}],"next_offset":6}});
        let response: ClipboardPresentationResponse =
            serde_json::from_value(value.clone()).unwrap();
        assert!(response.validate_for(request).is_ok());
        assert!(!format!("{response:?}").contains("private-path"));
        assert!(serde_json::from_value::<ClipboardProviderResponse>(value.clone()).is_err());
        value["captured_files"]["next_offset"] = 5.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value)
                .unwrap()
                .validate_for(request)
                .is_err()
        );
    }

    #[test]
    fn drafts_preserve_reference_order_and_reject_unavailable_content() {
        let view = Uuid::new_v4();
        let clip = serde_json::json!({"id":Uuid::new_v4(),"revision":1});
        let mut value = serde_json::json!({"kind":"presentation_start_draft","view_id":view,
            "name":"private draft name","separator":"\n\n","clips":[clip.clone(),clip]});
        let command: ClipboardPresentationCommand = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(command.presentation_view_id(), Some(view));
        assert!(command.presentation_may_mutate() && command.validate().is_ok());
        assert!(!format!("{command:?}").contains("private draft name"));
        value["separator"] = "x".repeat(257).into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value)
                .unwrap()
                .validate()
                .is_err()
        );
        let request = Uuid::new_v4();
        let mut response = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,
            "ok":true,"error_code":null,"message":null,"presentation_version":2,
            "draft_preview":{"draft_id":Uuid::new_v4(),"content_state":"source_unavailable","excerpt":"","byte_count":0}});
        let parse = |v| {
            serde_json::from_value::<ClipboardPresentationResponse>(v)
                .unwrap()
                .validate_for(request)
        };
        assert!(parse(response.clone()).is_ok());
        response["draft_preview"]["excerpt"] = "stale body".into();
        assert!(parse(response).is_err());
        let read: ClipboardPresentationCommand = serde_json::from_value(serde_json::json!({
            "kind":"presentation_read_draft","view_id":view,"draft_id":Uuid::new_v4()}))
        .unwrap();
        assert!(!read.presentation_may_mutate() && read.validate().is_ok());
    }

    #[test]
    fn capture_sessions_are_explicit_bounded_owner_mutations() {
        let view = Uuid::new_v4();
        let mut value = serde_json::json!({"kind":"presentation_start_capture_session","view_id":view,
            "pack_id":null,"pack_revision":null,"inactivity_timeout_seconds":60,"persist_across_restart":false});
        let command: ClipboardPresentationCommand = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(command.presentation_view_id(), Some(view));
        assert!(command.presentation_may_mutate() && command.validate().is_ok());
        value["pack_id"] = serde_json::json!(Uuid::new_v4());
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        value["pack_revision"] = 1.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        value["inactivity_timeout_seconds"] = 1.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(value)
                .unwrap()
                .validate()
                .is_err()
        );
        let command: ClipboardPresentationCommand = serde_json::from_value(
            serde_json::json!({"kind":"presentation_capture_sessions","view_id":view}),
        )
        .unwrap();
        assert!(!command.presentation_may_mutate());
    }

    #[test]
    fn presentation_grouping_and_progress_are_bounded() {
        let id = Uuid::new_v4();
        let mut query = serde_json::json!({"kind":"presentation_query","view_id":Uuid::new_v4(),
            "generation":7,"query":"","kinds":[],"limit":10,"related_tags":true,"related_group_id":"a".repeat(64)});
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(query.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        query["related_tags"] = false.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(query)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut value = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":id,
            "ok":true,"error_code":null,"message":null,"presentation_version":2,
            "page":{"generation":7,"snapshot_sequence":1000,"items":[],"has_more":false,
                "search_progress":{"stage":"indexing","indexed_clips":256,"total_clips":1000,"limited_clips":1}}});
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value.clone())
                .unwrap()
                .validate_for(id)
                .is_ok()
        );
        value["page"]["items"] = serde_json::json!([{
            "id":Uuid::new_v4(),"revision":1,"occurrence_id":Uuid::new_v4(),"capture_sequence":999,
            "copied_at":"2026-09-11T12:00:00Z","legacy_estimate":false,"kind":"text","excerpt":"Provisional verified match",
            "source_application":null,"source_executable_path":null,"source_attribution_confidence":null,
            "pinned":false,"copy_count":1,"tags":[],"tag_group_id":null,"related_group":null,"search_match":null
        }]);
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value.clone())
                .unwrap()
                .validate_for(id)
                .is_ok(),
            "an indexing page may expose bounded fully verified provisional results"
        );
        value["page"]["has_more"] = true.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value.clone())
                .unwrap()
                .validate_for(id)
                .is_err(),
            "provisional results must not expose an unstable pagination cursor"
        );
        value["page"]["has_more"] = false.into();
        value["page"]["items"] = serde_json::json!([]);
        value["page"]["search_progress"]["stage"] = "ready".into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value.clone())
                .unwrap()
                .validate_for(id)
                .is_err()
        );
        value["page"]["search_progress"]["indexed_clips"] = 1000.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value.clone())
                .unwrap()
                .validate_for(id)
                .is_ok()
        );
        value["page"]["search_progress"]["limited_clips"] = 1001.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(value)
                .unwrap()
                .validate_for(id)
                .is_err()
        );
    }

    #[test]
    fn presentation_response_negotiates_version_without_widening_v1() {
        let id = Uuid::new_v4();
        let rejection = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":id,"ok":false,
            "error_code":"view_revoked","message":"Clipboard presentation could not complete safely.","presentation_version":2});
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(rejection)
                .unwrap()
                .validate_for(id)
                .is_ok()
        );
        let value = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":id,
            "ok":true,"error_code":null,"message":null,"presentation_version":2,
            "page":{"generation":1,"snapshot_sequence":0,"items":[],"has_more":false}});
        let response: ClipboardPresentationResponse =
            serde_json::from_value(value.clone()).unwrap();
        assert!(response.validate_for(id).is_ok());
        assert!(response.validate_for(Uuid::new_v4()).is_err());
        assert!(serde_json::from_value::<ClipboardProviderResponse>(value.clone()).is_err());
        let mut unsupported = value;
        unsupported["presentation_version"] = 3.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationResponse>(unsupported)
                .unwrap()
                .validate_for(id)
                .is_err()
        );
    }

    #[test]
    fn presentation_hotkey_state_accepts_native_browse_only_without_relaxing_strictness() {
        let request = Uuid::new_v4();
        let session = Uuid::new_v4();
        let mut wire = serde_json::json!({
            "protocol":{"major":1,"minor":0},
            "request_id":request,
            "ok":true,
            "error_code":null,
            "message":null,
            "presentation_version":2,
            "hotkey_state":{
                "session_id":session,
                "revision":5,
                "cycle_offset":4,
                "cycle_count":4,
                "released":false,
                "cancelled":false,
                "browse_only":true
            }
        });
        // The shipped native provider emits browse_only. Rejecting that
        // *whole response* makes the renderer unable to cycle with Win+V.
        let response: ClipboardPresentationResponse = serde_json::from_value(wire.clone()).unwrap();
        assert!(response.validate_for(request).is_ok());
        assert!(response.hotkey_state.unwrap().browse_only);

        // Older native providers omit the optional flag. Keep those readable.
        wire["hotkey_state"]
            .as_object_mut()
            .unwrap()
            .remove("browse_only");
        let legacy: ClipboardPresentationResponse = serde_json::from_value(wire.clone()).unwrap();
        assert!(!legacy.hotkey_state.unwrap().browse_only);

        // Unknown fields beyond this contracted capability must still fail.
        wire["hotkey_state"]["unexpected"] = true.into();
        assert!(serde_json::from_value::<ClipboardPresentationResponse>(wire).is_err());
    }

    #[test]
    fn queue_ctrl_v_arming_is_explicit_and_runtime_local() {
        let request = Uuid::new_v4();
        let queue = Uuid::new_v4();
        let settings_revision = "a".repeat(64);
        let mut command = serde_json::json!({
            "kind":"presentation_select_queue", "view_id":Uuid::new_v4(),
            "queue_id":queue, "queue_revision":4, "expected_revision":settings_revision,
            "operation_id":Uuid::new_v4(), "ctrl_v_enabled":true
        });
        let arm: ClipboardPresentationCommand = serde_json::from_value(command.clone()).unwrap();
        assert!(arm.validate().is_ok());
        command["ctrl_v_enabled"] = false.into();
        let disarm: ClipboardPresentationCommand = serde_json::from_value(command.clone()).unwrap();
        assert!(disarm.validate().is_ok());
        command["ctrl_v_enabled"] = "yes".into();
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(command).is_err());

        let reply = serde_json::json!({"protocol":{"major":1,"minor":0}, "request_id":request,
            "ok":true,"presentation_version":2,
            "queue_selection":{"queue_id":queue,"owner_revision":settings_revision,"ctrl_v_armed":true}});
        let active: ClipboardPresentationResponse = serde_json::from_value(reply.clone()).unwrap();
        assert!(active.validate_for(request).is_ok());
        assert!(active.queue_selection.unwrap().ctrl_v_armed);
        let mut unarmed = reply;
        unarmed["queue_selection"]
            .as_object_mut()
            .unwrap()
            .remove("ctrl_v_armed");
        let legacy: ClipboardPresentationResponse =
            serde_json::from_value(unarmed.clone()).unwrap();
        assert!(!legacy.queue_selection.unwrap().ctrl_v_armed);
        unarmed["queue_selection"]["uncontracted"] = true.into();
        assert!(serde_json::from_value::<ClipboardPresentationResponse>(unarmed).is_err());
    }

    #[test]
    fn presentation_query_requires_only_its_page_and_recoverable_errors_carry_no_projection() {
        let request_id = Uuid::new_v4();
        let command: ClipboardPresentationCommand = serde_json::from_value(serde_json::json!({
            "kind":"presentation_query",
            "view_id":Uuid::new_v4(),
            "generation":3,
            "query":"needle",
            "kinds":[],
            "limit":100
        }))
        .unwrap();
        let success_without_page: ClipboardPresentationResponse =
            serde_json::from_value(serde_json::json!({
                "protocol":{"major":1,"minor":0},
                "request_id":request_id,
                "ok":true,
                "error_code":null,
                "message":null,
                "presentation_version":2
            }))
            .unwrap();
        assert!(success_without_page.validate_for(request_id).is_ok());
        assert!(success_without_page
            .validate_document_for(&command)
            .is_err());

        let recoverable: ClipboardPresentationResponse =
            serde_json::from_value(serde_json::json!({
                "protocol":{"major":1,"minor":0},
                "request_id":request_id,
                "ok":false,
                "error_code":"search_context_expired",
                "message":null,
                "presentation_version":2
            }))
            .unwrap();
        assert!(recoverable.validate_for(request_id).is_ok());
        assert!(recoverable.validate_document_for(&command).is_ok());

        let mut smuggled = recoverable;
        smuggled.page = Some(ClipboardPresentationPage {
            generation: 3,
            snapshot_sequence: 0,
            items: Vec::new(),
            has_more: false,
            search_progress: None,
        });
        assert!(smuggled.validate_document_for(&command).is_err());
    }
}

#[cfg(test)]
mod clipboard_drag_contract_tests {
    use super::*;
    #[test]
    fn generated_offer_proof_is_exclusive_and_binds_exact_request_and_ordinals() {
        let request = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let command = ClipboardPresentationCommand::PresentationDragVerifyOffer {
            operation_id: operation,
            lease_id: lease,
            target_window: 1,
            paths: vec![
                "C:\\owned\\first.txt".into(),
                "C:\\owned\\second.txt".into(),
            ],
        };
        assert!(
            command.validate().is_ok()
                && command.is_drag_command()
                && command.presentation_allows_unfocused()
        );
        let mut encoded = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"ok":true,"presentation_version":2,"generated_drag_offer":{"operation_id":operation,"lease_id":lease,"producer_pid":2,"producer_birth":3,"target_window":1,"offered_count":2,"expires_at":"2026-09-06T12:00:00Z","generated_files":[{"ordinal":1,"identity":"ab".repeat(24),"bytes":9}]}});
        let decode =
            |value| serde_json::from_value::<ClipboardPresentationResponse>(value).unwrap();
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_ok());
        encoded["generated_drag_offer"]["generated_files"][0]["ordinal"] = serde_json::json!(2);
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_err());
        encoded["generated_drag_offer"]["generated_files"][0]["ordinal"] = serde_json::json!(1);
        encoded["generated_drag_offer"]["lease_id"] = serde_json::json!(Uuid::new_v4());
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_err());
        encoded["generated_drag_offer"]["lease_id"] = serde_json::json!(lease);
        encoded["generated_drag_offer"]["generated_offer_version"] = serde_json::json!(2);
        encoded["generated_drag_offer"]["source_references"] = serde_json::json!([{
            "ordinal":1,
            "clip_id":Uuid::new_v4(),
            "occurrence_id":Uuid::new_v4(),
            "expected_revision":3,
            "queue_item_id":null
        }]);
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_ok());
        encoded["generated_drag_offer"]["source_references"][0]["ordinal"] = serde_json::json!(0);
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_err());
        encoded["generated_drag_offer"]["source_references"][0]["ordinal"] = serde_json::json!(1);
        encoded["ok"] = serde_json::json!(false);
        encoded["error_code"] = serde_json::json!("unavailable");
        assert!(decode(encoded)
            .validate_drag_for(&command, request)
            .is_err());
        let command = ClipboardPresentationCommand::PresentationDragVerifyOffer {
            operation_id: operation,
            lease_id: lease,
            target_window: 1,
            paths: vec!["x".repeat(32767); 9],
        };
        assert!(command.validate().is_err());
    }
    #[test]
    fn legacy_drag_capability_decodes_but_start_requires_generated_offer_contract() {
        let caps: ClipboardDragCapabilities = serde_json::from_value(serde_json::json!({
            "version":1,"maximum_items":100,"maximum_source_bytes":67108864,"file_lease_seconds":3600
        })).unwrap();
        assert_eq!(caps.generated_offer_version, 0);
        let mut command = serde_json::json!({"kind":"presentation_drag_start", "view_id":Uuid::new_v4(),
            "operation_id":Uuid::new_v4(), "consumer_window":1,
            "items":[{"id":Uuid::new_v4(),"expected_revision":1,"occurrence_id":Uuid::new_v4()}]});
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(command.clone()).is_err());
        command["generated_offer_version"] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(command.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        command["generated_offer_version"] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(command.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        command["generated_offer_version"] = serde_json::json!(2);
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(command.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        // The historical native ExactKeys admission rejects this added mandatory key.
        let old_keys = [
            "kind",
            "view_id",
            "operation_id",
            "consumer_window",
            "items",
        ];
        assert!(command
            .as_object()
            .unwrap()
            .keys()
            .any(|key| !old_keys.contains(&key.as_str())));
    }

    #[test]
    fn drag_selection_keeps_occurrences_and_rejects_duplicate_rows_and_payloads() {
        let clip = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let command = ClipboardPresentationCommand::PresentationDragStart {
            view_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            generated_offer_version: 1,
            consumer_window: 1,
            items: vec![
                ClipboardDragItem {
                    id: clip,
                    expected_revision: 3,
                    occurrence_id: first,
                    queue_item_id: None,
                },
                ClipboardDragItem {
                    id: clip,
                    expected_revision: 3,
                    occurrence_id: second,
                    queue_item_id: None,
                },
            ],
        };
        assert!(command.validate().is_ok());
        assert!(command.presentation_may_mutate());
        assert!(!command.presentation_allows_unfocused());
        let mut encoded = serde_json::to_value(&command).unwrap();
        encoded["items"][1]["occurrence_id"] = serde_json::json!(first);
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(encoded.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        encoded["items"][0]["text"] = serde_json::json!("body must never cross this route");
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(encoded).is_err());
        for command in [
            ClipboardPresentationCommand::PresentationDragStatus {
                operation_id: Uuid::new_v4(),
            },
            ClipboardPresentationCommand::PresentationDragCancel {
                operation_id: Uuid::new_v4(),
            },
        ] {
            assert!(
                command.validate().is_ok()
                    && command.presentation_allows_unfocused()
                    && command.presentation_view_id().is_none()
            );
        }
    }
    #[test]
    fn unfocused_drag_receipts_are_exact_and_cannot_smuggle_presentation_content() {
        let request = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let command = ClipboardPresentationCommand::PresentationDragStatus {
            operation_id: operation,
        };
        let mut encoded = serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"ok":true,"error_code":null,"message":null,"presentation_version":2,"drag_receipt":{"operation_id":operation,"state":"dragging","item_count":2,"revision":2,"mode":"files_only","error_code":null,"expires_at":"2026-09-06T12:00:00Z","file_lease_seconds":3600}});
        let decode =
            |value| serde_json::from_value::<ClipboardPresentationResponse>(value).unwrap();
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_ok());
        assert!(decode(encoded.clone())
            .validate_drag_for(
                &ClipboardPresentationCommand::PresentationDragStatus {
                    operation_id: Uuid::new_v4()
                },
                request
            )
            .is_err());
        encoded["view"] = serde_json::json!({"id":Uuid::new_v4(),"expires_at":"2026-09-06T12:00:00Z","snapshot_sequence":0,"target_available":false});
        assert!(decode(encoded.clone())
            .validate_drag_for(&command, request)
            .is_err());
        encoded["view"] = serde_json::Value::Null;
        encoded["drag_receipt"]["mode"] = serde_json::json!("renderer_chosen");
        assert!(decode(encoded)
            .validate_drag_for(&command, request)
            .is_err());
    }
}

#[cfg(test)]
mod clipboard_preview_contract_tests {
    use super::*;
    fn item() -> ClipboardPreviewItem {
        ClipboardPreviewItem {
            clip_id: Uuid::new_v4(),
            occurrence_id: Uuid::new_v4(),
            expected_revision: 1,
            queue_item_id: Some(Uuid::new_v4()),
            file_ordinal: None,
            purpose: ClipboardPreviewPurpose::Thumbnail,
        }
    }
    fn grant() -> ClipboardPreviewGrant {
        ClipboardPreviewGrant {
            grant_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            view_id: Uuid::new_v4(),
            producer_pid: 2,
            producer_birth: 3,
            consumer_window: 4,
            item: item(),
            file_count: None,
            expires_at: Utc::now() + chrono::Duration::seconds(30),
            source: ClipboardPreviewSource::Image {
                encoding: ClipboardPreviewImageEncoding::Png,
                total_bytes: 4,
                sha256: "a".repeat(64),
                width: 8,
                height: 8,
            },
        }
    }
    fn response(request_id: Uuid) -> ClipboardPresentationResponse {
        serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request_id,"ok":true,"presentation_version":2})).unwrap()
    }

    #[test]
    fn preview_body_requests_require_a_view_and_never_admit_paths_from_the_caller() {
        let command = ClipboardPresentationCommand::PresentationPreviewOpen {
            view_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            consumer_window: 1,
            item: item(),
        };
        assert!(command.validate().is_ok() && command.is_preview_command());
        assert!(!command.presentation_allows_unfocused() && !command.presentation_may_mutate());
        let mut json = serde_json::to_value(&command).unwrap();
        json["item"]["path"] = serde_json::json!("C:\\private-canary.png");
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(json).is_err());
        let close = ClipboardPresentationCommand::PresentationPreviewClose {
            operation_id: Uuid::new_v4(),
        };
        assert!(close.presentation_allows_unfocused() && close.presentation_view_id().is_none());
        let read = ClipboardPresentationCommand::PresentationPreviewRead {
            view_id: Uuid::nil(),
            grant_id: Uuid::new_v4(),
            offset: 0,
            max_bytes: 65536,
        };
        assert!(read.validate().is_err() && !read.presentation_allows_unfocused());
    }

    #[test]
    fn preview_grants_bind_every_reference_and_only_one_authorized_representation() {
        let request_id = Uuid::new_v4();
        let grant = grant();
        let command = ClipboardPresentationCommand::PresentationPreviewOpen {
            view_id: grant.view_id,
            operation_id: grant.operation_id,
            consumer_window: grant.consumer_window,
            item: grant.item.clone(),
        };
        let mut result = response(request_id);
        result.preview_grant = Some(grant.clone());
        assert!(result.validate_preview_for(&command, request_id).is_ok());
        for field in ["clip_id", "occurrence_id", "queue_item_id"] {
            let mut changed = serde_json::to_value(&result).unwrap();
            changed["preview_grant"]["item"][field] = serde_json::json!(Uuid::new_v4());
            let changed: ClipboardPresentationResponse = serde_json::from_value(changed).unwrap();
            assert!(changed.validate_preview_for(&command, request_id).is_err());
        }
        result.preview_grant.as_mut().unwrap().consumer_window += 1;
        assert!(result.validate_preview_for(&command, request_id).is_err());
        let mut invalid = grant.clone();
        invalid.file_count = Some(2);
        assert!(invalid.validate().is_err());
        invalid = grant.clone();
        invalid.source = ClipboardPreviewSource::Image {
            encoding: ClipboardPreviewImageEncoding::Bmp,
            total_bytes: 4096,
            sha256: "a".repeat(64),
            width: 8192,
            height: 8192,
        };
        assert!(
            invalid.validate().is_err(),
            "Compressed byte limits do not prove decoded image bounds"
        );
        invalid.source = ClipboardPreviewSource::File {
            path: "C:\\fixture.png".into(),
            identity: "a".repeat(48),
            bytes: 100,
            modified_ns: 1,
        };
        invalid.file_count = Some(2);
        assert!(
            invalid.validate().is_err(),
            "File selection must have an explicit ordinal"
        );
        invalid.item.file_ordinal = Some(1);
        assert!(invalid.validate().is_ok());
        invalid.item.file_ordinal = Some(2);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn preview_chunks_require_the_exact_requested_range_and_final_boundary() {
        let request_id = Uuid::new_v4();
        let view_id = Uuid::new_v4();
        let grant_id = Uuid::new_v4();
        let command = ClipboardPresentationCommand::PresentationPreviewRead {
            view_id,
            grant_id,
            offset: 4,
            max_bytes: 65536,
        };
        let mut result = response(request_id);
        result.preview_chunk = Some(ClipboardPreviewChunk {
            view_id,
            grant_id,
            offset: 4,
            total_bytes: 8,
            sha256: "b".repeat(64),
            data_base64: "YWJjZA==".into(),
            eof: true,
        });
        assert!(result.validate_preview_for(&command, request_id).is_ok());
        result.preview_chunk.as_mut().unwrap().offset = 0;
        assert!(result.validate_preview_for(&command, request_id).is_err());
        result.preview_chunk.as_mut().unwrap().offset = 4;
        result.preview_chunk.as_mut().unwrap().eof = false;
        assert!(result.validate_preview_for(&command, request_id).is_err());
        result.preview_chunk.as_mut().unwrap().eof = true;
        result.preview_chunk.as_mut().unwrap().data_base64 = "A".repeat(90000);
        assert!(result.validate_preview_for(&command, request_id).is_err());
    }

    #[test]
    fn metadata_only_preview_replies_cannot_carry_content_or_error_success_pairs() {
        let request_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let command = ClipboardPresentationCommand::PresentationPreviewClose { operation_id };
        let mut result = response(request_id);
        result.preview_closed = Some(ClipboardPreviewClosed {
            operation_id,
            closed: true,
        });
        assert!(result.validate_preview_for(&command, request_id).is_ok());
        result.message = Some("C:\\PRIVATE_CANARY.png".into());
        assert!(result.validate_preview_for(&command, request_id).is_err());
        result.message = None;
        result.preview_grant = Some(grant());
        assert!(result.validate_preview_for(&command, request_id).is_err());
        assert!(result
            .validate_settings_for(&ClipboardPresentationCommand::SettingsRead, request_id)
            .is_err());
        assert!(result
            .validate_drag_for(
                &ClipboardPresentationCommand::PresentationDragCapabilities,
                request_id
            )
            .is_err());
        result.preview_grant = None;
        result.ok = false;
        result.error_code = Some("preview_unavailable".into());
        assert!(result.validate_preview_for(&command, request_id).is_err());
        result.preview_closed = None;
        assert!(result.validate_preview_for(&command, request_id).is_ok());
        result.error_code = Some("private body\ncanary".into());
        assert!(result.validate_preview_for(&command, request_id).is_err());
    }
    #[test]
    fn complete_reader_previous_pages_and_unrelated_projection_are_fenced() {
        let id = Uuid::new_v4();
        let clip = Uuid::new_v4();
        let digest = format!("sha256:{}", "a".repeat(64));
        let command:ClipboardPresentationCommand=serde_json::from_value(serde_json::json!({"kind":"presentation_document_find","view_id":Uuid::new_v4(),"clip_id":clip,"occurrence_id":Uuid::new_v4(),"expected_revision":2,"query":"x","after_utf8":0,"before_utf8":100,"representation_revision":digest})).unwrap();
        assert!(command.validate().is_ok());
        let mut response:ClipboardPresentationResponse=serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":id,"ok":true,"presentation_version":2,
            "document_find":{"clip_id":clip,"revision":2,"representation_revision":digest,"result":{"matches":[{"start":90,"end":91,"utf16_start":90,"utf16_end":91,"actual_text":"x"},{"start":80,"end":81,"utf16_start":80,"utf16_end":81,"actual_text":"x"}],"has_more":true,"next_offset":80,"total_matches":1000,"complete":true,"coordinate_unit":"utf8_bytes","semantics_version":"1"}}})).unwrap();
        assert!(response.validate_document_for(&command).is_ok());
        response
            .document_find
            .as_mut()
            .unwrap()
            .result
            .matches
            .reverse();
        assert!(response.validate_document_for(&command).is_err());
        response
            .document_find
            .as_mut()
            .unwrap()
            .result
            .matches
            .reverse();
        response.page=Some(serde_json::from_value(serde_json::json!({"generation":1,"snapshot_sequence":1,"items":[],"has_more":false})).unwrap());
        assert!(response.validate_document_for(&command).is_err());
    }
    #[test]
    fn draft_chunks_and_publication_have_exact_bounded_authority() {
        let view = Uuid::new_v4();
        let draft = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let digest = format!("sha256:{}", "a".repeat(64));
        let mut wire = serde_json::json!({"kind":"presentation_edit_draft","view_id":view,"draft_id":draft,"expected_revision":7,"operation_id":operation,"offset":65536,"total_bytes":65540,"representation_revision":digest,"text":"😀"});
        let command: ClipboardPresentationCommand = serde_json::from_value(wire.clone()).unwrap();
        assert!(command.validate().is_ok());
        assert!(command.presentation_may_mutate());
        wire["total_bytes"] = 65539.into();
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(wire)
            .unwrap()
            .validate()
            .is_err());
        let mut publish = serde_json::json!({"kind":"presentation_publish_draft","view_id":view,"draft_id":draft,"expected_revision":7,"operation_id":operation,"paste":false,"start":1,"end":5,"representation_revision":digest});
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(publish.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        publish["paste"] = true.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(publish.clone())
                .unwrap()
                .validate()
                .is_err()
        );
        publish["paste"] = false.into();
        publish
            .as_object_mut()
            .unwrap()
            .remove("representation_revision");
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(publish)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    #[test]
    fn full_draft_reader_rejects_wrong_revision_page_and_extra_content() {
        let request = Uuid::new_v4();
        let draft = Uuid::new_v4();
        let digest = format!("sha256:{}", "a".repeat(64));
        let command:ClipboardPresentationCommand=serde_json::from_value(serde_json::json!({"kind":"presentation_read_draft","view_id":Uuid::new_v4(),"draft_id":draft,"expected_revision":7,"offset":65536})).unwrap();
        let mut response:ClipboardPresentationResponse=serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"ok":true,"presentation_version":2,"draft_preview":{"draft_id":draft,"content_state":"ready","excerpt":"tail","byte_count":65540,"revision":7,"representation_revision":digest,"offset":65536,"text":"😀","next_offset":null}})).unwrap();
        assert!(response.validate_for(request).is_ok());
        assert!(response.validate_document_for(&command).is_ok());
        response.draft_preview.as_mut().unwrap().next_offset = Some(65540);
        assert!(response.validate_for(request).is_err());
        response.draft_preview.as_mut().unwrap().next_offset = None;
        response.draft_preview.as_mut().unwrap().revision = Some(8);
        assert!(response.validate_document_for(&command).is_err());
        response.draft_preview.as_mut().unwrap().revision = Some(7);
        response.drafts = Some(Vec::new());
        assert!(response.validate_document_for(&command).is_err());
    }
    #[test]
    fn history_deletion_requires_exact_unique_sources_and_exclusive_receipt() {
        let operation = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let request = Uuid::new_v4();
        let command = ClipboardPresentationCommand::PresentationDeleteClips {
            view_id: Uuid::new_v4(),
            operation_id: operation,
            clips: vec![
                ClipboardDeleteClip {
                    clip_id: first,
                    occurrence_id: Uuid::new_v4(),
                    expected_revision: 7,
                },
                ClipboardDeleteClip {
                    clip_id: second,
                    occurrence_id: Uuid::new_v4(),
                    expected_revision: 2,
                },
            ],
        };
        assert!(command.validate().is_ok());
        assert!(command.presentation_may_mutate());
        let mut duplicate = command.clone();
        if let ClipboardPresentationCommand::PresentationDeleteClips { clips, .. } = &mut duplicate
        {
            clips[1].clip_id = first;
        }
        assert!(duplicate.validate().is_err());
        let mut response: ClipboardPresentationResponse = serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"ok":true,"presentation_version":2,"deleted_clips":{"operation_id":operation,"clip_ids":[first,second],"deleted_count":2}})).unwrap();
        assert!(response.validate_document_for(&command).is_ok());
        response.deleted_clips.as_mut().unwrap().clip_ids.reverse();
        assert!(response.validate_document_for(&command).is_err());
        response.deleted_clips.as_mut().unwrap().clip_ids.reverse();
        response.deleted_clips.as_mut().unwrap().deleted_count = 1;
        assert!(response.validate_document_for(&command).is_err());
        response.deleted_clips.as_mut().unwrap().deleted_count = 2;
        response.drafts = Some(Vec::new());
        assert!(response.validate_document_for(&command).is_err());
        response.drafts = None;
        response.ok = false;
        assert!(response.validate_document_for(&command).is_err());
    }
    #[test]
    fn ignore_next_copy_requires_cas_and_one_exclusive_current_receipt() {
        let operation = Uuid::new_v4();
        let request = Uuid::new_v4();
        let command = ClipboardProviderCommand::IgnoreNextCopy {
            value: true,
            expected_revision: 1,
            operation_id: operation,
        };
        assert!(command.validate().is_ok());
        assert!(ClipboardProviderCommand::IgnoreNextCopy {
            value: true,
            expected_revision: 0,
            operation_id: operation
        }
        .validate()
        .is_err());
        let mut response:ClipboardProviderResponse=serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":request,"ok":true,"ignore_next_copy":{"armed":false,"expires_at":null,"revision":3,"operation_id":operation}})).unwrap();
        assert!(response.validate_for(request).is_ok());
        response.ignore_next_copy.as_mut().unwrap().armed = true;
        assert!(response.validate_for(request).is_err());
        response.ignore_next_copy.as_mut().unwrap().armed = false;
        response.clips = Some(Vec::new());
        assert!(response.validate_for(request).is_err());
    }
    #[test]
    fn meaning_results_require_the_exact_generation_and_original_byte_range() {
        let operation = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let command: ClipboardPresentationCommand = serde_json::from_value(serde_json::json!({
            "kind":"presentation_semantic", "view_id":Uuid::new_v4(),
            "action":"query", "operation_id":operation, "generation_id":generation,
            "query":"remembered meaning"
        }))
        .unwrap();
        assert!(command.validate().is_ok());
        let fixture = serde_json::json!({"protocol":{"major":1,"minor":0},
            "request_id":Uuid::new_v4(),"ok":true,"presentation_version":2,
            "semantic":{"operation_id":operation,"generation_id":generation,
                "state":"complete","model":"local-qualified-model",
                "encoding_fingerprint":"a".repeat(64),"scope_count":3,
                "completed_fields":3,"total_fields":3,"error_code":null,
                "results":[{"clip_id":Uuid::new_v4(),"occurrence_id":Uuid::new_v4(),
                    "revision":7,"field_id":"native_text",
                    "representation_revision":format!("sha256:{}", "b".repeat(64)),
                    "start":1100040,"end":1100044,"score":-0.25,
                    "title":"Synthetic source","excerpt":"😀"}]}});
        let valid = |value| {
            serde_json::from_value::<ClipboardPresentationResponse>(value)
                .is_ok_and(|response| response.validate_document_for(&command).is_ok())
        };
        assert!(valid(fixture.clone()));
        for (key, value) in [
            ("generation_id", serde_json::json!(Uuid::new_v4())),
            ("operation_id", serde_json::json!(Uuid::new_v4())),
            ("encoding_fingerprint", serde_json::Value::Null),
            ("completed_fields", serde_json::json!(2)),
            ("state", serde_json::json!("preparing")),
        ] {
            let mut invalid = fixture.clone();
            invalid["semantic"][key] = value;
            assert!(!valid(invalid), "accepted {key}");
        }
        for (key, value) in [
            ("end", serde_json::json!(1100042)),
            ("field_id", serde_json::json!("recall_name")),
            ("score", serde_json::json!(1.01)),
            ("representation_revision", serde_json::json!("unverified")),
        ] {
            let mut invalid = fixture.clone();
            invalid["semantic"]["results"][0][key] = value;
            assert!(!valid(invalid), "accepted result {key}");
        }
        let mut mixed = fixture;
        mixed["drafts"] = serde_json::json!([]);
        assert!(!valid(mixed));
        let mut wire = serde_json::to_value(command).unwrap();
        wire.as_object_mut().unwrap().remove("generation_id");
        assert!(serde_json::from_value::<ClipboardPresentationCommand>(wire)
            .unwrap()
            .validate()
            .is_err());
    }

    #[test]
    fn meaning_preparation_requires_an_explicit_unique_bounded_scope() {
        let clip = Uuid::new_v4();
        let mut wire = serde_json::json!({"kind":"presentation_semantic", "view_id":Uuid::new_v4(),
            "action":"prepare", "operation_id":Uuid::new_v4(), "clip_ids":[clip]});
        let valid = |value| {
            serde_json::from_value::<ClipboardPresentationCommand>(value)
                .is_ok_and(|command| command.validate().is_ok())
        };
        assert!(valid(wire.clone()));
        wire["clip_ids"] = serde_json::json!([]);
        assert!(!valid(wire.clone()));
        wire["clip_ids"] = serde_json::json!([clip, clip]);
        assert!(!valid(wire.clone()));
        wire["clip_ids"] = serde_json::json!([clip]);
        wire["query"] = serde_json::json!("must not silently limit the source scope");
        assert!(!valid(wire.clone()));
        wire.as_object_mut().unwrap().remove("query");
        wire["action"] = serde_json::json!("status");
        assert!(!valid(wire));
    }
    #[test]
    fn ocr_chunk_contract_is_bounded_and_requires_an_owner_commit_receipt() {
        let id = Uuid::new_v4();
        let command:ClipboardPresentationCommand=serde_json::from_value(serde_json::json!({"kind":"presentation_preview_ocr_append","view_id":Uuid::new_v4(),"grant_id":Uuid::new_v4(),"offset":0,"total_bytes":4,"document_sha256":"a".repeat(64),"text":"😀","eof":true})).unwrap();
        assert!(command.validate().is_ok());
        let response:ClipboardPresentationResponse=serde_json::from_value(serde_json::json!({"protocol":{"major":1,"minor":0},"request_id":id,"ok":true,"presentation_version":2})).unwrap();
        assert!(response.validate_document_for(&command).is_err());
        let mut invalid = serde_json::to_value(&command).unwrap();
        invalid["total_bytes"] = 3.into();
        assert!(
            serde_json::from_value::<ClipboardPresentationCommand>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[cfg(test)]
mod clipboard_publication_contract_tests {
    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn document_copy(operation_id: Uuid) -> ClipboardPresentationCommand {
        ClipboardPresentationCommand::PresentationDocumentCopy {
            view_id: id(1),
            clip_id: id(2),
            occurrence_id: id(3),
            expected_revision: 7,
            representation_revision: format!("sha256:{}", "a".repeat(64)),
            start: 0,
            end: 4,
            operation_id,
            full_entry: false,
            field_id: None,
        }
    }

    fn publish(operation_id: Uuid, paste: bool, queued: bool) -> ClipboardPresentationCommand {
        ClipboardPresentationCommand::PresentationPublish {
            view_id: id(1),
            clip_id: id(2),
            expected_revision: 7,
            plain_text: false,
            paste,
            operation_id,
            queue_id: queued.then(|| id(4)),
            queue_revision: queued.then_some(3),
            queue_item_id: queued.then(|| id(5)),
        }
    }

    fn response(
        request_id: Uuid,
        operation_id: Uuid,
        state: &str,
        clipboard_sequence: u32,
        queue_advanced: bool,
    ) -> ClipboardPresentationResponse {
        serde_json::from_value(serde_json::json!({
            "protocol": {"major": 1, "minor": 0},
            "request_id": request_id,
            "ok": true,
            "error_code": null,
            "message": null,
            "presentation_version": 2,
            "receipt": {
                "operation_id": operation_id,
                "state": state,
                "clipboard_sequence": clipboard_sequence,
                "queue_advanced": queue_advanced
            }
        }))
        .unwrap()
    }

    fn valid(
        response: &ClipboardPresentationResponse,
        command: &ClipboardPresentationCommand,
        request_id: Uuid,
    ) -> bool {
        response.validate_for(request_id).is_ok() && response.validate_document_for(command).is_ok()
    }

    #[test]
    fn document_copy_requires_its_exact_exclusive_receipt() {
        let request_id = id(10);
        let operation_id = id(11);
        let command = document_copy(operation_id);
        assert!(command.validate().is_ok());

        let published = response(request_id, operation_id, "published", 19, false);
        assert!(valid(&published, &command, request_id));
        for state in ["blocked", "unknown"] {
            assert!(valid(
                &response(request_id, operation_id, state, 0, false),
                &command,
                request_id
            ));
        }

        let mut missing = published.clone();
        missing.receipt = None;
        assert!(missing.validate_for(request_id).is_ok());
        assert!(missing.validate_document_for(&command).is_err());

        let wrong_operation = response(request_id, id(12), "published", 19, false);
        assert!(wrong_operation.validate_for(request_id).is_ok());
        assert!(wrong_operation.validate_document_for(&command).is_err());

        let zero_sequence = response(request_id, operation_id, "published", 0, false);
        assert!(zero_sequence.validate_for(request_id).is_ok());
        assert!(zero_sequence.validate_document_for(&command).is_err());

        let dispatched = response(request_id, operation_id, "input_dispatched", 20, false);
        assert!(dispatched.validate_for(request_id).is_ok());
        assert!(dispatched.validate_document_for(&command).is_err());

        let advanced = response(request_id, operation_id, "published", 20, true);
        assert!(advanced.validate_for(request_id).is_ok());
        assert!(advanced.validate_document_for(&command).is_err());

        let mut extra_projection = published;
        extra_projection.page = Some(ClipboardPresentationPage {
            generation: 1,
            snapshot_sequence: 0,
            items: Vec::new(),
            has_more: false,
            search_progress: None,
        });
        assert!(extra_projection.validate_for(request_id).is_ok());
        assert!(extra_projection.validate_document_for(&command).is_err());
    }

    #[test]
    fn publish_receipt_state_and_sequence_match_the_requested_action() {
        let request_id = id(20);
        let operation_id = id(21);
        let copy = publish(operation_id, false, false);
        let paste = publish(operation_id, true, false);
        assert!(copy.validate().is_ok());
        assert!(paste.validate().is_ok());

        assert!(valid(
            &response(request_id, operation_id, "published", 30, false),
            &copy,
            request_id
        ));
        assert!(valid(
            &response(request_id, operation_id, "input_dispatched", 31, false),
            &paste,
            request_id
        ));
        for state in ["blocked", "unknown"] {
            assert!(valid(
                &response(request_id, operation_id, state, 0, false),
                &copy,
                request_id
            ));
            assert!(valid(
                &response(request_id, operation_id, state, 0, false),
                &paste,
                request_id
            ));
        }

        for (command, state) in [(&copy, "input_dispatched"), (&paste, "published")] {
            let impossible = response(request_id, operation_id, state, 32, false);
            assert!(impossible.validate_for(request_id).is_ok());
            assert!(impossible.validate_document_for(command).is_err());
        }

        let zero_sequence = response(request_id, operation_id, "input_dispatched", 0, false);
        assert!(zero_sequence.validate_for(request_id).is_ok());
        assert!(zero_sequence.validate_document_for(&paste).is_err());

        let mut missing = response(request_id, operation_id, "published", 33, false);
        missing.receipt = None;
        assert!(missing.validate_document_for(&copy).is_err());

        let wrong_operation = response(request_id, id(22), "published", 33, false);
        assert!(wrong_operation.validate_document_for(&copy).is_err());

        let mut extra_projection = response(request_id, operation_id, "published", 33, false);
        extra_projection.page = Some(ClipboardPresentationPage {
            generation: 1,
            snapshot_sequence: 0,
            items: Vec::new(),
            has_more: false,
            search_progress: None,
        });
        assert!(extra_projection.validate_document_for(&copy).is_err());
    }

    #[test]
    fn publish_queue_advance_is_exactly_bound_to_confirmed_queue_publication() {
        let request_id = id(30);
        let operation_id = id(31);
        let queued_copy = publish(operation_id, false, true);
        let queued_paste = publish(operation_id, true, true);
        let ordinary_copy = publish(operation_id, false, false);

        assert!(queued_copy.validate().is_err());
        assert!(valid(
            &response(request_id, operation_id, "input_dispatched", 41, true),
            &queued_paste,
            request_id
        ));
        for state in ["blocked", "unknown"] {
            assert!(valid(
                &response(request_id, operation_id, state, 0, false),
                &queued_paste,
                request_id
            ));
        }

        let unadvanced = response(request_id, operation_id, "published", 42, false);
        assert!(unadvanced.validate_for(request_id).is_ok());
        assert!(unadvanced.validate_document_for(&queued_copy).is_err());

        let unrelated_advance = response(request_id, operation_id, "published", 42, true);
        assert!(unrelated_advance.validate_for(request_id).is_ok());
        assert!(unrelated_advance
            .validate_document_for(&ordinary_copy)
            .is_err());

        let impossible_advance = response(request_id, operation_id, "unknown", 42, true);
        assert!(impossible_advance
            .validate_document_for(&queued_paste)
            .is_err());
    }
}
