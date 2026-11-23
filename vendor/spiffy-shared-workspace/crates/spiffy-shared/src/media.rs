use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::workflow::{validate_blake3, validate_text, validate_token};
use crate::{LeaseKind, LocalFileLease, ProtocolVersion, StableOwnerRef, MAX_LEASE_BYTES};

pub const MEDIA_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
pub const MEDIA_PRESET_SCHEMA_VERSION: u16 = 1;
pub const MEDIA_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const MAX_MEDIA_STREAMS: usize = 128;
pub const MAX_MEDIA_DIMENSION: u32 = 65_535;
pub const MAX_MEDIA_FRAME_RATE: f64 = 1_000.0;
pub const MAX_MEDIA_DURATION_MILLIS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const MAX_MEDIA_JOB_MILLIS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaFamily {
    Image,
    AnimatedImage,
    Video,
    Audio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaFormat {
    Png,
    Jpeg,
    Webp,
    Avif,
    Bmp,
    Tiff,
    Gif,
    Mp4,
    Mov,
    Mkv,
    Webm,
    Wav,
    Mp3,
    M4a,
    Flac,
    Opus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResizeMode {
    Fit,
    Fill,
    Contain,
    Stretch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlphaPolicy {
    Preserve,
    Discard,
    Composite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataPolicy {
    Strip,
    Safe,
    Preserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamPolicy {
    PreserveCompatible,
    FirstAudioVideo,
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediaPresetSpec {
    Image {
        format: MediaFormat,
        quality: Option<u8>,
        width: Option<u32>,
        height: Option<u32>,
        resize_mode: ResizeMode,
        alpha_policy: AlphaPolicy,
        background_rgba: Option<[u8; 4]>,
        color_profile: MetadataPolicy,
        metadata: MetadataPolicy,
    },
    AnimatedImage {
        format: MediaFormat,
        preserve_animation: bool,
        quality: Option<u8>,
        width: Option<u32>,
        height: Option<u32>,
        frame_rate: Option<f64>,
        still_frame_millis: Option<u64>,
    },
    Video {
        format: MediaFormat,
        video_codec: String,
        audio_codec: String,
        crf: Option<u8>,
        bitrate_kbps: Option<u32>,
        width: Option<u32>,
        height: Option<u32>,
        frame_rate: Option<f64>,
        pixel_format: Option<String>,
        audio_bitrate_kbps: Option<u32>,
        channels: Option<u8>,
        sample_rate: Option<u32>,
        maximum_bytes: Option<u64>,
        stream_policy: StreamPolicy,
        explicit_stream_indexes: Vec<u32>,
        allow_stream_copy: bool,
    },
    Audio {
        format: MediaFormat,
        codec: String,
        sample_rate: Option<u32>,
        channels: Option<u8>,
        bit_depth: Option<u8>,
        bitrate_kbps: Option<u32>,
        metadata: MetadataPolicy,
        normalize_loudness: bool,
    },
}

impl MediaPresetSpec {
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Image {
                format,
                quality,
                width,
                height,
                alpha_policy,
                background_rgba,
                ..
            } => {
                if !matches!(
                    format,
                    MediaFormat::Png
                        | MediaFormat::Jpeg
                        | MediaFormat::Webp
                        | MediaFormat::Avif
                        | MediaFormat::Bmp
                        | MediaFormat::Tiff
                ) {
                    return Err("image preset uses a non-image format");
                }
                validate_quality(*quality)?;
                validate_dimensions(*width, *height)?;
                if *format == MediaFormat::Jpeg && *alpha_policy == AlphaPolicy::Preserve {
                    return Err("JPEG preset cannot preserve alpha");
                }
                if *alpha_policy == AlphaPolicy::Composite && background_rgba.is_none() {
                    return Err("composite alpha policy requires a background color");
                }
            }
            Self::AnimatedImage {
                format,
                preserve_animation,
                quality,
                width,
                height,
                frame_rate,
                still_frame_millis,
            } => {
                if !matches!(
                    format,
                    MediaFormat::Gif | MediaFormat::Webp | MediaFormat::Mp4 | MediaFormat::Webm
                ) {
                    return Err("animated-image preset uses an unsupported format");
                }
                validate_quality(*quality)?;
                validate_dimensions(*width, *height)?;
                validate_frame_rate(*frame_rate)?;
                if *preserve_animation && still_frame_millis.is_some() {
                    return Err("animation-preserving preset cannot also extract a still frame");
                }
                if still_frame_millis.is_some_and(|value| value > MAX_MEDIA_DURATION_MILLIS) {
                    return Err("still-frame timestamp exceeds 30 days");
                }
            }
            Self::Video {
                format,
                video_codec,
                audio_codec,
                crf,
                bitrate_kbps,
                width,
                height,
                frame_rate,
                pixel_format,
                audio_bitrate_kbps,
                channels,
                sample_rate,
                maximum_bytes,
                stream_policy,
                explicit_stream_indexes,
                ..
            } => {
                if !matches!(
                    format,
                    MediaFormat::Mp4 | MediaFormat::Mov | MediaFormat::Mkv | MediaFormat::Webm
                ) {
                    return Err("video preset uses a non-video format");
                }
                validate_token(video_codec, 64, "video codec")?;
                validate_token(audio_codec, 64, "audio codec")?;
                if crf.is_some_and(|value| value > 63) {
                    return Err("video CRF must be between 0 and 63");
                }
                if bitrate_kbps.is_some_and(|value| value == 0 || value > 1_000_000) {
                    return Err("video bitrate must be between 1 and 1000000 kbps");
                }
                validate_dimensions(*width, *height)?;
                validate_frame_rate(*frame_rate)?;
                if let Some(value) = pixel_format {
                    validate_token(value, 64, "pixel format")?;
                }
                validate_audio_shape(*channels, *sample_rate)?;
                if audio_bitrate_kbps.is_some_and(|value| value == 0 || value > 10_000) {
                    return Err("audio bitrate must be between 1 and 10000 kbps");
                }
                if maximum_bytes.is_some_and(|value| value == 0 || value > MAX_LEASE_BYTES) {
                    return Err("video size target must be between 1 byte and 100 GiB");
                }
                if explicit_stream_indexes.len() > MAX_MEDIA_STREAMS {
                    return Err("video preset permits at most 128 explicit streams");
                }
                if explicit_stream_indexes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != explicit_stream_indexes.len()
                {
                    return Err("video explicit stream indexes must be unique");
                }
                if *stream_policy == StreamPolicy::Explicit && explicit_stream_indexes.is_empty() {
                    return Err("explicit stream policy requires stream indexes");
                }
            }
            Self::Audio {
                format,
                codec,
                sample_rate,
                channels,
                bit_depth,
                bitrate_kbps,
                ..
            } => {
                if !matches!(
                    format,
                    MediaFormat::Wav
                        | MediaFormat::Mp3
                        | MediaFormat::M4a
                        | MediaFormat::Flac
                        | MediaFormat::Opus
                ) {
                    return Err("audio preset uses a non-audio format");
                }
                validate_token(codec, 64, "audio codec")?;
                validate_audio_shape(*channels, *sample_rate)?;
                if bit_depth.is_some_and(|value| !matches!(value, 8 | 16 | 24 | 32 | 64)) {
                    return Err("audio bit depth is unsupported");
                }
                if bitrate_kbps.is_some_and(|value| value == 0 || value > 10_000) {
                    return Err("audio bitrate must be between 1 and 10000 kbps");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaPresetContract {
    pub schema_version: u16,
    pub preset_id: String,
    pub preset_version: u16,
    pub display_name: String,
    pub spec: MediaPresetSpec,
    pub filename_suffix: String,
    pub set_as_current_clipboard: bool,
}

impl MediaPresetContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != MEDIA_PRESET_SCHEMA_VERSION || self.preset_version == 0 {
            return Err("media preset schema or preset version is unsupported");
        }
        validate_token(&self.preset_id, 128, "media preset ID")?;
        validate_text(&self.display_name, 256, "media preset display name")?;
        if self.filename_suffix.chars().count() > 128 || self.filename_suffix.contains(['/', '\\'])
        {
            return Err("media filename suffix is unsafe or exceeds 128 characters");
        }
        self.spec.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaJobRequest {
    pub protocol: ProtocolVersion,
    pub job_id: Uuid,
    pub correlation_id: Uuid,
    pub requesting_owner_id: String,
    pub input: StableOwnerRef,
    pub input_lease: LocalFileLease,
    pub output_lease: LocalFileLease,
    pub preset: MediaPresetContract,
    pub requested_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

impl MediaJobRequest {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if !self.protocol.is_compatible_with(MEDIA_PROTOCOL_VERSION) {
            return Err("media protocol major is incompatible");
        }
        if self.job_id.is_nil() || self.correlation_id.is_nil() {
            return Err("media job and correlation IDs must not be nil");
        }
        validate_token(&self.requesting_owner_id, 128, "media requesting owner ID")?;
        self.input.validate()?;
        self.input_lease.validate(now)?;
        self.output_lease.validate(now)?;
        if self.input_lease.kind != LeaseKind::Input || self.output_lease.kind != LeaseKind::Output
        {
            return Err("media jobs require input and output lease kinds");
        }
        if self.input_lease.lease_id == self.output_lease.lease_id {
            return Err("media input and output leases must be distinct");
        }
        if self.output_lease.owner_id != self.requesting_owner_id {
            return Err("media output lease must belong to the requesting owner");
        }
        self.preset.validate()?;
        if self.deadline <= self.requested_at || self.deadline <= now {
            return Err("media job deadline must be in the future and after request time");
        }
        if (self.deadline - self.requested_at).num_milliseconds() > MAX_MEDIA_JOB_MILLIS {
            return Err("media job deadline exceeds the 24-hour maximum");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaStreamProbe {
    pub index: u32,
    pub codec_type: String,
    pub codec_name: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub frame_rate: Option<f64>,
    pub sample_rate: Option<u32>,
    pub channels: Option<u8>,
}

impl MediaStreamProbe {
    fn validate(&self) -> Result<(), &'static str> {
        validate_token(&self.codec_type, 32, "media codec type")?;
        validate_token(&self.codec_name, 64, "media codec name")?;
        validate_dimensions(self.width, self.height)?;
        validate_frame_rate(self.frame_rate)?;
        validate_audio_shape(self.channels, self.sample_rate)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaProbeContract {
    pub format_name: String,
    pub byte_len: u64,
    pub duration_millis: Option<u64>,
    pub streams: Vec<MediaStreamProbe>,
}

impl MediaProbeContract {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_token(&self.format_name, 128, "media format name")?;
        if self
            .duration_millis
            .is_some_and(|value| value > MAX_MEDIA_DURATION_MILLIS)
        {
            return Err("media duration exceeds 30 days");
        }
        if self.streams.len() > MAX_MEDIA_STREAMS {
            return Err("media probe permits at most 128 streams");
        }
        for stream in &self.streams {
            stream.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaJobState {
    Queued,
    DeferredForCapture,
    Probing,
    Processing,
    Verifying,
    Succeeded,
    Cancelled,
    Failed,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaJobReceipt {
    pub schema_version: u16,
    pub job_id: Uuid,
    pub correlation_id: Uuid,
    pub state: MediaJobState,
    pub input: StableOwnerRef,
    pub input_blake3: String,
    pub output: Option<StableOwnerRef>,
    pub output_blake3: Option<String>,
    pub output_probe: Option<MediaProbeContract>,
    pub preset_id: String,
    pub preset_version: u16,
    pub source_unchanged: bool,
    pub source_current: bool,
    pub cleanup_complete: bool,
    pub error_code: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
}

impl MediaJobReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != MEDIA_RECEIPT_SCHEMA_VERSION
            || self.job_id.is_nil()
            || self.correlation_id.is_nil()
            || self.preset_version == 0
        {
            return Err("media receipt version and IDs are invalid");
        }
        self.input.validate()?;
        validate_blake3(&self.input_blake3)?;
        validate_token(&self.preset_id, 128, "media preset ID")?;
        if let Some(output) = &self.output {
            output.validate()?;
        }
        if let Some(digest) = &self.output_blake3 {
            validate_blake3(digest)?;
        }
        if let Some(probe) = &self.output_probe {
            probe.validate()?;
        }
        if let Some(error) = &self.error_code {
            validate_token(error, 128, "media error code")?;
        }
        if self.ended_at < self.started_at {
            return Err("media receipt ends before it starts");
        }
        if self.state == MediaJobState::Succeeded
            && (self.output.is_none()
                || self.output_blake3.is_none()
                || self.output_probe.is_none()
                || self.error_code.is_some()
                || !self.source_unchanged
                || !self.source_current)
        {
            return Err("successful media receipt lacks verified current output");
        }
        Ok(())
    }
}

fn validate_quality(value: Option<u8>) -> Result<(), &'static str> {
    if value.is_some_and(|quality| quality > 100) {
        return Err("media quality must be between 0 and 100");
    }
    Ok(())
}

fn validate_dimensions(width: Option<u32>, height: Option<u32>) -> Result<(), &'static str> {
    for value in [width, height].into_iter().flatten() {
        if value == 0 || value > MAX_MEDIA_DIMENSION {
            return Err("media dimension must be between 1 and 65535");
        }
    }
    Ok(())
}

fn validate_frame_rate(value: Option<f64>) -> Result<(), &'static str> {
    if value.is_some_and(|rate| !rate.is_finite() || rate <= 0.0 || rate > MAX_MEDIA_FRAME_RATE) {
        return Err("media frame rate must be finite and between 0 and 1000");
    }
    Ok(())
}

fn validate_audio_shape(
    channels: Option<u8>,
    sample_rate: Option<u32>,
) -> Result<(), &'static str> {
    if channels.is_some_and(|value| value == 0 || value > 64) {
        return Err("audio channel count must be between 1 and 64");
    }
    if sample_rate.is_some_and(|value| !(8_000..=768_000).contains(&value)) {
        return Err("audio sample rate must be between 8000 and 768000");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_rejects_alpha_preservation_without_mutating_source() {
        let preset = MediaPresetContract {
            schema_version: MEDIA_PRESET_SCHEMA_VERSION,
            preset_id: "image.jpeg.default".to_string(),
            preset_version: 1,
            display_name: "JPEG".to_string(),
            spec: MediaPresetSpec::Image {
                format: MediaFormat::Jpeg,
                quality: Some(90),
                width: None,
                height: None,
                resize_mode: ResizeMode::Fit,
                alpha_policy: AlphaPolicy::Preserve,
                background_rgba: None,
                color_profile: MetadataPolicy::Safe,
                metadata: MetadataPolicy::Safe,
            },
            filename_suffix: "-jpeg".to_string(),
            set_as_current_clipboard: false,
        };
        assert_eq!(preset.validate(), Err("JPEG preset cannot preserve alpha"));
    }

    #[test]
    fn animated_preserve_and_still_extraction_are_mutually_exclusive() {
        let spec = MediaPresetSpec::AnimatedImage {
            format: MediaFormat::Gif,
            preserve_animation: true,
            quality: None,
            width: None,
            height: None,
            frame_rate: None,
            still_frame_millis: Some(500),
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn successful_receipts_require_hash_probe_and_current_source() {
        let now = Utc::now();
        let reference = StableOwnerRef {
            owner_id: "spiffy.shelf".to_string(),
            entity_id: "item-1".to_string(),
            entity_kind: "shelf_item".to_string(),
            revision: 1,
            digest_blake3: "aa".repeat(32),
        };
        let receipt = MediaJobReceipt {
            schema_version: MEDIA_RECEIPT_SCHEMA_VERSION,
            job_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            state: MediaJobState::Succeeded,
            input: reference,
            input_blake3: "aa".repeat(32),
            output: None,
            output_blake3: None,
            output_probe: None,
            preset_id: "video.mp4.default".to_string(),
            preset_version: 1,
            source_unchanged: true,
            source_current: true,
            cleanup_complete: true,
            error_code: None,
            started_at: now,
            ended_at: now,
        };
        assert_eq!(
            receipt.validate(),
            Err("successful media receipt lacks verified current output")
        );
    }

    #[test]
    fn preset_contracts_deny_unknown_fields() {
        let encoded = serde_json::json!({
            "schema_version": 1,
            "preset_id": "audio.wav.default",
            "preset_version": 1,
            "display_name": "WAV",
            "spec": {
                "family": "audio",
                "format": "wav",
                "codec": "pcm_s24le",
                "sample_rate": 48000,
                "channels": 2,
                "bit_depth": 24,
                "bitrate_kbps": null,
                "metadata": "safe",
                "normalize_loudness": false,
                "surprise": true
            },
            "filename_suffix": "-wav",
            "set_as_current_clipboard": false
        });
        assert!(serde_json::from_value::<MediaPresetContract>(encoded).is_err());
    }
}
