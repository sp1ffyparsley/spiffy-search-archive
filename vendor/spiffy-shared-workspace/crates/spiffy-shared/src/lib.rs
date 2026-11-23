#![forbid(unsafe_code)]

pub mod action;
pub mod contracts;
pub mod cross_shelf;
pub mod cross_shelf_control;
pub mod events;
pub mod framing;
pub mod identity;
pub mod ipc;
pub mod media;
pub mod paths;
pub mod provider;
pub mod security;
pub mod shelf_search;
pub mod workflow;

pub use action::{
    ActionAuthorizationScope, ActionDispatchPacket, ActionProgress, ActionProviderIdentity,
    ActionProviderManifest, ActionReceipt, ActionRunState, AuthenticationPolicy,
    ConfirmationPolicy, IdempotencePolicy, SourceMutationPolicy, SourceMutationState,
    ACTION_MANIFEST_SCHEMA_VERSION, ACTION_PROTOCOL_VERSION, ACTION_RECEIPT_SCHEMA_VERSION,
    MAX_ACTION_CAPABILITIES, MAX_ACTION_MESSAGES, MAX_ACTION_PARAMETERS_BYTES,
    MAX_ACTION_RELATIONS, MAX_ACTION_SELECTIONS, MAX_ACTION_TIMEOUT_MILLIS,
};

pub use contracts::{
    AppKind, Envelope, HealthReport, ProtocolVersion, RemoteAvailability, RemoteResultResolution,
    RemoteSearchQuery, RemoteSearchResponse, SearchResultContract, SearchServiceCommand,
    ShelfItemContract, ShelfItemKind, TransferReceipt, TransferState,
    MAX_REMOTE_SEARCH_QUERY_CHARS, MAX_REMOTE_SEARCH_RESULTS, MAX_REMOTE_SEARCH_ROOTS,
    PROTOCOL_VERSION, REMOTE_SEARCH_LEASE_SECONDS, SEARCH_PROTOCOL_VERSION,
    SEARCH_SERVICE_PROTOCOL_MINOR,
};
pub use cross_shelf::{
    normalize_follow_me_folder_path, ClipboardItemContract, ClipboardKind, ClipboardMode,
    DeviceMode, DevicePlatform, DeviceTrustState, RemoteClipboardSnapshot,
    RemoteClipboardSnapshotItem, ShelfEntityKind, ShelfEventOperation, ShelfMutationContract,
    SignedShelfEventContract, TransferChunkContract, TransferDecision, TransferOfferContract,
    TransferResumeContract, TransferThumbnailContract, CROSS_SEARCH_PROTOCOL_MINOR,
    CROSS_SHELF_PROTOCOL_VERSION, DEFAULT_TRANSFER_CHUNK_BYTES, FOLLOW_ME_FOLDER_TAR_V1,
    FOLLOW_ME_SHELF_PROTOCOL_MINOR, FOLLOW_ME_TRANSFER_KIND_METADATA, MAX_FOLLOW_ME_CONTENT_BYTES,
    MAX_FOLLOW_ME_FOLDER_DEPTH, MAX_FOLLOW_ME_FOLDER_ENTRIES, MAX_FOLLOW_ME_FOLDER_PATH_BYTES,
    MAX_FOLLOW_ME_ITEMS, REMOTE_CLIPBOARD_SNAPSHOT_PROTOCOL_MINOR,
};
pub use cross_shelf_control::{
    CrossShelfControlCommand, CrossShelfControlReply, CrossShelfIpcEndpoint, CrossShelfIpcRequest,
    PendingShelfEventContract, CROSS_SHELF_IPC_ENDPOINT_SCHEMA_VERSION,
    CROSS_SHELF_MAX_IPC_FRAME_BYTES, MAX_FOLLOW_ME_WAIT_MILLIS, MAX_PENDING_SHELF_EVENTS,
};
pub use framing::{read_json_frame, write_json_frame, FrameError, DEFAULT_MAX_FRAME_BYTES};
pub use identity::{DeviceIdentity, StableFileIdentity};
pub use ipc::{
    AuthenticatedLocalEndpoint, AuthenticatedLocalRequest, LocalIpcEndpoint, LocalIpcRequest,
    LocalTransportEndpoint, AUTHENTICATED_LOCAL_ENDPOINT_SCHEMA_VERSION,
    LOCAL_IPC_ENDPOINT_SCHEMA_VERSION, MAX_LOCAL_REQUEST_LIFETIME_SECONDS,
    MAX_UNIX_SOCKET_PATH_BYTES, MAX_WINDOWS_PIPE_NAME_CHARS,
};
pub use media::{
    AlphaPolicy, MediaFamily, MediaFormat, MediaJobReceipt, MediaJobRequest, MediaJobState,
    MediaPresetContract, MediaPresetSpec, MediaProbeContract, MediaStreamProbe, MetadataPolicy,
    ResizeMode, StreamPolicy, MAX_MEDIA_DIMENSION, MAX_MEDIA_DURATION_MILLIS, MAX_MEDIA_FRAME_RATE,
    MAX_MEDIA_JOB_MILLIS, MAX_MEDIA_STREAMS, MEDIA_PRESET_SCHEMA_VERSION, MEDIA_PROTOCOL_VERSION,
    MEDIA_RECEIPT_SCHEMA_VERSION,
};
pub use paths::{
    cross_shelf_cache_dir, cross_shelf_data_dir, cross_shelf_staging_dir, product_cache_dir,
    product_data_dir, product_log_dir, Product,
};
pub use provider::{
    ClipboardCapturePipelineStatus, ClipboardProviderClip, ClipboardProviderCommand,
    ClipboardProviderFavorite, ClipboardProviderPack, ClipboardProviderQueue,
    ClipboardProviderResponse, ClipboardProviderSection, ClipboardProviderStatus, PasteQueueAction,
    PasteQueueMode, CLIPBOARD_PROVIDER_DISCOVERY_RELATIVE_PATH, CLIPBOARD_PROVIDER_MAX_FRAME_BYTES,
    CLIPBOARD_PROVIDER_MAX_MUTATION_ITEMS, CLIPBOARD_PROVIDER_MAX_NAME_CHARS,
    CLIPBOARD_PROVIDER_MAX_PAGE_ITEMS, CLIPBOARD_PROVIDER_MAX_QUERY_CHARS,
    CLIPBOARD_PROVIDER_PROTOCOL_VERSION,
};
pub use security::{classify_clipboard, IpcAuthToken, SensitiveClipboardInput};
pub use workflow::{
    AppRecipeContract, CaptureKind, CapturePublication, LeaseKind, LeaseState, LocalFileLease,
    ProjectContextContract, RecordingOrigin, RelationKind, SecurityProfile, ShelfSelectionRef,
    StableOwnerRef, StackContract, StackMemberContract, StorageClass, VariantContract,
    WorkflowRelation, MAX_DISPLAY_NAME_CHARS, MAX_ENTITY_ID_CHARS, MAX_LEASE_BYTES,
    MAX_OWNER_ID_CHARS, MAX_RECIPE_DEPENDENCIES, MAX_RECIPE_PAYLOAD_BYTES, MAX_RELATION_MEMBERS,
    WORKFLOW_PROTOCOL_VERSION,
};
