use crate::config::ContentConfig;
use crate::error::{io_error, SearchError, SearchResult};
use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use quick_xml::Reader as XmlReader;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use zip::ZipArchive;

const WORKER_PROTOCOL_VERSION: u16 = 1;
const MAX_WORKER_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_WORKER_HEADER_BYTES: usize = 64 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_PDF_PAGES: usize = 10_000;
const MIN_PDF_STREAM_LIMIT: usize = 8 * 1024 * 1024;
const MAX_PDF_STREAM_LIMIT: usize = 64 * 1024 * 1024;
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionRequest {
    pub protocol_version: u16,
    pub path: String,
    pub max_file_bytes: u64,
    pub max_extracted_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionErrorCode {
    Missing,
    NotFile,
    Symlink,
    Oversized,
    Unsupported,
    InvalidSignature,
    BinaryContent,
    Corrupt,
    Io,
    Cancelled,
    Timeout,
    WorkerUnavailable,
    WorkerProtocol,
    WorkerCrashed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionFailure {
    pub code: ExtractionErrorCode,
    pub message: String,
}

impl ExtractionFailure {
    fn new(code: ExtractionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractedContent {
    pub mime_type: String,
    pub text: String,
    pub truncated: bool,
    pub source_size: u64,
    pub modified_time_millis: Option<i64>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerHeader {
    protocol_version: u16,
    ok: bool,
    content_bytes: u64,
    mime_type: Option<String>,
    truncated: bool,
    source_size: u64,
    modified_time_millis: Option<i64>,
    digest: Option<String>,
    error: Option<ExtractionFailure>,
}

#[derive(Debug, Clone)]
enum WorkerBackend {
    Process(PathBuf),
    #[cfg(test)]
    InProcess,
}

#[derive(Debug, Clone)]
pub struct ContentWorkerClient {
    backend: WorkerBackend,
}

impl ContentWorkerClient {
    pub fn discover() -> SearchResult<Self> {
        let current =
            std::env::current_exe().map_err(|error| io_error("current executable", error))?;
        let filename = if cfg!(windows) {
            "spiffy-search-content-worker.exe"
        } else {
            "spiffy-search-content-worker"
        };
        let path = current
            .parent()
            .ok_or_else(|| {
                SearchError::Content(
                    "content worker executable has no parent directory".to_string(),
                )
            })?
            .join(filename);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            SearchError::Content(format!(
                "content worker is missing beside the agent at {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(SearchError::Content(format!(
                "content worker is not a normal file: {}",
                path.display()
            )));
        }
        Ok(Self {
            backend: WorkerBackend::Process(path),
        })
    }

    #[cfg(test)]
    pub(crate) fn in_process() -> Self {
        Self {
            backend: WorkerBackend::InProcess,
        }
    }

    pub fn extract(
        &self,
        path: &Path,
        config: &ContentConfig,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ExtractedContent, ExtractionFailure> {
        if cancellation.load(Ordering::Acquire) {
            return Err(ExtractionFailure::new(
                ExtractionErrorCode::Cancelled,
                "content extraction was cancelled",
            ));
        }
        let request = ExtractionRequest {
            protocol_version: WORKER_PROTOCOL_VERSION,
            path: path.to_string_lossy().to_string(),
            max_file_bytes: config.max_file_bytes,
            max_extracted_bytes: config.max_extracted_bytes,
        };
        match &self.backend {
            WorkerBackend::Process(worker) => run_worker_process(
                worker,
                &request,
                Duration::from_secs(u64::from(config.timeout_seconds)),
                cancellation,
            ),
            #[cfg(test)]
            WorkerBackend::InProcess => extract_request(&request),
        }
    }
}

pub fn run_worker_stdio() -> i32 {
    let result = read_worker_request(std::io::stdin().lock()).and_then(|request| {
        let response = extract_request(&request);
        write_worker_response(std::io::stdout().lock(), response)
            .map_err(|error| ExtractionFailure::new(ExtractionErrorCode::Io, error.to_string()))
    });
    match result {
        Ok(()) => 0,
        Err(failure) => {
            let _ = write_worker_response(std::io::stdout().lock(), Err(failure));
            2
        }
    }
}

pub fn supported_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "txt"
            | "md"
            | "rs"
            | "py"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "css"
            | "toml"
            | "yaml"
            | "yml"
            | "c"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "java"
            | "swift"
            | "kt"
            | "go"
            | "rb"
            | "php"
            | "sh"
            | "ps1"
            | "ahk"
            | "json"
            | "xml"
            | "csv"
            | "html"
            | "htm"
            | "rtf"
            | "srt"
            | "vtt"
            | "pdf"
            | "docx"
            | "pptx"
            | "xlsx"
            | "odt"
            | "ods"
            | "odp"
            | "epub"
    )
}

fn run_worker_process(
    worker: &Path,
    request: &ExtractionRequest,
    timeout: Duration,
    cancellation: Arc<AtomicBool>,
) -> Result<ExtractedContent, ExtractionFailure> {
    let mut command = Command::new(worker);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerUnavailable,
            format!("could not start isolated content worker: {error}"),
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker stdout was not available",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker stderr was not available",
        )
    })?;
    let max_content = usize::try_from(request.max_extracted_bytes).map_err(|_| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "configured extraction limit exceeds this platform",
        )
    })?;
    let stdout_thread = thread::spawn(move || read_worker_response(stdout, max_content));
    let stderr_thread = thread::spawn(move || read_capped_and_drain(stderr, 16 * 1024));

    let encoded = serde_json::to_vec(request).map_err(|error| {
        ExtractionFailure::new(ExtractionErrorCode::WorkerProtocol, error.to_string())
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(error) = stdin.write_all(&encoded).and_then(|_| stdin.flush()) {
            terminate_child(&mut child);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(ExtractionFailure::new(
                ExtractionErrorCode::WorkerProtocol,
                format!("could not send request to content worker: {error}"),
            ));
        }
    } else {
        terminate_child(&mut child);
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker stdin was not available",
        ));
    }

    let started = Instant::now();
    let status = loop {
        if cancellation.load(Ordering::Acquire) {
            terminate_child(&mut child);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(ExtractionFailure::new(
                ExtractionErrorCode::Cancelled,
                "content extraction was cancelled",
            ));
        }
        if started.elapsed() >= timeout {
            terminate_child(&mut child);
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(ExtractionFailure::new(
                ExtractionErrorCode::Timeout,
                "content extraction exceeded its configured timeout",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(WORKER_POLL_INTERVAL),
            Err(error) => {
                terminate_child(&mut child);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(ExtractionFailure::new(
                    ExtractionErrorCode::WorkerCrashed,
                    format!("could not monitor content worker: {error}"),
                ));
            }
        }
    };
    let response = stdout_thread.join().map_err(|_| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerCrashed,
            "content worker response reader panicked",
        )
    })?;
    let stderr = stderr_thread.join().unwrap_or_default();
    match response {
        Ok(value) if status.success() => Ok(value),
        Ok(_) => Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerCrashed,
            "content worker exited unsuccessfully after returning success",
        )),
        Err(failure) => Err(failure),
    }
    .map_err(|mut failure| {
        if failure.code == ExtractionErrorCode::WorkerCrashed && !stderr.is_empty() {
            failure.message = format!("{}; worker diagnostic: {stderr}", failure.message);
        }
        failure
    })
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_worker_request(mut reader: impl Read) -> Result<ExtractionRequest, ExtractionFailure> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_WORKER_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ExtractionFailure::new(ExtractionErrorCode::Io, error.to_string()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_WORKER_REQUEST_BYTES {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker request is empty or oversized",
        ));
    }
    let request: ExtractionRequest = serde_json::from_slice(&bytes).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            format!("content worker request is invalid: {error}"),
        )
    })?;
    validate_request(&request)?;
    Ok(request)
}

fn validate_request(request: &ExtractionRequest) -> Result<(), ExtractionFailure> {
    if request.protocol_version != WORKER_PROTOCOL_VERSION
        || request.path.is_empty()
        || request.path.len() > 32_768
        || !(64 * 1024..=1024 * 1024 * 1024).contains(&request.max_file_bytes)
        || !(4 * 1024..=32 * 1024 * 1024).contains(&request.max_extracted_bytes)
    {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker request is outside supported limits",
        ));
    }
    Ok(())
}

fn write_worker_response(
    mut writer: impl Write,
    response: Result<ExtractedContent, ExtractionFailure>,
) -> std::io::Result<()> {
    let (header, content) = match response {
        Ok(content) => (
            WorkerHeader {
                protocol_version: WORKER_PROTOCOL_VERSION,
                ok: true,
                content_bytes: content.text.len() as u64,
                mime_type: Some(content.mime_type),
                truncated: content.truncated,
                source_size: content.source_size,
                modified_time_millis: content.modified_time_millis,
                digest: Some(content.digest),
                error: None,
            },
            content.text.into_bytes(),
        ),
        Err(error) => (
            WorkerHeader {
                protocol_version: WORKER_PROTOCOL_VERSION,
                ok: false,
                content_bytes: 0,
                mime_type: None,
                truncated: false,
                source_size: 0,
                modified_time_millis: None,
                digest: None,
                error: Some(error),
            },
            Vec::new(),
        ),
    };
    let encoded = serde_json::to_vec(&header).map_err(std::io::Error::other)?;
    let header_len = u32::try_from(encoded.len())
        .map_err(|_| std::io::Error::other("content worker header is too large"))?;
    writer.write_all(&header_len.to_le_bytes())?;
    writer.write_all(&encoded)?;
    writer.write_all(&content)?;
    writer.flush()
}

fn read_worker_response(
    mut reader: impl Read,
    max_content: usize,
) -> Result<ExtractedContent, ExtractionFailure> {
    let mut header_len = [0_u8; 4];
    reader.read_exact(&mut header_len).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            format!("content worker response header is missing: {error}"),
        )
    })?;
    let header_len = u32::from_le_bytes(header_len) as usize;
    if header_len == 0 || header_len > MAX_WORKER_HEADER_BYTES {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker response header is oversized",
        ));
    }
    let mut header_bytes = vec![0_u8; header_len];
    reader.read_exact(&mut header_bytes).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            format!("content worker response header is incomplete: {error}"),
        )
    })?;
    let header: WorkerHeader = serde_json::from_slice(&header_bytes).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            format!("content worker response header is invalid: {error}"),
        )
    })?;
    if header.protocol_version != WORKER_PROTOCOL_VERSION {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker protocol version is incompatible",
        ));
    }
    if !header.ok {
        return Err(header.error.unwrap_or_else(|| {
            ExtractionFailure::new(
                ExtractionErrorCode::WorkerProtocol,
                "content worker failure omitted its error",
            )
        }));
    }
    let content_len = usize::try_from(header.content_bytes).map_err(|_| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker response exceeds this platform",
        )
    })?;
    if content_len > max_content || header.error.is_some() {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker response is inconsistent or oversized",
        ));
    }
    let mut content = vec![0_u8; content_len];
    reader.read_exact(&mut content).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            format!("content worker response body is incomplete: {error}"),
        )
    })?;
    let text = String::from_utf8(content).map_err(|_| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "content worker returned non-UTF-8 text",
        )
    })?;
    Ok(ExtractedContent {
        mime_type: header.mime_type.ok_or_else(|| {
            ExtractionFailure::new(
                ExtractionErrorCode::WorkerProtocol,
                "content worker success omitted MIME type",
            )
        })?,
        text,
        truncated: header.truncated,
        source_size: header.source_size,
        modified_time_millis: header.modified_time_millis,
        digest: header.digest.ok_or_else(|| {
            ExtractionFailure::new(
                ExtractionErrorCode::WorkerProtocol,
                "content worker success omitted digest",
            )
        })?,
    })
}

fn read_capped_and_drain(mut reader: impl Read, cap: usize) -> String {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let remaining = cap.saturating_sub(output.len());
                output.extend_from_slice(&buffer[..read.min(remaining)]);
            }
        }
    }
    String::from_utf8_lossy(&output).trim().to_string()
}

fn extract_request(request: &ExtractionRequest) -> Result<ExtractedContent, ExtractionFailure> {
    validate_request(request)?;
    let path = Path::new(&request.path);
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ExtractionFailure::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                ExtractionErrorCode::Missing
            } else {
                ExtractionErrorCode::Io
            },
            format!("could not inspect content source: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Symlink,
            "content extraction does not follow symbolic links",
        ));
    }
    if !metadata.is_file() {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::NotFile,
            "content extraction requires a normal file",
        ));
    }
    if metadata.len() > request.max_file_bytes {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Oversized,
            "content source exceeds the configured file-size limit",
        ));
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !supported_extension(&extension) {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Unsupported,
            "content source format is unsupported",
        ));
    }
    let bytes = read_file_bounded(path, request.max_file_bytes)?;
    validate_signature(&extension, &bytes)?;
    let max_text = usize::try_from(request.max_extracted_bytes).map_err(|_| {
        ExtractionFailure::new(
            ExtractionErrorCode::WorkerProtocol,
            "configured extraction limit exceeds this platform",
        )
    })?;
    let (mime_type, mut collector) = extract_bytes(&extension, &bytes, max_text)?;
    collector.finish();
    let modified_time_millis = metadata
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .map(|value| value.timestamp_millis());
    Ok(ExtractedContent {
        mime_type,
        text: collector.text,
        truncated: collector.truncated,
        source_size: metadata.len(),
        modified_time_millis,
        digest: blake3::hash(&bytes).to_hex().to_string(),
    })
}

fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ExtractionFailure> {
    let file = fs::File::open(path).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::Io,
            format!("could not open content source: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ExtractionFailure::new(
                ExtractionErrorCode::Io,
                format!("could not read content source: {error}"),
            )
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Oversized,
            "content source exceeded the configured limit while reading",
        ));
    }
    Ok(bytes)
}

fn validate_signature(extension: &str, bytes: &[u8]) -> Result<(), ExtractionFailure> {
    if extension == "pdf" && !bytes.starts_with(b"%PDF-") {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::InvalidSignature,
            "PDF signature is missing",
        ));
    }
    if matches!(
        extension,
        "docx" | "pptx" | "xlsx" | "odt" | "ods" | "odp" | "epub"
    ) && !(bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08"))
    {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::InvalidSignature,
            "ZIP-based document signature is missing",
        ));
    }
    Ok(())
}

fn extract_bytes(
    extension: &str,
    bytes: &[u8],
    max_text: usize,
) -> Result<(String, TextCollector), ExtractionFailure> {
    let mut collector = TextCollector::new(max_text);
    let fallback_mime = mime_guess::from_ext(extension).first_or_text_plain();
    let mime_type = match extension {
        "pdf" => {
            extract_pdf(bytes, max_text, &mut collector)?;
            "application/pdf"
        }
        "docx" => {
            extract_archive(bytes, ArchiveKind::Docx, &mut collector)?;
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        "pptx" => {
            extract_archive(bytes, ArchiveKind::Pptx, &mut collector)?;
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        "xlsx" => {
            extract_archive(bytes, ArchiveKind::Xlsx, &mut collector)?;
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        "odt" => {
            extract_archive(bytes, ArchiveKind::Odf, &mut collector)?;
            "application/vnd.oasis.opendocument.text"
        }
        "ods" => {
            extract_archive(bytes, ArchiveKind::Odf, &mut collector)?;
            "application/vnd.oasis.opendocument.spreadsheet"
        }
        "odp" => {
            extract_archive(bytes, ArchiveKind::Odf, &mut collector)?;
            "application/vnd.oasis.opendocument.presentation"
        }
        "epub" => {
            extract_archive(bytes, ArchiveKind::Epub, &mut collector)?;
            "application/epub+zip"
        }
        "json" => {
            extract_json(bytes, &mut collector)?;
            "application/json"
        }
        "xml" => {
            extract_xml(bytes, false, &mut collector)?;
            "application/xml"
        }
        "html" | "htm" => {
            extract_xml(bytes, true, &mut collector)?;
            "text/html"
        }
        "rtf" => {
            extract_rtf(bytes, &mut collector)?;
            "application/rtf"
        }
        _ => {
            let text = decode_plain_text(bytes)?;
            collector.push(&text);
            fallback_mime.essence_str()
        }
    };
    Ok((mime_type.to_string(), collector))
}

fn extract_pdf(
    bytes: &[u8],
    max_text: usize,
    collector: &mut TextCollector,
) -> Result<(), ExtractionFailure> {
    let stream_limit = max_text
        .saturating_mul(4)
        .clamp(MIN_PDF_STREAM_LIMIT, MAX_PDF_STREAM_LIMIT);
    let document = lopdf::Document::load_mem_with_options(
        bytes,
        lopdf::LoadOptions::with_max_decompressed_size(stream_limit),
    )
    .map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            format!("PDF parsing failed: {error}"),
        )
    })?;
    if document.is_encrypted() {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Unsupported,
            "encrypted PDFs require a password and are not indexed",
        ));
    }
    let pages = document.get_pages();
    for (index, page_number) in pages.keys().copied().enumerate() {
        if index >= MAX_PDF_PAGES {
            collector.truncated = true;
            break;
        }
        let page_text = document
            .extract_text_with_limit(&[page_number], stream_limit)
            .map_err(|error| {
                ExtractionFailure::new(
                    ExtractionErrorCode::Corrupt,
                    format!("PDF text extraction failed: {error}"),
                )
            })?;
        collector.push(&page_text);
        if collector.truncated || collector.text.len() >= collector.limit {
            break;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ArchiveKind {
    Docx,
    Pptx,
    Xlsx,
    Odf,
    Epub,
}

fn extract_archive(
    bytes: &[u8],
    kind: ArchiveKind,
    collector: &mut TextCollector,
) -> Result<(), ExtractionFailure> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            format!("document archive could not be opened: {error}"),
        )
    })?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            "document archive contains too many entries",
        ));
    }
    let mut selected = Vec::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index).map_err(|error| {
            ExtractionFailure::new(
                ExtractionErrorCode::Corrupt,
                format!("document archive entry is invalid: {error}"),
            )
        })?;
        if file.enclosed_name().is_none() || file.name().len() > 1024 || file.is_dir() {
            continue;
        }
        if archive_entry_selected(kind, file.name()) {
            selected.push((file.name().to_string(), index));
        }
    }
    selected.sort_by(|left, right| left.0.cmp(&right.0));
    let input_limit = collector
        .limit
        .saturating_mul(8)
        .clamp(64 * 1024, 64 * 1024 * 1024);
    for (name, index) in selected {
        if collector.truncated {
            break;
        }
        let mut file = archive.by_index(index).map_err(|error| {
            ExtractionFailure::new(
                ExtractionErrorCode::Corrupt,
                format!("document archive entry could not be reopened: {error}"),
            )
        })?;
        if file.size() > input_limit as u64 {
            collector.truncated = true;
            break;
        }
        let mut entry = Vec::new();
        file.by_ref()
            .take(input_limit.saturating_add(1) as u64)
            .read_to_end(&mut entry)
            .map_err(|error| {
                ExtractionFailure::new(
                    ExtractionErrorCode::Corrupt,
                    format!("document archive entry could not be read: {error}"),
                )
            })?;
        if entry.len() > input_limit {
            collector.truncated = true;
            break;
        }
        let html = matches!(kind, ArchiveKind::Epub)
            && matches!(
                Path::new(&name)
                    .extension()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str(),
                "html" | "htm" | "xhtml"
            );
        extract_xml(&entry, html, collector)?;
    }
    Ok(())
}

fn archive_entry_selected(kind: ArchiveKind, name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    match kind {
        ArchiveKind::Docx => {
            lower == "word/document.xml"
                || lower.starts_with("word/header")
                || lower.starts_with("word/footer")
                || matches!(
                    lower.as_str(),
                    "word/comments.xml" | "word/footnotes.xml" | "word/endnotes.xml"
                )
        }
        ArchiveKind::Pptx => {
            (lower.starts_with("ppt/slides/slide")
                || lower.starts_with("ppt/notesslides/noteslide"))
                && lower.ends_with(".xml")
        }
        ArchiveKind::Xlsx => {
            lower == "xl/sharedstrings.xml"
                || (lower.starts_with("xl/worksheets/sheet") && lower.ends_with(".xml"))
        }
        ArchiveKind::Odf => matches!(lower.as_str(), "content.xml" | "meta.xml"),
        ArchiveKind::Epub => {
            matches!(
                Path::new(&lower)
                    .extension()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default(),
                "xhtml" | "html" | "htm" | "xml"
            ) && !lower.ends_with("container.xml")
        }
    }
}

fn extract_json(bytes: &[u8], collector: &mut TextCollector) -> Result<(), ExtractionFailure> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            format!("JSON extraction failed: {error}"),
        )
    })?;
    collect_json(&value, collector);
    Ok(())
}

fn collect_json(value: &serde_json::Value, collector: &mut TextCollector) {
    if collector.truncated {
        return;
    }
    match value {
        serde_json::Value::Null => collector.push("null"),
        serde_json::Value::Bool(value) => collector.push(if *value { "true" } else { "false" }),
        serde_json::Value::Number(value) => collector.push(&value.to_string()),
        serde_json::Value::String(value) => collector.push(value),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json(value, collector);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                collector.push(key);
                collect_json(value, collector);
            }
        }
    }
}

fn extract_xml(
    bytes: &[u8],
    html: bool,
    collector: &mut TextCollector,
) -> Result<(), ExtractionFailure> {
    let mut reader = XmlReader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    if html {
        reader.config_mut().check_end_names = false;
        reader.config_mut().allow_unmatched_ends = true;
    }
    let mut skipped_depth = 0_usize;
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name =
                    String::from_utf8_lossy(start.local_name().as_ref()).to_ascii_lowercase();
                if skipped_depth > 0 {
                    skipped_depth = skipped_depth.saturating_add(1);
                } else if html && matches!(name.as_str(), "script" | "style" | "noscript") {
                    skipped_depth = 1;
                }
            }
            Ok(Event::End(_)) if skipped_depth > 0 => {
                skipped_depth = skipped_depth.saturating_sub(1);
            }
            Ok(Event::Text(text)) if skipped_depth == 0 => {
                let decoded = text.decode().map_err(|error| {
                    ExtractionFailure::new(
                        ExtractionErrorCode::Corrupt,
                        format!("text encoding in markup is invalid: {error}"),
                    )
                })?;
                let unescaped = quick_xml::escape::unescape(&decoded).map_err(|error| {
                    ExtractionFailure::new(
                        ExtractionErrorCode::Corrupt,
                        format!("text entity in markup is invalid: {error}"),
                    )
                })?;
                collector.push(&unescaped);
            }
            Ok(Event::CData(text)) if skipped_depth == 0 => {
                let decoded = text.decode().map_err(|error| {
                    ExtractionFailure::new(
                        ExtractionErrorCode::Corrupt,
                        format!("CDATA encoding is invalid: {error}"),
                    )
                })?;
                collector.push(&decoded);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(ExtractionFailure::new(
                    ExtractionErrorCode::Corrupt,
                    format!("markup extraction failed: {error}"),
                ));
            }
        }
        if collector.truncated {
            break;
        }
    }
    Ok(())
}

fn decode_plain_text(bytes: &[u8]) -> Result<String, ExtractionFailure> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], false);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if !bytes.is_empty() && bytes.iter().filter(|byte| **byte == 0).count() * 100 > bytes.len() * 2
    {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::BinaryContent,
            "plain-text source contains too many NUL bytes",
        ));
    }
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|error| {
            ExtractionFailure::new(
                ExtractionErrorCode::Corrupt,
                format!("plain-text source is not valid UTF-8: {error}"),
            )
        })
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String, ExtractionFailure> {
    if !bytes.len().is_multiple_of(2) {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            "UTF-16 source has an incomplete code unit",
        ));
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|error| {
        ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            format!("UTF-16 source is invalid: {error}"),
        )
    })
}

#[derive(Debug, Clone, Copy)]
struct RtfState {
    skip: bool,
    unicode_skip: usize,
}

fn extract_rtf(bytes: &[u8], collector: &mut TextCollector) -> Result<(), ExtractionFailure> {
    let mut index = 0_usize;
    let mut state = RtfState {
        skip: false,
        unicode_skip: 1,
    };
    let mut stack = Vec::new();
    let mut skip_fallback = 0_usize;
    while index < bytes.len() && !collector.truncated {
        match bytes[index] {
            b'{' => {
                stack.push(state);
                index += 1;
            }
            b'}' => {
                state = stack.pop().ok_or_else(|| {
                    ExtractionFailure::new(
                        ExtractionErrorCode::Corrupt,
                        "RTF source contains an unmatched closing group",
                    )
                })?;
                index += 1;
            }
            b'\\' => {
                index += 1;
                if index >= bytes.len() {
                    break;
                }
                match bytes[index] {
                    b'\\' | b'{' | b'}' => {
                        if !state.skip && skip_fallback == 0 {
                            collector.push_char(bytes[index] as char);
                        }
                        skip_fallback = skip_fallback.saturating_sub(1);
                        index += 1;
                    }
                    b'\'' if index + 2 < bytes.len() => {
                        let value = parse_hex_byte(bytes[index + 1], bytes[index + 2])?;
                        if !state.skip && skip_fallback == 0 {
                            collector.push_char(cp1252(value));
                        }
                        skip_fallback = skip_fallback.saturating_sub(1);
                        index += 3;
                    }
                    b'*' => {
                        state.skip = true;
                        index += 1;
                    }
                    b'~' => {
                        if !state.skip {
                            collector.push_char(' ');
                        }
                        index += 1;
                    }
                    b'_' | b'-' => {
                        if !state.skip {
                            collector.push_char('-');
                        }
                        index += 1;
                    }
                    value if value.is_ascii_alphabetic() => {
                        let start = index;
                        while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                            index += 1;
                        }
                        let word = std::str::from_utf8(&bytes[start..index]).unwrap_or_default();
                        let number_start = index;
                        if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
                            index += 1;
                        }
                        while index < bytes.len() && bytes[index].is_ascii_digit() {
                            index += 1;
                        }
                        let number = (index > number_start)
                            .then(|| std::str::from_utf8(&bytes[number_start..index]).ok())
                            .flatten()
                            .and_then(|value| value.parse::<i32>().ok());
                        if index < bytes.len() && bytes[index] == b' ' {
                            index += 1;
                        }
                        apply_rtf_control(word, number, &mut state, &mut skip_fallback, collector);
                    }
                    _ => index += 1,
                }
            }
            byte => {
                if !state.skip && skip_fallback == 0 {
                    collector.push_char(cp1252(byte));
                }
                skip_fallback = skip_fallback.saturating_sub(1);
                index += 1;
            }
        }
    }
    if !stack.is_empty() {
        return Err(ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            "RTF source contains an unclosed group",
        ));
    }
    Ok(())
}

fn apply_rtf_control(
    word: &str,
    number: Option<i32>,
    state: &mut RtfState,
    skip_fallback: &mut usize,
    collector: &mut TextCollector,
) {
    if matches!(
        word,
        "fonttbl"
            | "colortbl"
            | "stylesheet"
            | "info"
            | "pict"
            | "object"
            | "filetbl"
            | "listtable"
            | "listoverridetable"
            | "xmlnstbl"
            | "datastore"
    ) {
        state.skip = true;
        return;
    }
    if state.skip {
        return;
    }
    match word {
        "par" | "line" | "tab" | "cell" | "row" => collector.push_char(' '),
        "uc" => {
            state.unicode_skip = number.unwrap_or(1).clamp(0, 32) as usize;
        }
        "u" => {
            if let Some(number) = number {
                let unit = number as i16 as u16;
                if let Some(character) = char::from_u32(u32::from(unit)) {
                    collector.push_char(character);
                }
                *skip_fallback = state.unicode_skip;
            }
        }
        _ => {}
    }
}

fn parse_hex_byte(high: u8, low: u8) -> Result<u8, ExtractionFailure> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    match (value(high), value(low)) {
        (Some(high), Some(low)) => Ok((high << 4) | low),
        _ => Err(ExtractionFailure::new(
            ExtractionErrorCode::Corrupt,
            "RTF source contains an invalid hexadecimal escape",
        )),
    }
}

fn cp1252(byte: u8) -> char {
    const EXTENDED: [char; 32] = [
        '\u{20ac}', '\u{0081}', '\u{201a}', '\u{0192}', '\u{201e}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02c6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008d}',
        '\u{017d}', '\u{008f}', '\u{0090}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02dc}', '\u{2122}', '\u{0161}', '\u{203a}',
        '\u{0153}', '\u{009d}', '\u{017e}', '\u{0178}',
    ];
    if (0x80..=0x9F).contains(&byte) {
        EXTENDED[usize::from(byte - 0x80)]
    } else {
        byte as char
    }
}

#[derive(Debug)]
struct TextCollector {
    text: String,
    limit: usize,
    truncated: bool,
    pending_space: bool,
}

impl TextCollector {
    fn new(limit: usize) -> Self {
        Self {
            text: String::with_capacity(limit.min(64 * 1024)),
            limit,
            truncated: false,
            pending_space: false,
        }
    }

    fn push(&mut self, value: &str) {
        for character in value.chars() {
            self.push_char(character);
            if self.truncated {
                break;
            }
        }
        self.pending_space = true;
    }

    fn push_char(&mut self, character: char) {
        if self.truncated {
            return;
        }
        if character.is_whitespace() || character.is_control() {
            self.pending_space = !self.text.is_empty();
            return;
        }
        let separator_bytes = usize::from(self.pending_space && !self.text.is_empty());
        if self
            .text
            .len()
            .saturating_add(separator_bytes)
            .saturating_add(character.len_utf8())
            > self.limit
        {
            self.truncated = true;
            return;
        }
        if self.pending_space && !self.text.is_empty() {
            self.text.push(' ');
        }
        self.pending_space = false;
        self.text.push(character);
    }

    fn finish(&mut self) {
        self.pending_space = false;
        while self.text.ends_with(char::is_whitespace) {
            self.text.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::content::{Content, Operation};
    use lopdf::{dictionary, Document, Object, Stream};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn request(path: &Path, max_extracted_bytes: u64) -> ExtractionRequest {
        ExtractionRequest {
            protocol_version: WORKER_PROTOCOL_VERSION,
            path: path.to_string_lossy().to_string(),
            max_file_bytes: 64 * 1024,
            max_extracted_bytes,
        }
    }

    fn write_pdf(path: &Path, text: &str) {
        let mut document = Document::with_version("1.5");
        let pages_id = document.new_object_id();
        let font_id = document.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Courier",
        });
        let resources_id = document.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::string_literal(text)]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            content.encode().expect("encode PDF content"),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        document.compress();
        document.save(path).expect("save test PDF");
    }

    #[test]
    fn extracts_structured_text_and_skips_html_script_content() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("data.json");
        fs::write(&json, br#"{"title":"Production Notes","count":3}"#).unwrap();
        let extracted = extract_request(&request(&json, 4096)).unwrap();
        assert!(extracted.text.contains("Production Notes"));
        assert!(extracted.text.contains("count 3"));

        let html = temp.path().join("page.html");
        fs::write(
            &html,
            b"<html><body>Visible Hero<script>privateToken</script></body></html>",
        )
        .unwrap();
        let extracted = extract_request(&request(&html, 4096)).unwrap();
        assert!(extracted.text.contains("Visible Hero"));
        assert!(!extracted.text.contains("privateToken"));
    }

    #[test]
    fn extracts_pdf_text_with_the_bounded_parser() {
        let temp = tempfile::tempdir().unwrap();
        let pdf = temp.path().join("production.pdf");
        write_pdf(&pdf, "Release PDF lighthouse proof");

        let extracted = extract_request(&request(&pdf, 4096)).unwrap();
        assert_eq!(extracted.mime_type, "application/pdf");
        assert!(extracted.text.contains("Release PDF lighthouse proof"));
        assert!(!extracted.truncated);
    }

    #[test]
    fn extracts_utf16_rtf_and_bounded_text() {
        let temp = tempfile::tempdir().unwrap();
        let utf16 = temp.path().join("utf16.txt");
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "UTF16 production note".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fs::write(&utf16, bytes).unwrap();
        assert_eq!(
            extract_request(&request(&utf16, 4096)).unwrap().text,
            "UTF16 production note"
        );

        let rtf = temp.path().join("note.rtf");
        fs::write(
            &rtf,
            br"{\rtf1\ansi Visible \b production\b0{} note {\fonttbl hiddenfont}}",
        )
        .unwrap();
        let extracted = extract_request(&request(&rtf, 4096)).unwrap();
        assert!(extracted.text.contains("Visible production note"));
        assert!(!extracted.text.contains("hiddenfont"));

        let large = temp.path().join("large.txt");
        fs::write(&large, "word ".repeat(2000)).unwrap();
        let extracted = extract_request(&request(&large, 4096)).unwrap();
        assert!(extracted.truncated);
        assert!(extracted.text.len() <= 4096);
    }

    #[test]
    fn extracts_docx_xml_without_extracting_archive_paths() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("document.docx");
        let file = fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("word/document.xml", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"<w:document><w:p><w:t>Hero transcript</w:t></w:p></w:document>")
            .unwrap();
        zip.start_file("../outside.xml", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"<x>must not appear</x>").unwrap();
        zip.finish().unwrap();

        let extracted = extract_request(&request(&path, 4096)).unwrap();
        assert!(extracted.text.contains("Hero transcript"));
        assert!(!extracted.text.contains("must not appear"));
        assert!(!temp.path().join("outside.xml").exists());
    }

    #[test]
    fn worker_frame_round_trips_success_and_failure() {
        let content = ExtractedContent {
            mime_type: "text/plain".to_string(),
            text: "hello".to_string(),
            truncated: false,
            source_size: 5,
            modified_time_millis: Some(1),
            digest: "digest".to_string(),
        };
        let mut frame = Vec::new();
        write_worker_response(&mut frame, Ok(content.clone())).unwrap();
        assert_eq!(
            read_worker_response(frame.as_slice(), 100).unwrap(),
            content
        );

        frame.clear();
        write_worker_response(
            &mut frame,
            Err(ExtractionFailure::new(
                ExtractionErrorCode::Corrupt,
                "bad file",
            )),
        )
        .unwrap();
        assert_eq!(
            read_worker_response(frame.as_slice(), 100)
                .unwrap_err()
                .code,
            ExtractionErrorCode::Corrupt
        );
    }
}
