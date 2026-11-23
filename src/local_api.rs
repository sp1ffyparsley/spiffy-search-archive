use crate::access::{bounded_preview_chars, bounded_result_limit, scoped_query, AccessSearchScope};
use crate::config::LocalApiConfig;
use crate::engine::SearchRuntime;
use crate::error::{io_error, SearchError, SearchResult};
use crate::model::{FavoriteItem, ItemMetadata, PreviewText};
use crate::protocol::{SearchResponse, SEARCH_PROTOCOL_VERSION};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use spiffy_shared::IpcAuthToken;
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::timeout::TimeoutLayer;
use zeroize::Zeroize;

const ENDPOINT_SCHEMA_VERSION: u16 = 1;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalApiEndpoint {
    pub schema_version: u16,
    pub protocol: spiffy_shared::ProtocolVersion,
    pub process_id: u32,
    pub address: SocketAddr,
    pub token: String,
    pub started_at: DateTime<Utc>,
}

impl fmt::Debug for LocalApiEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalApiEndpoint")
            .field("schema_version", &self.schema_version)
            .field("protocol", &self.protocol)
            .field("process_id", &self.process_id)
            .field("address", &self.address)
            .field("token", &"[redacted]")
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl Drop for LocalApiEndpoint {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

pub struct LocalApiServer {
    listener: Option<TcpListener>,
    state: Arc<LocalApiState>,
    endpoint_path: PathBuf,
    started_at: DateTime<Utc>,
}

impl fmt::Debug for LocalApiServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalApiServer")
            .field("address", &self.address())
            .field("token", &"[redacted]")
            .field("endpoint_path", &self.endpoint_path)
            .field("started_at", &self.started_at)
            .finish()
    }
}

struct LocalApiState {
    search: Arc<SearchRuntime>,
    token: Arc<IpcAuthToken>,
    config: LocalApiConfig,
    rate: Mutex<RateWindow>,
    generation: AtomicU64,
}

#[derive(Debug)]
struct RateWindow {
    started_at: Instant,
    accepted: u16,
}

impl RateWindow {
    fn accept(&mut self, limit: u16, now: Instant) -> bool {
        if now.duration_since(self.started_at) >= RATE_WINDOW {
            self.started_at = now;
            self.accepted = 0;
        }
        if self.accepted >= limit {
            return false;
        }
        self.accepted = self.accepted.saturating_add(1);
        true
    }
}

impl LocalApiServer {
    pub async fn bind(
        config: LocalApiConfig,
        search: Arc<SearchRuntime>,
        endpoint_path: PathBuf,
    ) -> SearchResult<Self> {
        config.validate()?;
        if !config.enabled {
            return Err(SearchError::Config(
                "local API cannot bind while disabled".to_string(),
            ));
        }
        remove_stale_endpoint(&endpoint_path)?;
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            config.port,
        ))
        .await
        .map_err(|error| SearchError::Protocol(format!("local API bind failed: {error}")))?;
        let token = Arc::new(IpcAuthToken::generate());
        let started_at = Utc::now();
        let server = Self {
            listener: Some(listener),
            state: Arc::new(LocalApiState {
                search,
                token,
                config,
                rate: Mutex::new(RateWindow {
                    started_at: Instant::now(),
                    accepted: 0,
                }),
                generation: AtomicU64::new(1),
            }),
            endpoint_path,
            started_at,
        };
        server.write_endpoint()?;
        Ok(server)
    }

    pub fn address(&self) -> SearchResult<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| {
                SearchError::State("local API listener was already consumed".to_string())
            })?
            .local_addr()
            .map_err(|error| {
                SearchError::Protocol(format!("could not read local API address: {error}"))
            })
    }

    pub fn base_url(&self) -> SearchResult<String> {
        Ok(format!("http://{}", self.address()?))
    }

    pub async fn serve(mut self, shutdown: CancellationToken) -> SearchResult<()> {
        let listener = self.listener.take().ok_or_else(|| {
            SearchError::State("local API listener was already consumed".to_string())
        })?;
        let router = api_router(Arc::clone(&self.state));
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .map_err(|error| SearchError::Protocol(format!("local API server failed: {error}")))
    }

    fn write_endpoint(&self) -> SearchResult<()> {
        let parent = self.endpoint_path.parent().ok_or_else(|| {
            SearchError::Config(format!(
                "local API endpoint path has no parent: {}",
                self.endpoint_path.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
        let endpoint = LocalApiEndpoint {
            schema_version: ENDPOINT_SCHEMA_VERSION,
            protocol: SEARCH_PROTOCOL_VERSION,
            process_id: std::process::id(),
            address: self.address()?,
            token: self.state.token.expose().to_string(),
            started_at: self.started_at,
        };
        let encoded = serde_json::to_vec_pretty(&endpoint)?;
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|error| io_error(parent, error))?;
        temporary
            .write_all(&encoded)
            .map_err(|error| io_error(temporary.path(), error))?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|error| io_error(temporary.path(), error))?;
        crate::ipc::restrict_file_to_owner(temporary.path())?;
        temporary
            .persist(&self.endpoint_path)
            .map_err(|error| io_error(&self.endpoint_path, error.error))?;
        Ok(())
    }
}

impl Drop for LocalApiServer {
    fn drop(&mut self) {
        let should_remove = load_endpoint(&self.endpoint_path)
            .map(|endpoint| endpoint.token == self.state.token.expose())
            .unwrap_or(false);
        if should_remove {
            let _ = fs::remove_file(&self.endpoint_path);
        }
    }
}

pub fn load_endpoint(path: &Path) -> SearchResult<LocalApiEndpoint> {
    let encoded = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let endpoint: LocalApiEndpoint = serde_json::from_str(&encoded)?;
    if endpoint.schema_version != ENDPOINT_SCHEMA_VERSION {
        return Err(SearchError::Protocol(format!(
            "unsupported local API endpoint schema {}",
            endpoint.schema_version
        )));
    }
    if !SEARCH_PROTOCOL_VERSION.is_compatible_with(endpoint.protocol) {
        return Err(SearchError::Protocol(format!(
            "local API protocol {}.{} is incompatible",
            endpoint.protocol.major, endpoint.protocol.minor
        )));
    }
    if !endpoint.address.ip().is_loopback() {
        return Err(SearchError::Authentication(
            "local API endpoint is not bound to loopback".to_string(),
        ));
    }
    IpcAuthToken::from_encoded(endpoint.token.clone()).map_err(|error| {
        SearchError::Authentication(format!("local API token is invalid: {error}"))
    })?;
    Ok(endpoint)
}

pub fn remove_stale_endpoint(path: &Path) -> SearchResult<()> {
    if !path.exists() {
        return Ok(());
    }
    #[cfg(not(test))]
    if path != crate::config::local_api_endpoint_path() {
        return Err(SearchError::Config(format!(
            "refusing to remove a local API endpoint outside its owner path: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SearchError::State(format!(
            "refusing to remove a local API endpoint that is not a normal file: {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|error| io_error(path, error))
}

fn api_router(state: Arc<LocalApiState>) -> Router {
    let max_body_bytes = state.config.max_body_bytes as usize;
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/search/files", post(search_files))
        .route("/v1/search/folders", post(search_folders))
        .route("/v1/search/applications", post(search_applications))
        .route("/v1/search/content", post(search_content))
        .route("/v1/items/metadata", post(item_metadata))
        .route("/v1/items/preview-text", post(preview_text))
        .route("/v1/favorites", get(favorites))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authenticate_and_limit,
        ))
        .with_state(state)
}

async fn authenticate_and_limit(
    State(state): State<Arc<LocalApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let candidate = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if candidate.is_none_or(|candidate| !state.token.matches(candidate)) {
        return secured(
            ApiFailure::new(
                StatusCode::UNAUTHORIZED,
                "authentication_failed",
                "A valid local API bearer token is required",
            )
            .into_response(),
        );
    }
    let accepted = {
        let Ok(mut rate) = state.rate.lock() else {
            return secured(
                ApiFailure::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "state_unavailable",
                    "The local API rate limiter is unavailable",
                )
                .into_response(),
            );
        };
        rate.accept(state.config.requests_per_minute, Instant::now())
    };
    if !accepted {
        return secured(
            ApiFailure::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "The local API request limit was reached; retry after the current minute window",
            )
            .into_response(),
        );
    }
    secured(next.run(request).await)
}

fn secured(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRequest {
    #[serde(default)]
    query: String,
    limit: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StableKeyRequest {
    stable_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    stable_key: String,
    max_chars: Option<u32>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    protocol: spiffy_shared::ProtocolVersion,
    read_only: bool,
    preview_text_enabled: bool,
    max_results: u16,
    max_body_bytes: u32,
    requests_per_minute: u16,
}

#[derive(Debug, Serialize)]
struct ApiSuccess<T> {
    ok: bool,
    data: T,
}

type ApiResult<T> = Result<Json<ApiSuccess<T>>, ApiFailure>;

async fn status(State(state): State<Arc<LocalApiState>>) -> ApiResult<StatusResponse> {
    Ok(success(StatusResponse {
        protocol: SEARCH_PROTOCOL_VERSION,
        read_only: true,
        preview_text_enabled: state.search.preview_text_allowed(),
        max_results: state
            .search
            .max_results()
            .min(crate::access::MAX_ACCESS_RESULTS),
        max_body_bytes: state.config.max_body_bytes,
        requests_per_minute: state.config.requests_per_minute,
    }))
}

async fn search_files(
    State(state): State<Arc<LocalApiState>>,
    Json(request): Json<SearchRequest>,
) -> ApiResult<SearchResponse> {
    search_scoped(state, AccessSearchScope::Files, request).await
}

async fn search_folders(
    State(state): State<Arc<LocalApiState>>,
    Json(request): Json<SearchRequest>,
) -> ApiResult<SearchResponse> {
    search_scoped(state, AccessSearchScope::Folders, request).await
}

async fn search_applications(
    State(state): State<Arc<LocalApiState>>,
    Json(request): Json<SearchRequest>,
) -> ApiResult<SearchResponse> {
    search_scoped(state, AccessSearchScope::Applications, request).await
}

async fn search_content(
    State(state): State<Arc<LocalApiState>>,
    Json(request): Json<SearchRequest>,
) -> ApiResult<SearchResponse> {
    search_scoped(state, AccessSearchScope::Content, request).await
}

async fn search_scoped(
    state: Arc<LocalApiState>,
    scope: AccessSearchScope,
    request: SearchRequest,
) -> ApiResult<SearchResponse> {
    let query = scoped_query(scope, &request.query).map_err(ApiFailure::from_search)?;
    let limit = bounded_result_limit(request.limit, state.search.max_results());
    let generation = state.generation.fetch_add(1, Ordering::Relaxed);
    let search = Arc::clone(&state.search);
    let response = blocking(move || search.search(&query, generation, Some(limit), None)).await?;
    Ok(success(response))
}

async fn item_metadata(
    State(state): State<Arc<LocalApiState>>,
    Json(request): Json<StableKeyRequest>,
) -> ApiResult<ItemMetadata> {
    let search = Arc::clone(&state.search);
    let metadata = blocking(move || search.item_metadata(&request.stable_key)).await?;
    metadata
        .map(success)
        .ok_or_else(|| ApiFailure::not_found("No indexed item has that stable key"))
}

async fn preview_text(
    State(state): State<Arc<LocalApiState>>,
    Json(request): Json<PreviewRequest>,
) -> ApiResult<PreviewText> {
    if !state.search.preview_text_allowed() {
        return Err(ApiFailure::new(
            StatusCode::FORBIDDEN,
            "preview_text_disabled",
            "Preview text access is disabled in Search configuration",
        ));
    }
    let max_chars = bounded_preview_chars(request.max_chars);
    let search = Arc::clone(&state.search);
    let preview = blocking(move || search.preview_text(&request.stable_key, max_chars)).await?;
    preview
        .map(success)
        .ok_or_else(|| ApiFailure::not_found("No indexed preview text is available"))
}

async fn favorites(State(state): State<Arc<LocalApiState>>) -> ApiResult<Vec<FavoriteItem>> {
    let limit = bounded_result_limit(None, state.search.max_results());
    let search = Arc::clone(&state.search);
    Ok(success(
        blocking(move || search.favorite_items(limit)).await?,
    ))
}

fn success<T>(data: T) -> Json<ApiSuccess<T>> {
    Json(ApiSuccess { ok: true, data })
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> SearchResult<T> + Send + 'static,
) -> Result<T, ApiFailure> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| {
            ApiFailure::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "worker_failed",
                "The local API worker did not complete",
            )
        })?
        .map_err(ApiFailure::from_search)
}

struct ApiFailure {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiFailure {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    fn from_search(error: SearchError) -> Self {
        match error {
            SearchError::Query(_) | SearchError::Config(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                error.to_string(),
            ),
            SearchError::Authentication(_) => Self::new(
                StatusCode::UNAUTHORIZED,
                "authentication_failed",
                "The local API request could not be authenticated",
            ),
            SearchError::Content(_) => Self::new(
                StatusCode::CONFLICT,
                "content_unavailable",
                error.to_string(),
            ),
            _ => {
                tracing::error!(error = %error, "local API search operation failed");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "search_failed",
                    "The search request failed; inspect the local Spiffy Search logs",
                )
            }
        }
    }
}

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        (
            self.status,
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            Json(serde_json::json!({
                "ok": false,
                "error": {
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SearchConfig;
    use crate::engine::SearchEngine;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_loopback_server_authenticates_scopes_bounds_and_cleans_its_endpoint() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Media");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("API Hero.mov"), b"hero").unwrap();
        fs::create_dir(root.join("Projects")).unwrap();
        let mut engine = SearchEngine::open_for_test(temp.path(), SearchConfig::default()).unwrap();
        let source = engine.add_root(&root, false, Vec::new()).unwrap();
        engine
            .index_root(
                source.id,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .unwrap();
        let workspace = temp.path().join("Spiffy Workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("Launch Workspace"), b"launcher").unwrap();
        let workspace_catalog = temp.path().join("workspace_catalog.json");
        fs::write(
            &workspace_catalog,
            serde_json::to_vec(&serde_json::json!({
                "schema": "ss_scripts_workspace_catalog_v1",
                "version": 1,
                "systems": [{
                    "id": "fixture_workspace",
                    "label": "Fixture Workspace",
                    "platforms": ["windows", "macos"],
                    "launch_targets": [{
                        "id": "workspace_hero",
                        "label": "Workspace Hero",
                        "aliases": ["Hero App"],
                        "platform_paths": {
                            "windows": "Spiffy Workspace/Launch Workspace",
                            "macos": "Spiffy Workspace/Launch Workspace"
                        }
                    }]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        engine
            .refresh_workspace_catalog(&workspace_catalog)
            .unwrap();
        let search = Arc::new(engine.search_runtime().unwrap());
        let endpoint_path = temp.path().join("local-api-endpoint.json");
        let config = LocalApiConfig {
            enabled: true,
            requests_per_minute: 10,
            max_body_bytes: 1024,
            ..LocalApiConfig::default()
        };
        let server = LocalApiServer::bind(config, search, endpoint_path.clone())
            .await
            .unwrap();
        let endpoint = load_endpoint(&endpoint_path).unwrap();
        assert!(endpoint.address.ip().is_loopback());
        assert!(!format!("{endpoint:?}").contains(&endpoint.token));
        let ipc_path = temp.path().join("ipc-endpoint.json");
        let _ipc_server = crate::ipc::IpcServer::bind(ipc_path.clone()).await.unwrap();
        let ipc_endpoint = crate::ipc::load_endpoint(&ipc_path).unwrap();
        assert_ne!(endpoint.token, ipc_endpoint.token);
        let address = endpoint.address;
        let token = endpoint.token.clone();
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(server.serve(task_shutdown));

        let unauthorized = raw_request(address, None, "GET", "/v1/status", "").await;
        assert!(unauthorized.starts_with("HTTP/1.1 401"));
        let search = raw_request(
            address,
            Some(&token),
            "POST",
            "/v1/search/files",
            r#"{"query":"api hero","limit":10}"#,
        )
        .await;
        assert!(search.starts_with("HTTP/1.1 200"), "{search}");
        assert!(search.contains("API Hero.mov"), "{search}");
        assert!(search
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        let applications = raw_request(
            address,
            Some(&token),
            "POST",
            "/v1/search/applications",
            r#"{"query":"workspace hero"}"#,
        )
        .await;
        assert!(applications.starts_with("HTTP/1.1 200"), "{applications}");
        assert!(applications.contains("Workspace Hero"), "{applications}");
        assert!(!applications.contains("API Hero.mov"), "{applications}");
        let escaped = raw_request(
            address,
            Some(&token),
            "POST",
            "/v1/search/files",
            r#"{"query":"browser:private"}"#,
        )
        .await;
        assert!(escaped.starts_with("HTTP/1.1 400"), "{escaped}");
        let preview = raw_request(
            address,
            Some(&token),
            "POST",
            "/v1/items/preview-text",
            r#"{"stable_key":"not-a-key"}"#,
        )
        .await;
        assert!(preview.starts_with("HTTP/1.1 403"), "{preview}");
        let oversized = raw_request(
            address,
            Some(&token),
            "POST",
            "/v1/search/files",
            &format!(r#"{{"query":"{}"}}"#, "x".repeat(1100)),
        )
        .await;
        assert!(oversized.starts_with("HTTP/1.1 413"), "{oversized}");

        shutdown.cancel();
        task.await.unwrap().unwrap();
        assert!(!endpoint_path.exists());
    }

    #[test]
    fn fixed_rate_window_is_bounded_and_resets() {
        let start = Instant::now();
        let mut rate = RateWindow {
            started_at: start,
            accepted: 0,
        };
        assert!(rate.accept(2, start));
        assert!(rate.accept(2, start));
        assert!(!rate.accept(2, start));
        assert!(rate.accept(2, start + RATE_WINDOW));
    }

    #[test]
    fn internal_failures_do_not_disclose_local_paths() {
        let failure = ApiFailure::from_search(crate::error::io_error(
            "C:/Private/Projects/secret.txt",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied"),
        ));
        assert_eq!(failure.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(failure.code, "search_failed");
        assert!(!failure.message.contains("Private"));
        assert!(failure.message.contains("local Spiffy Search logs"));

        let invalid = ApiFailure::from_search(SearchError::Query("bad filter".to_string()));
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
        assert!(invalid.message.contains("bad filter"));
    }

    async fn raw_request(
        address: SocketAddr,
        token: Option<&str>,
        method: &str,
        path: &str,
        body: &str,
    ) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let authorization = token
            .map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }
}
