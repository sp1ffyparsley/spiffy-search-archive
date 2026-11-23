use crate::error::{io_error, SearchError, SearchResult};
use crate::protocol::{
    AgentCommand, AgentReply, IpcRequest, SearchIpcCommand, SEARCH_PROTOCOL_VERSION,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Serialize};
use spiffy_shared::{IpcAuthToken, LocalIpcEndpoint, LOCAL_IPC_ENDPOINT_SCHEMA_VERSION};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

pub const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST_AGE_SECONDS: i64 = 120;

pub type IpcEndpoint = LocalIpcEndpoint;

#[derive(Debug)]
pub struct AuthenticatedRequest {
    pub request_id: Uuid,
    pub command: SearchIpcCommand,
}

pub struct IpcServer {
    listener: TcpListener,
    token: IpcAuthToken,
    endpoint_path: PathBuf,
    lock_path: PathBuf,
    lock_file: File,
    started_at: DateTime<Utc>,
}

impl fmt::Debug for IpcServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpcServer")
            .field("address", &self.listener.local_addr())
            .field("token", &"[redacted]")
            .field("endpoint_path", &self.endpoint_path)
            .field("lock_path", &self.lock_path)
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl IpcServer {
    pub async fn bind_default() -> SearchResult<Self> {
        Self::bind(crate::config::ipc_endpoint_path()).await
    }

    pub async fn bind(endpoint_path: PathBuf) -> SearchResult<Self> {
        let parent = endpoint_path.parent().ok_or_else(|| {
            SearchError::Config(format!(
                "IPC endpoint path has no parent: {}",
                endpoint_path.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
        let lock_path = endpoint_path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| io_error(&lock_path, error))?;
        restrict_file_to_owner(&lock_path)?;
        lock_file.try_lock_exclusive().map_err(|error| {
            SearchError::State(format!(
                "another Spiffy Search agent owns {}: {error}",
                lock_path.display()
            ))
        })?;

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .map_err(|error| {
                SearchError::Protocol(format!("could not bind local IPC listener: {error}"))
            })?;
        let token = IpcAuthToken::generate();
        let started_at = Utc::now();
        let server = Self {
            listener,
            token,
            endpoint_path,
            lock_path,
            lock_file,
            started_at,
        };
        server.write_endpoint_file()?;
        Ok(server)
    }

    pub fn address(&self) -> SearchResult<SocketAddr> {
        self.listener.local_addr().map_err(|error| {
            SearchError::Protocol(format!("could not read local IPC address: {error}"))
        })
    }

    pub async fn accept(&self) -> SearchResult<(TcpStream, SocketAddr)> {
        self.listener.accept().await.map_err(|error| {
            SearchError::Protocol(format!("could not accept local IPC connection: {error}"))
        })
    }

    pub async fn read_authenticated(
        &self,
        stream: &mut TcpStream,
    ) -> SearchResult<AuthenticatedRequest> {
        let request: IpcRequest = timeout(IPC_TIMEOUT, read_json_frame(stream))
            .await
            .map_err(|_| {
                SearchError::Authentication("local IPC request timed out".to_string())
            })??;
        if !SEARCH_PROTOCOL_VERSION.is_compatible_with(request.protocol) {
            return Err(SearchError::Protocol(format!(
                "IPC protocol {}.{} is incompatible",
                request.protocol.major, request.protocol.minor
            )));
        }
        if !self.token.matches(&request.token) {
            return Err(SearchError::Authentication(
                "local IPC bearer token mismatch".to_string(),
            ));
        }
        let age = Utc::now() - request.sent_at;
        if age < ChronoDuration::seconds(-MAX_REQUEST_AGE_SECONDS)
            || age > ChronoDuration::seconds(MAX_REQUEST_AGE_SECONDS)
        {
            return Err(SearchError::Authentication(
                "local IPC request timestamp is stale".to_string(),
            ));
        }
        Ok(AuthenticatedRequest {
            request_id: request.request_id,
            command: request.command.clone(),
        })
    }

    pub async fn write_reply(
        &self,
        stream: &mut TcpStream,
        reply: &AgentReply,
    ) -> SearchResult<()> {
        timeout(IPC_TIMEOUT, write_json_frame(stream, reply))
            .await
            .map_err(|_| SearchError::Protocol("local IPC response timed out".to_string()))?
    }

    pub fn endpoint_owner_only(&self) -> bool {
        endpoint_owner_only(&self.endpoint_path)
    }

    fn write_endpoint_file(&self) -> SearchResult<()> {
        let parent = self.endpoint_path.parent().expect("endpoint has parent");
        let endpoint = IpcEndpoint {
            schema_version: LOCAL_IPC_ENDPOINT_SCHEMA_VERSION,
            protocol: SEARCH_PROTOCOL_VERSION,
            process_id: std::process::id(),
            address: self.address()?,
            token: self.token.expose().to_string(),
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
        restrict_file_to_owner(temporary.path())?;
        temporary
            .persist(&self.endpoint_path)
            .map_err(|error| io_error(&self.endpoint_path, error.error))?;
        Ok(())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let should_remove = load_endpoint(&self.endpoint_path)
            .map(|endpoint| endpoint.token == self.token.expose())
            .unwrap_or(false);
        if should_remove {
            let _ = fs::remove_file(&self.endpoint_path);
        }
        let _ = fs2::FileExt::unlock(&self.lock_file);
    }
}

pub fn load_endpoint(path: &Path) -> SearchResult<IpcEndpoint> {
    let contents = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let endpoint: IpcEndpoint = serde_json::from_str(&contents)?;
    if endpoint.schema_version != LOCAL_IPC_ENDPOINT_SCHEMA_VERSION {
        return Err(SearchError::Protocol(format!(
            "unsupported IPC endpoint schema {}",
            endpoint.schema_version
        )));
    }
    if !SEARCH_PROTOCOL_VERSION.is_compatible_with(endpoint.protocol) {
        return Err(SearchError::Protocol(format!(
            "IPC protocol {}.{} is incompatible",
            endpoint.protocol.major, endpoint.protocol.minor
        )));
    }
    if !endpoint.address.ip().is_loopback() {
        return Err(SearchError::Authentication(
            "IPC endpoint is not bound to loopback".to_string(),
        ));
    }
    IpcAuthToken::from_encoded(endpoint.token.clone()).map_err(|error| {
        SearchError::Authentication(format!("IPC endpoint token is invalid: {error}"))
    })?;
    Ok(endpoint)
}

pub async fn send_command(command: AgentCommand) -> SearchResult<AgentReply> {
    send_command_at(&crate::config::ipc_endpoint_path(), command).await
}

pub async fn send_command_at(path: &Path, command: AgentCommand) -> SearchResult<AgentReply> {
    let endpoint = load_endpoint(path)?;
    let required_minor = command.minimum_protocol_minor();
    if endpoint.protocol.minor < required_minor {
        return Err(SearchError::Protocol(format!(
            "command requires IPC protocol {}.{required_minor}, but the agent provides {}.{}",
            SEARCH_PROTOCOL_VERSION.major, endpoint.protocol.major, endpoint.protocol.minor
        )));
    }
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint.address))
        .await
        .map_err(|_| SearchError::Protocol("local IPC connection timed out".to_string()))?
        .map_err(|error| SearchError::Protocol(format!("local IPC connection failed: {error}")))?;
    let request = IpcRequest::new(
        SEARCH_PROTOCOL_VERSION,
        endpoint.token.clone(),
        SearchIpcCommand::Agent(command),
    );
    timeout(IPC_TIMEOUT, write_json_frame(&mut stream, &request))
        .await
        .map_err(|_| SearchError::Protocol("local IPC request timed out".to_string()))??;
    timeout(IPC_TIMEOUT, read_json_frame(&mut stream))
        .await
        .map_err(|_| SearchError::Protocol("local IPC response timed out".to_string()))?
}

async fn write_json_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> SearchResult<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(SearchError::Protocol(format!(
            "IPC frame size {} is outside supported bounds",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| SearchError::Protocol("IPC frame exceeds u32".to_string()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| SearchError::Protocol(format!("IPC frame write failed: {error}")))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|error| SearchError::Protocol(format!("IPC payload write failed: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| SearchError::Protocol(format!("IPC flush failed: {error}")))?;
    Ok(())
}

async fn read_json_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> SearchResult<T> {
    let length = stream
        .read_u32()
        .await
        .map_err(|error| SearchError::Protocol(format!("IPC frame read failed: {error}")))?
        as usize;
    if length == 0 || length > MAX_IPC_FRAME_BYTES {
        return Err(SearchError::Protocol(format!(
            "IPC frame size {length} is outside supported bounds"
        )));
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| SearchError::Protocol(format!("IPC payload read failed: {error}")))?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(unix)]
pub(crate) fn restrict_file_to_owner(path: &Path) -> SearchResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| io_error(path, error))
}

#[cfg(windows)]
pub(crate) fn restrict_file_to_owner(path: &Path) -> SearchResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
    use windows::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl, TokenUser,
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|error| {
        SearchError::Authentication(format!("could not inspect current user: {error}"))
    })?;
    let result = (|| {
        let mut required = 0_u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        if required < std::mem::size_of::<TOKEN_USER>() as u32 || required > 64 * 1024 {
            return Err(SearchError::Authentication(
                "current-user SID is unavailable".into(),
            ));
        }
        let word_size = std::mem::size_of::<usize>();
        let mut token_words = vec![0_usize; (required as usize).div_ceil(word_size)];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(token_words.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }
        .map_err(|error| {
            SearchError::Authentication(format!("could not read current-user SID: {error}"))
        })?;
        let sid = unsafe { (*token_words.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let sid_bytes = unsafe { GetLengthSid(sid) } as usize;
        let acl_bytes = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            - std::mem::size_of::<u32>()
            + sid_bytes;
        let mut acl_words = vec![0_u32; acl_bytes.div_ceil(std::mem::size_of::<u32>())];
        let acl = acl_words.as_mut_ptr().cast::<ACL>();
        unsafe { InitializeAcl(acl, acl_bytes as u32, ACL_REVISION) }.map_err(|error| {
            SearchError::Authentication(format!("could not initialize private ACL: {error}"))
        })?;
        unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, sid) }.map_err(
            |error| SearchError::Authentication(format!("could not build private ACL: {error}")),
        )?;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                windows::Win32::Security::OBJECT_SECURITY_INFORMATION(
                    DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
                ),
                None,
                None,
                Some(acl),
                None,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(SearchError::Authentication(format!(
                "could not protect Search IPC file ACL: {}",
                std::io::Error::from_raw_os_error(status.0 as i32)
            )));
        }
        Ok(())
    })();
    let _ = unsafe { CloseHandle(token) };
    result
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn restrict_file_to_owner(_path: &Path) -> SearchResult<()> {
    Ok(())
}

#[cfg(unix)]
pub fn endpoint_owner_only(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(windows)]
pub fn endpoint_owner_only(path: &Path) -> bool {
    path.is_file() && path.starts_with(crate::config::data_dir())
}

#[cfg(not(any(unix, windows)))]
pub fn endpoint_owner_only(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use spiffy_shared::{DeviceIdentity, LocalIpcRequest, SearchServiceCommand};

    #[cfg(windows)]
    #[tokio::test]
    async fn token_bearing_search_endpoint_and_lock_have_owner_only_acl() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private-search-ipc.json");
        let _server = IpcServer::bind(path.clone()).await.unwrap();
        assert!(
            crate::shelf::private_file(&File::open(&path).unwrap()),
            "Search token endpoint inherited broader grants"
        );
        assert!(
            crate::shelf::private_file(&File::open(path.with_extension("lock")).unwrap()),
            "Search IPC lock inherited broader grants"
        );
    }

    #[tokio::test]
    async fn authenticated_loopback_ipc_round_trips_and_redacts_token() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("endpoint.json");
        let server = Arc::new(IpcServer::bind(path.clone()).await.unwrap());
        let endpoint = load_endpoint(&path).unwrap();
        assert!(!format!("{endpoint:?}").contains(&endpoint.token));
        let task_server = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let (mut stream, source) = task_server.accept().await.unwrap();
            assert!(source.ip().is_loopback());
            let request = task_server.read_authenticated(&mut stream).await.unwrap();
            assert_eq!(
                request.command,
                SearchIpcCommand::Agent(AgentCommand::Status)
            );
            task_server
                .write_reply(&mut stream, &AgentReply::empty_success("healthy"))
                .await
                .unwrap();
        });
        let reply = send_command_at(&path, AgentCommand::Status).await.unwrap();
        assert!(reply.ok);
        assert_eq!(reply.message, "healthy");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_token_is_rejected_and_second_agent_cannot_take_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("endpoint.json");
        let server = Arc::new(IpcServer::bind(path.clone()).await.unwrap());
        assert!(IpcServer::bind(path.clone()).await.is_err());
        let endpoint = load_endpoint(&path).unwrap();
        let task_server = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let (mut stream, _) = task_server.accept().await.unwrap();
            task_server
                .read_authenticated(&mut stream)
                .await
                .unwrap_err()
        });
        let mut stream = TcpStream::connect(endpoint.address).await.unwrap();
        let request = IpcRequest::new(
            SEARCH_PROTOCOL_VERSION,
            IpcAuthToken::generate().expose().to_string(),
            SearchIpcCommand::Agent(AgentCommand::Shutdown),
        );
        write_json_frame(&mut stream, &request).await.unwrap();
        assert!(task.await.unwrap().to_string().contains("token mismatch"));
    }

    #[tokio::test]
    async fn shared_search_service_command_uses_the_authenticated_endpoint_contract() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("endpoint.json");
        let server = Arc::new(IpcServer::bind(path.clone()).await.unwrap());
        let endpoint = load_endpoint(&path).unwrap();
        let task_server = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let (mut stream, _) = task_server.accept().await.unwrap();
            task_server.read_authenticated(&mut stream).await.unwrap()
        });
        let mut stream = TcpStream::connect(endpoint.address).await.unwrap();
        let requester = Uuid::new_v4();
        let command = SearchServiceCommand::RemoteSearch {
            requester_device_id: requester,
            serving_device: DeviceIdentity {
                id: Uuid::new_v4(),
                display_name: "Editing PC".to_string(),
            },
            query: spiffy_shared::RemoteSearchQuery {
                query_id: Uuid::new_v4(),
                text: "hero".to_string(),
                permitted_root_ids: Vec::new(),
                result_limit: 20,
                include_thumbnails: false,
            },
        };
        let request =
            LocalIpcRequest::new(SEARCH_PROTOCOL_VERSION, endpoint.token.clone(), command);
        write_json_frame(&mut stream, &request).await.unwrap();
        let authenticated = task.await.unwrap();
        assert!(matches!(
            authenticated.command,
            SearchIpcCommand::Service(SearchServiceCommand::RemoteSearch {
                requester_device_id,
                ..
            }) if requester_device_id == requester
        ));
    }

    #[tokio::test]
    async fn newer_commands_are_rejected_before_connecting_to_an_older_agent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("endpoint.json");
        let _server = IpcServer::bind(path.clone()).await.unwrap();
        let mut endpoint = load_endpoint(&path).unwrap();
        endpoint.protocol = spiffy_shared::ProtocolVersion::new(1, 0);
        fs::write(&path, serde_json::to_vec(&endpoint).unwrap()).unwrap();

        let error = send_command_at(&path, AgentCommand::ContentStatus)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires IPC protocol 1.1, but the agent provides 1.0"));

        endpoint.protocol = spiffy_shared::ProtocolVersion::new(1, 1);
        fs::write(&path, serde_json::to_vec(&endpoint).unwrap()).unwrap();
        let error = send_command_at(
            &path,
            AgentCommand::FileOperationStatus {
                operation_id: Uuid::new_v4(),
            },
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires IPC protocol 1.2, but the agent provides 1.1"));

        endpoint.protocol = spiffy_shared::ProtocolVersion::new(1, 3);
        fs::write(&path, serde_json::to_vec(&endpoint).unwrap()).unwrap();
        let error = send_command_at(
            &path,
            AgentCommand::GetItemMetadata {
                stable_key: "key".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires IPC protocol 1.4, but the agent provides 1.3"));
    }

    use std::sync::Arc;
}
