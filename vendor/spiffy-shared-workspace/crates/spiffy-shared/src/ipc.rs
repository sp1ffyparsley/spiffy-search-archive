use std::fmt;
use std::net::SocketAddr;
use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::ProtocolVersion;

pub const LOCAL_IPC_ENDPOINT_SCHEMA_VERSION: u16 = 1;
pub const AUTHENTICATED_LOCAL_ENDPOINT_SCHEMA_VERSION: u16 = 2;
pub const MAX_LOCAL_REQUEST_LIFETIME_SECONDS: i64 = 60;
pub const MAX_WINDOWS_PIPE_NAME_CHARS: usize = 256;
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalIpcEndpoint {
    pub schema_version: u16,
    pub protocol: ProtocolVersion,
    pub process_id: u32,
    pub address: SocketAddr,
    pub token: String,
    pub started_at: DateTime<Utc>,
}

impl fmt::Debug for LocalIpcEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalIpcEndpoint")
            .field("schema_version", &self.schema_version)
            .field("protocol", &self.protocol)
            .field("process_id", &self.process_id)
            .field("address", &self.address)
            .field("token", &"[redacted]")
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl Drop for LocalIpcEndpoint {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub struct LocalIpcRequest<T> {
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub sent_at: DateTime<Utc>,
    pub token: String,
    pub command: T,
}

impl<T> LocalIpcRequest<T> {
    pub fn new(protocol: ProtocolVersion, token: String, command: T) -> Self {
        Self {
            protocol,
            request_id: Uuid::new_v4(),
            sent_at: Utc::now(),
            token,
            command,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for LocalIpcRequest<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalIpcRequest")
            .field("protocol", &self.protocol)
            .field("request_id", &self.request_id)
            .field("sent_at", &self.sent_at)
            .field("token", &"[redacted]")
            .field("command", &self.command)
            .finish()
    }
}

impl<T> Drop for LocalIpcRequest<T> {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalTransportEndpoint {
    TcpLoopback { address: SocketAddr },
    WindowsNamedPipe { pipe_name: String },
    UnixSocket { socket_path: String },
}

impl LocalTransportEndpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::TcpLoopback { address } if address.ip().is_loopback() => Ok(()),
            Self::TcpLoopback { .. } => Err("local TCP endpoint must use a loopback address"),
            Self::WindowsNamedPipe { pipe_name } => {
                let normalized = pipe_name.replace('/', "\\");
                if !normalized.starts_with("\\\\.\\pipe\\Spiffy")
                    || normalized.chars().count() > MAX_WINDOWS_PIPE_NAME_CHARS
                    || normalized.chars().any(char::is_control)
                {
                    return Err("Windows named pipe must use a bounded Spiffy pipe name");
                }
                Ok(())
            }
            Self::UnixSocket { socket_path } => {
                let path = Path::new(socket_path);
                if !path.is_absolute()
                    || socket_path.len() > MAX_UNIX_SOCKET_PATH_BYTES
                    || path.components().any(|component| {
                        matches!(component, Component::ParentDir | Component::CurDir)
                    })
                {
                    return Err("Unix socket must use a bounded absolute normalized path");
                }
                Ok(())
            }
        }
    }

    fn kind_name(&self) -> &'static str {
        match self {
            Self::TcpLoopback { .. } => "tcp_loopback",
            Self::WindowsNamedPipe { .. } => "windows_named_pipe",
            Self::UnixSocket { .. } => "unix_socket",
        }
    }
}

impl fmt::Debug for LocalTransportEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalTransportEndpoint")
            .field("transport", &self.kind_name())
            .field("address", &"[redacted]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedLocalEndpoint {
    pub schema_version: u16,
    pub protocol: ProtocolVersion,
    pub process_id: u32,
    pub session_id: String,
    pub endpoint: LocalTransportEndpoint,
    pub token: String,
    pub executable_digest_blake3: Option<String>,
    pub started_at: DateTime<Utc>,
}

impl AuthenticatedLocalEndpoint {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if self.schema_version != AUTHENTICATED_LOCAL_ENDPOINT_SCHEMA_VERSION {
            return Err("authenticated local endpoint schema version is unsupported");
        }
        if self.process_id == 0 {
            return Err("authenticated local endpoint process ID must be positive");
        }
        crate::workflow::validate_token(&self.session_id, 128, "local session ID")?;
        self.endpoint.validate()?;
        crate::IpcAuthToken::from_encoded(self.token.clone())?;
        if let Some(digest) = &self.executable_digest_blake3 {
            crate::workflow::validate_blake3(digest)?;
        }
        if self.started_at > now + chrono::Duration::minutes(5) {
            return Err("authenticated local endpoint start time is implausibly in the future");
        }
        Ok(())
    }
}

impl fmt::Debug for AuthenticatedLocalEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedLocalEndpoint")
            .field("schema_version", &self.schema_version)
            .field("protocol", &self.protocol)
            .field("process_id", &self.process_id)
            .field("session_id", &self.session_id)
            .field("endpoint", &self.endpoint)
            .field("token", &"[redacted]")
            .field("executable_digest_blake3", &self.executable_digest_blake3)
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl Drop for AuthenticatedLocalEndpoint {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedLocalRequest<T> {
    pub protocol: ProtocolVersion,
    pub request_id: Uuid,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub token: String,
    pub command: T,
}

impl<T> AuthenticatedLocalRequest<T> {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if self.request_id.is_nil() {
            return Err("authenticated local request ID must not be nil");
        }
        crate::workflow::validate_token(&self.session_id, 128, "local session ID")?;
        crate::IpcAuthToken::from_encoded(self.token.clone())?;
        if self.expires_at <= self.sent_at
            || self.expires_at <= now
            || (self.expires_at - self.sent_at)
                > chrono::Duration::seconds(MAX_LOCAL_REQUEST_LIFETIME_SECONDS)
            || self.sent_at > now + chrono::Duration::seconds(5)
        {
            return Err("authenticated local request freshness window is invalid");
        }
        Ok(())
    }
}

impl<T: fmt::Debug> fmt::Debug for AuthenticatedLocalRequest<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedLocalRequest")
            .field("protocol", &self.protocol)
            .field("request_id", &self.request_id)
            .field("sent_at", &self.sent_at)
            .field("expires_at", &self.expires_at)
            .field("session_id", &self.session_id)
            .field("token", &"[redacted]")
            .field("command", &self.command)
            .finish()
    }
}

impl<T> Drop for AuthenticatedLocalRequest<T> {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_bearer_tokens() {
        let request = LocalIpcRequest::new(
            ProtocolVersion::new(1, 2),
            "private-token".to_string(),
            "status",
        );
        let debug = format!("{request:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("private-token"));
    }

    #[test]
    fn authenticated_endpoints_reject_public_tcp_and_redact_paths() {
        let endpoint = LocalTransportEndpoint::TcpLoopback {
            address: "0.0.0.0:23443".parse().expect("socket address"),
        };
        assert_eq!(
            endpoint.validate(),
            Err("local TCP endpoint must use a loopback address")
        );

        let pipe = LocalTransportEndpoint::WindowsNamedPipe {
            pipe_name: "\\\\.\\pipe\\SpiffyClipboard-test".to_string(),
        };
        assert!(pipe.validate().is_ok());
        assert!(!format!("{pipe:?}").contains("SpiffyClipboard-test"));
    }

    #[test]
    fn authenticated_requests_are_short_lived_and_token_safe() {
        let now = Utc::now();
        let token = crate::IpcAuthToken::generate().expose().to_string();
        let mut request = AuthenticatedLocalRequest {
            protocol: ProtocolVersion::new(1, 0),
            request_id: Uuid::new_v4(),
            sent_at: now,
            expires_at: now + chrono::Duration::seconds(30),
            session_id: "session-1".to_string(),
            token,
            command: "health",
        };
        assert!(request.validate(now).is_ok());
        assert!(!format!("{request:?}").contains(request.token.as_str()));
        request.expires_at = now + chrono::Duration::seconds(60);
        assert!(request.validate(now).is_ok());
        request.expires_at += chrono::Duration::nanoseconds(1);
        assert!(request.validate(now).is_err());
        request.expires_at = now + chrono::Duration::minutes(5);
        assert!(request.validate(now).is_err());
    }
}
