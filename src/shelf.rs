//! Live saved-Shelf metadata adapter. No Shelf index, payload mirror, or Capture authority.
use crate::error::{SearchError, SearchResult};
use crate::query::{ParsedQuery, SearchMode};
use chrono::Utc;
use spiffy_shared::shelf_search::{
    ShelfSearchCommand, ShelfSearchNavigationReceipt, ShelfSearchPage, ShelfSearchReference,
    ShelfSearchReply, SHELF_SEARCH_DISCOVERY_RELATIVE_PATH, SHELF_SEARCH_MAX_FRAME_BYTES,
    SHELF_SEARCH_PROTOCOL_VERSION,
};
use spiffy_shared::{
    product_data_dir, read_json_frame, write_json_frame, AuthenticatedLocalEndpoint,
    AuthenticatedLocalRequest, LocalTransportEndpoint, Product,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Route Shelf metadata to its owner without rewriting shared query syntax.
pub fn metadata_query(raw: &str, current_folder: Option<&str>) -> SearchResult<Option<String>> {
    let parsed = ParsedQuery::parse(raw)
        .map_err(|_| SearchError::Query("search query syntax is invalid".into()))?;
    if parsed.mode != SearchMode::Shelf {
        return Ok(None);
    }
    let mut expected = ParsedQuery::parse("shelf:")?;
    expected.raw_text = parsed.raw_text.clone();
    expected.terms = parsed.terms.clone();
    expected.exact_phrases = parsed.exact_phrases.clone();
    expected.excluded_terms = parsed.excluded_terms.clone();
    if current_folder.is_some() || parsed != expected {
        return Err(SearchError::Query("shelf: supports saved Shelf names and item titles only; filesystem filters are unavailable".into()));
    }
    Ok(Some(crate::query::shelf_query_text(raw).map_err(|_| {
        SearchError::Query("saved Shelf query syntax is invalid".into())
    })?))
}

pub fn query(
    query: String,
    generation: u64,
    limit: u16,
    cursor: Option<String>,
) -> SearchResult<ShelfSearchPage> {
    request(ShelfSearchCommand::QuerySavedShelf {
        protocol: SHELF_SEARCH_PROTOCOL_VERSION,
        query,
        generation,
        limit,
        cursor,
    })?
    .page
    .ok_or_else(|| protocol("saved Shelf reply omitted its page"))
}

pub fn reveal(reference: ShelfSearchReference) -> SearchResult<ShelfSearchNavigationReceipt> {
    request(ShelfSearchCommand::RevealShelfResult {
        protocol: SHELF_SEARCH_PROTOCOL_VERSION,
        reference,
    })?
    .navigation
    .ok_or_else(|| protocol("saved Shelf reply omitted its navigation receipt"))
}

fn protocol(message: &str) -> SearchError {
    SearchError::Protocol(message.into())
}

fn request(command: ShelfSearchCommand) -> SearchResult<ShelfSearchReply> {
    command.validate().map_err(protocol)?;
    let path = product_data_dir(Product::Shelf).join(SHELF_SEARCH_DISCOVERY_RELATIVE_PATH);
    let endpoint = load_endpoint(&path)?;
    exchange(&endpoint, command)
}

fn load_endpoint(path: &Path) -> SearchResult<AuthenticatedLocalEndpoint> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| {
        SearchError::State(
            "saved Shelf search is unavailable; open Spiffy Shelf in normal mode".into(),
        )
    })?;
    if !private_file(&file) {
        return Err(SearchError::Authentication(
            "saved Shelf discovery is not an owner-private regular file".into(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| protocol("saved Shelf discovery could not be read"))?;
    if bytes.len() > 16 * 1024 {
        return Err(protocol("saved Shelf discovery exceeds its bound"));
    }
    let endpoint: AuthenticatedLocalEndpoint =
        serde_json::from_slice(&bytes).map_err(|_| protocol("saved Shelf discovery is invalid"))?;
    endpoint.validate(Utc::now()).map_err(protocol)?;
    if endpoint.protocol != SHELF_SEARCH_PROTOCOL_VERSION
        || !matches!(
            endpoint.endpoint,
            LocalTransportEndpoint::TcpLoopback { .. }
        )
    {
        return Err(protocol("saved Shelf endpoint capability is incompatible"));
    }
    Ok(endpoint)
}

fn exchange(
    endpoint: &AuthenticatedLocalEndpoint,
    command: ShelfSearchCommand,
) -> SearchResult<ShelfSearchReply> {
    command.validate().map_err(protocol)?;
    endpoint.validate(Utc::now()).map_err(protocol)?;
    if endpoint.protocol != SHELF_SEARCH_PROTOCOL_VERSION {
        return Err(protocol("saved Shelf endpoint protocol is incompatible"));
    }
    let LocalTransportEndpoint::TcpLoopback { address } = &endpoint.endpoint else {
        return Err(protocol("saved Shelf requires loopback transport"));
    };
    let timeout = if matches!(command, ShelfSearchCommand::RevealShelfResult { .. }) {
        Duration::from_secs(4)
    } else {
        Duration::from_secs(2)
    };
    let started = Instant::now();
    let stream = TcpStream::connect_timeout(address, Duration::from_millis(750)).map_err(|_| {
        SearchError::State("saved Shelf owner is unavailable; reopen Spiffy Shelf".into())
    })?;
    let mut io = DeadlineStream {
        stream,
        deadline: started + timeout,
    };
    let now = Utc::now();
    let request = AuthenticatedLocalRequest {
        protocol: SHELF_SEARCH_PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        sent_at: now,
        expires_at: now + chrono::Duration::seconds(10),
        session_id: endpoint.session_id.clone(),
        token: endpoint.token.clone(),
        command,
    };
    write_json_frame(&mut io, &request, SHELF_SEARCH_MAX_FRAME_BYTES)
        .map_err(|_| protocol("saved Shelf request transport failed"))?;
    let reply: ShelfSearchReply = read_json_frame(&mut io, SHELF_SEARCH_MAX_FRAME_BYTES)
        .map_err(|_| protocol("saved Shelf response was unavailable or invalid"))?;
    reply
        .validate_for(request.request_id, &request.command)
        .map_err(protocol)?;
    tracing::info!(
        action = if matches!(request.command, ShelfSearchCommand::QuerySavedShelf { .. }) {
            "saved_shelf_query"
        } else {
            "saved_shelf_reveal"
        },
        applied = reply.ok,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "Shelf metadata owner replied"
    );
    if !reply.ok {
        return Err(SearchError::State(format!(
            "saved Shelf owner rejected the request: {}",
            reply.error_code.as_deref().unwrap_or("unavailable")
        )));
    }
    Ok(reply)
}

struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "saved Shelf deadline elapsed")
            })
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(unix)]
fn private_file(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    file.metadata().is_ok_and(|m| {
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.len() <= 16 * 1024
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn private_file(file: &File) -> bool {
    use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        EqualSid, GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    if !file.metadata().is_ok_and(|m| {
        m.is_file()
            && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
            && m.len() <= 16 * 1024
    }) {
        return false;
    }
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = (|| {
        let mut required = 0;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        if required < std::mem::size_of::<TOKEN_USER>() as u32 {
            return false;
        }
        let mut words = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(words.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }
        .is_err()
        {
            return false;
        }
        let user = unsafe { (*words.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut owner = PSID::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut acl),
                None,
                Some(&mut descriptor),
            )
        } != ERROR_SUCCESS
            || acl.is_null()
            || unsafe { EqualSid(owner, user) }.is_err()
        {
            return false;
        }
        let count = unsafe { (*acl).AceCount };
        if count == 0 {
            return false;
        }
        for index in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(acl, index, &mut ace) }.is_err() || ace.is_null() {
                return false;
            }
            // Shelf publishes only simple owner allow ACEs. Unknown/object/inherited grants fail closed.
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceType != 0
                || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            {
                return false;
            }
            let sid = unsafe {
                PSID(std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast())
            };
            if unsafe { EqualSid(sid, user) }.is_err() {
                return false;
            }
        }
        true
    })();
    if !descriptor.0.is_null() {
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    }
    let _ = unsafe { CloseHandle(token) };
    result
}

#[cfg(not(any(target_os = "windows", unix)))]
fn private_file(_: &File) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    fn fixture_acl(path: &Path, public: bool) {
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
        use windows::Win32::Security::Authorization::{
            GetSecurityInfo, SetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            AddAccessAllowedAce, CreateWellKnownSid, InitializeAcl, WinWorldSid, ACL, ACL_REVISION,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };
        use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        let file = File::open(path).unwrap();
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    HANDLE(file.as_raw_handle()),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    Some(&mut owner),
                    None,
                    None,
                    None,
                    Some(&mut descriptor),
                )
            },
            ERROR_SUCCESS
        );
        let mut acl_words = [0usize; 128];
        let acl = acl_words.as_mut_ptr().cast::<ACL>();
        unsafe { InitializeAcl(acl, std::mem::size_of_val(&acl_words) as u32, ACL_REVISION) }
            .unwrap();
        unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, owner) }.unwrap();
        if public {
            let mut sid_words = [0usize; 16];
            let mut length = std::mem::size_of_val(&sid_words) as u32;
            let sid = PSID(sid_words.as_mut_ptr().cast());
            unsafe { CreateWellKnownSid(WinWorldSid, None, Some(sid), &mut length) }.unwrap();
            unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, sid) }.unwrap();
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    PCWSTR(wide.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(acl),
                    None,
                )
            },
            ERROR_SUCCESS
        );
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn discovery_reads_actual_owner_only_acl_and_rejects_broader_grants() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("search-endpoint-v1.json");
        let endpoint = AuthenticatedLocalEndpoint {
            schema_version: spiffy_shared::AUTHENTICATED_LOCAL_ENDPOINT_SCHEMA_VERSION,
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            process_id: std::process::id(),
            session_id: Uuid::new_v4().to_string(),
            endpoint: LocalTransportEndpoint::TcpLoopback {
                address: "127.0.0.1:32123".parse().unwrap(),
            },
            token: spiffy_shared::IpcAuthToken::generate().expose().to_string(),
            executable_digest_blake3: None,
            started_at: Utc::now(),
        };
        std::fs::write(&path, serde_json::to_vec(&endpoint).unwrap()).unwrap();
        fixture_acl(&path, false);
        let loaded = load_endpoint(&path).unwrap();
        assert_eq!(loaded.session_id, endpoint.session_id);
        assert_eq!(loaded.token, endpoint.token);
        fixture_acl(&path, true);
        assert!(matches!(
            load_endpoint(&path),
            Err(SearchError::Authentication(_))
        ));
        fixture_acl(&path, false);
        std::fs::write(&path, vec![b' '; 16 * 1024 + 1]).unwrap();
        assert!(load_endpoint(&path).is_err());
    }
    #[test]
    fn shelf_mode_rejects_filesystem_filters_instead_of_dropping_them() {
        assert_eq!(
            metadata_query("shelf: storyboard", None).unwrap(),
            Some("storyboard".into())
        );
        assert_eq!(metadata_query("shelf:", None).unwrap(), Some(String::new()));
        assert_eq!(
            metadata_query("shelf: \"project one\" storyboard", None).unwrap(),
            Some("\"project one\" storyboard".into())
        );
        for query in [
            "shelf: video:",
            "shelf: ext:mov",
            "shelf: favorite:",
            "shelf: path:C:/Projects",
        ] {
            assert!(metadata_query(query, None).is_err(), "{query}");
        }
        assert!(metadata_query("shelf: story", Some("C:/Projects")).is_err());
        assert_eq!(metadata_query("ext:mov", None).unwrap(), None);
    }

    #[test]
    fn live_transport_continues_scanning_and_results_with_exact_query_and_cursor() {
        use spiffy_shared::shelf_search::{ShelfSearchHit, ShelfSearchStage};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = AuthenticatedLocalEndpoint {
            schema_version: spiffy_shared::AUTHENTICATED_LOCAL_ENDPOINT_SCHEMA_VERSION,
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            process_id: std::process::id(),
            session_id: Uuid::new_v4().to_string(),
            endpoint: LocalTransportEndpoint::TcpLoopback {
                address: listener.local_addr().unwrap(),
            },
            token: spiffy_shared::IpcAuthToken::generate().expose().to_string(),
            executable_digest_blake3: None,
            started_at: Utc::now(),
        };
        let session = endpoint.session_id.clone();
        let token = endpoint.token.clone();
        let order = Uuid::new_v4();
        let worker = std::thread::spawn(move || {
            for page in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request: AuthenticatedLocalRequest<ShelfSearchCommand> =
                    read_json_frame(&mut stream, SHELF_SEARCH_MAX_FRAME_BYTES).unwrap();
                request.validate(Utc::now()).unwrap();
                assert_eq!(request.session_id, session);
                assert_eq!(request.token, token);
                let ShelfSearchCommand::QuerySavedShelf {
                    query,
                    generation,
                    limit,
                    cursor,
                    ..
                } = &request.command
                else {
                    panic!("wrong request")
                };
                assert_eq!(query, "\"teacher one\"");
                assert_eq!(*generation, 9);
                assert_eq!(*limit, 1);
                assert_eq!(
                    *cursor,
                    if page == 0 {
                        None
                    } else {
                        Some(format!("{order}:{}", page - 1))
                    }
                );
                let results = if page == 0 {
                    vec![]
                } else {
                    vec![ShelfSearchHit {
                        reference: ShelfSearchReference {
                            shelf_id: order,
                            shelf_stamp: "a".repeat(64),
                            item_id: Some(Uuid::new_v4()),
                            item_revision: Some(1),
                        },
                        title: format!("teacher one {page}"),
                        shelf_name: "Synthetic".into(),
                        kind: "text".into(),
                        missing: false,
                    }]
                };
                let reply = ShelfSearchReply {
                    protocol: SHELF_SEARCH_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    ok: true,
                    page: Some(ShelfSearchPage {
                        generation: 9,
                        results,
                        has_more: page < 2,
                        next_cursor: (page < 2).then(|| format!("{order}:{page}")),
                        stage: if page == 0 {
                            ShelfSearchStage::Scanning
                        } else {
                            ShelfSearchStage::Ready
                        },
                        scanned: 300,
                        complete: page == 2,
                    }),
                    navigation: None,
                    error_code: None,
                };
                write_json_frame(&mut stream, &reply, SHELF_SEARCH_MAX_FRAME_BYTES).unwrap();
            }
        });
        let mut cursor = None;
        let mut titles = Vec::new();
        loop {
            let page = exchange(
                &endpoint,
                ShelfSearchCommand::QuerySavedShelf {
                    protocol: SHELF_SEARCH_PROTOCOL_VERSION,
                    query: "\"teacher one\"".into(),
                    generation: 9,
                    limit: 1,
                    cursor,
                },
            )
            .unwrap()
            .page
            .unwrap();
            titles.extend(page.results.into_iter().map(|r| r.title));
            cursor = page.next_cursor;
            if page.complete {
                break;
            }
        }
        assert_eq!(titles, ["teacher one 1", "teacher one 2"]);
        worker.join().unwrap();
    }

    #[test]
    fn reply_identity_and_absolute_deadline_are_checked() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = AuthenticatedLocalEndpoint {
            schema_version: spiffy_shared::AUTHENTICATED_LOCAL_ENDPOINT_SCHEMA_VERSION,
            protocol: SHELF_SEARCH_PROTOCOL_VERSION,
            process_id: std::process::id(),
            session_id: Uuid::new_v4().to_string(),
            endpoint: LocalTransportEndpoint::TcpLoopback {
                address: listener.local_addr().unwrap(),
            },
            token: spiffy_shared::IpcAuthToken::generate().expose().to_string(),
            executable_digest_blake3: None,
            started_at: Utc::now(),
        };
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request: AuthenticatedLocalRequest<ShelfSearchCommand> =
                read_json_frame(&mut stream, SHELF_SEARCH_MAX_FRAME_BYTES).unwrap();
            request.validate(Utc::now()).unwrap();
            let reply = ShelfSearchReply {
                protocol: SHELF_SEARCH_PROTOCOL_VERSION,
                request_id: Uuid::new_v4(),
                ok: true,
                page: Some(ShelfSearchPage {
                    generation: 7,
                    results: vec![],
                    has_more: false,
                    next_cursor: None,
                    stage: spiffy_shared::shelf_search::ShelfSearchStage::Ready,
                    scanned: 0,
                    complete: true,
                }),
                navigation: None,
                error_code: None,
            };
            write_json_frame(&mut stream, &reply, SHELF_SEARCH_MAX_FRAME_BYTES).unwrap();
        });
        assert!(exchange(
            &endpoint,
            ShelfSearchCommand::QuerySavedShelf {
                protocol: SHELF_SEARCH_PROTOCOL_VERSION,
                generation: 7,
                query: "synthetic".into(),
                limit: 10,
                cursor: None,
            }
        )
        .is_err());
        worker.join().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut expired = DeadlineStream {
            stream,
            deadline: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(
            expired.read(&mut [0u8; 1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
