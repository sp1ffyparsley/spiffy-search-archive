use crate::error::{SearchError, SearchResult};
use crate::ipc;
use crate::protocol::{
    AgentCommand, AgentReply, BrowserHistoryStatus, FileConflictPolicy, FileOperationKind,
    FileOperationRequest, FileOperationStatus, SearchResponse,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "spiffy-searchctl",
    version,
    about = "Control the local Spiffy Search agent"
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Print the complete machine-readable agent reply"
    )]
    json: bool,
    #[arg(long, global = true, hide = true)]
    endpoint: Option<PathBuf>,
    #[command(subcommand)]
    command: CommandLine,
}

#[derive(Debug, Subcommand)]
enum CommandLine {
    /// Print compiled product, protocol, and binary-set metadata without contacting the agent.
    BuildInfo,
    /// Read live saved Shelf metadata or reveal an exact returned reference in Shelf.
    Shelf {
        #[command(subcommand)]
        command: ShelfCommand,
    },
    /// Connect Search to launcher metadata owned by the Spiffy workspace catalog.
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    Start,
    Status,
    Doctor,
    Search {
        #[arg(required = true, num_args = 1..)]
        query: Vec<String>,
        /// Continue a shelf: metadata page using the returned opaque cursor.
        #[arg(long)]
        shelf_cursor: Option<String>,
        #[arg(long)]
        limit: Option<u16>,
        #[arg(long)]
        current_folder: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        generation: u64,
    },
    Parse {
        #[arg(required = true, num_args = 1..)]
        query: Vec<String>,
    },
    Filters {
        #[arg(default_value = "")]
        prefix: String,
    },
    Metadata {
        stable_key: String,
    },
    PreviewText {
        stable_key: String,
        #[arg(long)]
        max_chars: Option<u32>,
    },
    Favorites {
        #[arg(long)]
        limit: Option<u16>,
    },
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    Reindex {
        #[arg(long)]
        root_id: Option<Uuid>,
    },
    Content {
        #[command(subcommand)]
        command: ContentCommand,
    },
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    Favorite {
        stable_key: String,
        display_name: String,
        path: PathBuf,
        #[arg(long)]
        off: bool,
    },
    Pin {
        stable_key: String,
        display_name: String,
        path: PathBuf,
        #[arg(long)]
        off: bool,
    },
    Aliases {
        stable_key: String,
        aliases: Vec<String>,
    },
    Usage {
        stable_key: String,
        #[arg(long)]
        opened: bool,
    },
    Stop,
}

#[derive(Debug, Subcommand)]
enum RootCommand {
    List,
    Add {
        path: PathBuf,
        #[arg(long)]
        remote_searchable: bool,
        #[arg(long = "exclude")]
        exclusions: Vec<String>,
        #[arg(long)]
        no_index: bool,
    },
    Remove {
        root_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum ShelfCommand {
    /// Shared all-words/quoted-phrase metadata; never item bodies or local paths.
    Search {
        #[arg(default_value = "")]
        query: String,
        #[arg(long, default_value_t = 50)]
        limit: u16,
        #[arg(long, default_value_t = 1)]
        generation: u64,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Wait for Shelf to select the exact saved shelf/item and acknowledge it.
    Reveal {
        #[arg(long)]
        shelf_id: Uuid,
        #[arg(long)]
        shelf_stamp: String,
        #[arg(long, requires = "item_revision")]
        item_id: Option<Uuid>,
        #[arg(long, requires = "item_id")]
        item_revision: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    /// Validate and persist one workspace catalog for Application search results.
    Connect { catalog: PathBuf },
    /// Remove the configured workspace catalog connection.
    Disconnect,
    /// Show the configured workspace catalog path.
    Status,
}

#[derive(Debug, Subcommand)]
enum ContentCommand {
    Index { paths: Vec<PathBuf> },
    Status,
}

#[derive(Debug, Subcommand)]
enum BrowserCommand {
    Refresh,
    Status,
    Clear,
}

#[derive(Debug, Subcommand)]
enum FileCommand {
    Preview(FileRequestArgs),
    Run(FileRequestArgs),
    Status { operation_id: Uuid },
    Cancel { operation_id: Uuid },
    Undo { operation_id: Uuid },
}

#[derive(Debug, Args)]
struct FileRequestArgs {
    #[arg(value_enum)]
    kind: FileKindArgument,
    #[arg(long = "source", required = true, num_args = 1..)]
    sources: Vec<PathBuf>,
    #[arg(long)]
    destination: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ConflictArgument::Fail)]
    conflict: ConflictArgument,
    #[arg(long)]
    operation_id: Option<Uuid>,
    #[arg(long)]
    confirmation_token: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FileKindArgument {
    Copy,
    Move,
    Rename,
    Trash,
}

impl From<FileKindArgument> for FileOperationKind {
    fn from(value: FileKindArgument) -> Self {
        match value {
            FileKindArgument::Copy => Self::Copy,
            FileKindArgument::Move => Self::Move,
            FileKindArgument::Rename => Self::Rename,
            FileKindArgument::Trash => Self::Trash,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum ConflictArgument {
    #[default]
    Fail,
    KeepBoth,
}

impl From<ConflictArgument> for FileConflictPolicy {
    fn from(value: ConflictArgument) -> Self {
        match value {
            ConflictArgument::Fail => Self::Fail,
            ConflictArgument::KeepBoth => Self::KeepBoth,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FollowUp {
    ReindexAddedRoot,
    WaitForBrowserRefresh,
    WaitForFileOperation(Uuid),
}

pub async fn run() -> SearchResult<i32> {
    run_cli(Cli::parse()).await
}

async fn run_cli(cli: Cli) -> SearchResult<i32> {
    if matches!(cli.command, CommandLine::BuildInfo) {
        let reply = build_info_reply();
        print_reply(&reply, cli.json)?;
        return Ok(0);
    }

    if let CommandLine::Workspace { command } = cli.command {
        if cli.endpoint.is_some() {
            return Err(SearchError::Config(
                "workspace configuration is local and does not accept an endpoint override"
                    .to_string(),
            ));
        }
        let reply = workspace_catalog_reply(&crate::config::config_path(), command)?;
        print_reply(&reply, cli.json)?;
        return Ok(i32::from(!reply.ok));
    }

    if let CommandLine::Shelf { command } = cli.command {
        if cli.endpoint.is_some() {
            return Err(SearchError::Config("Shelf commands use the fixed separate Shelf discovery; a Search endpoint override is not accepted".into()));
        }
        let result = tokio::task::spawn_blocking(move || -> SearchResult<AgentReply> {
            Ok(match command {
                ShelfCommand::Search {
                    query,
                    limit,
                    generation,
                    cursor,
                } => AgentReply::success(
                    "Saved Shelf metadata page",
                    crate::shelf::query(query, generation, limit, cursor)?,
                ),
                ShelfCommand::Reveal {
                    shelf_id,
                    shelf_stamp,
                    item_id,
                    item_revision,
                } => AgentReply::success(
                    "Saved Shelf navigation acknowledged",
                    crate::shelf::reveal(spiffy_shared::shelf_search::ShelfSearchReference {
                        shelf_id,
                        shelf_stamp,
                        item_id,
                        item_revision,
                    })?,
                ),
            })
        })
        .await
        .unwrap_or_else(|_| {
            Err(SearchError::State(
                "saved Shelf request worker failed".into(),
            ))
        });
        let reply = result.unwrap_or_else(|error| {
            AgentReply::failure("saved_shelf_request_failed", error.to_string())
        });
        print_reply(&reply, cli.json)?;
        return Ok(i32::from(!reply.ok));
    }

    let endpoint = cli
        .endpoint
        .unwrap_or_else(crate::config::ipc_endpoint_path);
    if matches!(cli.command, CommandLine::Start) {
        if endpoint != crate::config::ipc_endpoint_path() {
            return Err(SearchError::Config(
                "start cannot be combined with a custom endpoint".to_string(),
            ));
        }
        let reply = start_agent(&endpoint).await?;
        print_reply(&reply, cli.json)?;
        return Ok(i32::from(!reply.ok));
    }

    let (command, follow_up) = command_for(cli.command)?;
    let reply = ipc::send_command_at(&endpoint, command)
        .await
        .map_err(|error| {
            SearchError::Protocol(format!(
                "{error}; start the agent with 'spiffy-searchctl start'"
            ))
        })?;
    if !reply.ok {
        print_reply(&reply, cli.json)?;
        return Ok(2);
    }
    match follow_up {
        Some(FollowUp::ReindexAddedRoot) => {
            if !cli.json {
                print_reply(&reply, false)?;
            }
            let root_value = reply.data.clone().ok_or_else(|| {
                SearchError::Protocol("add-root response omitted the new root".to_string())
            })?;
            let root: crate::catalog::SourceRoot = serde_json::from_value(root_value.clone())
                .map_err(|error| {
                    SearchError::Protocol(format!("add-root response was invalid: {error}"))
                })?;
            let follow_reply = ipc::send_command_at(
                &endpoint,
                AgentCommand::Reindex {
                    root_id: Some(root.id),
                },
            )
            .await?;
            if cli.json {
                print_reply(&combined_add_root_reply(root_value, &follow_reply), true)?;
            } else {
                print_reply(&follow_reply, false)?;
            }
            if !follow_reply.ok {
                return Ok(2);
            }
        }
        Some(FollowUp::WaitForFileOperation(operation_id)) => {
            let terminal = wait_for_file_operation(&endpoint, operation_id).await?;
            print_reply(&terminal, cli.json)?;
            if !terminal.ok
                || terminal
                    .data
                    .as_ref()
                    .and_then(|data| {
                        serde_json::from_value::<FileOperationStatus>(data.clone()).ok()
                    })
                    .is_some_and(|status| {
                        !matches!(
                            status.receipt.state,
                            crate::protocol::FileOperationState::Complete
                                | crate::protocol::FileOperationState::Undone
                        )
                    })
            {
                return Ok(2);
            }
        }
        Some(FollowUp::WaitForBrowserRefresh) => {
            let terminal = wait_for_browser_refresh(&endpoint).await?;
            let failed = terminal
                .data
                .as_ref()
                .and_then(|data| serde_json::from_value::<BrowserHistoryStatus>(data.clone()).ok())
                .is_none_or(|status| {
                    status.latest_error.is_some()
                        || status.latest_report.is_some_and(|report| {
                            report
                                .providers
                                .iter()
                                .any(|provider| provider.enabled && !provider.succeeded)
                        })
                });
            print_reply(&terminal, cli.json)?;
            if !terminal.ok || failed {
                return Ok(2);
            }
        }
        None => print_reply(&reply, cli.json)?,
    }
    Ok(0)
}

fn build_info_reply() -> AgentReply {
    AgentReply::success(
        "Compiled Spiffy Search build information",
        serde_json::json!({
            "schema_version": 1,
            "product": "spiffy-search",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": crate::protocol::SEARCH_PROTOCOL_VERSION,
            "saved_shelf_protocol": spiffy_shared::shelf_search::SHELF_SEARCH_PROTOCOL_VERSION,
            "binaries": [
                "spiffy-search-agent",
                "spiffy-searchctl",
                "spiffy-search-content-worker",
                "spiffy-search-mcp",
                "spiffy-file-dialog-bridge",
            ],
        }),
    )
}

fn workspace_catalog_reply(
    config_path: &Path,
    command: WorkspaceCommand,
) -> SearchResult<AgentReply> {
    let mut config = crate::config::SearchConfig::load_or_create(config_path)?;
    let (message, changed) = match command {
        WorkspaceCommand::Connect { catalog } => {
            let absolute = std::path::absolute(&catalog)
                .map_err(|error| crate::error::io_error(&catalog, error))?;
            let canonical = absolute
                .canonicalize()
                .map_err(|error| crate::error::io_error(&absolute, error))?;
            crate::workspace_catalog::load(&canonical, Uuid::nil())?;
            let changed = config.workspace_catalog_path.as_ref() != Some(&canonical);
            config.workspace_catalog_path = Some(canonical);
            if changed {
                config.save(config_path)?;
            }
            ("Workspace catalog connected", changed)
        }
        WorkspaceCommand::Disconnect => {
            let changed = config.workspace_catalog_path.take().is_some();
            if changed {
                config.save(config_path)?;
            }
            ("Workspace catalog disconnected", changed)
        }
        WorkspaceCommand::Status => ("Workspace catalog status", false),
    };
    Ok(AgentReply::success(
        message,
        serde_json::json!({
            "connected": config.workspace_catalog_path.is_some(),
            "catalog": config.workspace_catalog_path,
            "restart_required": changed,
        }),
    ))
}

fn combined_add_root_reply(root: serde_json::Value, indexing: &AgentReply) -> AgentReply {
    AgentReply {
        ok: indexing.ok,
        code: indexing.code.clone(),
        message: if indexing.ok {
            "Source root added and indexing started".to_string()
        } else {
            format!(
                "Source root was added, but automatic indexing failed: {}",
                indexing.message
            )
        },
        data: Some(serde_json::json!({
            "root": root,
            "indexing": indexing.data.clone(),
        })),
    }
}

fn command_for(command: CommandLine) -> SearchResult<(AgentCommand, Option<FollowUp>)> {
    Ok(match command {
        CommandLine::BuildInfo => unreachable!("build-info handled before IPC conversion"),
        CommandLine::Workspace { .. } => {
            unreachable!("workspace configuration handled before IPC conversion")
        }
        CommandLine::Shelf { .. } => {
            unreachable!("Shelf capability handled before Search IPC conversion")
        }
        CommandLine::Start => unreachable!("start handled before command conversion"),
        CommandLine::Status => (AgentCommand::Status, None),
        CommandLine::Doctor => (AgentCommand::Doctor, None),
        CommandLine::Search {
            query,
            shelf_cursor,
            limit,
            current_folder,
            generation,
        } if shelf_cursor.is_some() => {
            let metadata = crate::shelf::metadata_query(
                &query.join(" "),
                current_folder.as_ref().and_then(|p| p.to_str()),
            )?
            .ok_or_else(|| SearchError::Query("--shelf-cursor requires a shelf: query".into()))?;
            (
                AgentCommand::ShelfSearchPage {
                    query: metadata,
                    generation,
                    limit: limit.unwrap_or(50),
                    cursor: shelf_cursor,
                },
                None,
            )
        }
        CommandLine::Search {
            query,
            limit,
            current_folder,
            generation,
            ..
        } => (
            AgentCommand::Search {
                query: query.join(" "),
                generation,
                limit,
                current_folder: current_folder.map(|path| path.to_string_lossy().to_string()),
            },
            None,
        ),
        CommandLine::Parse { query } => (
            AgentCommand::ParseQuery {
                query: query.join(" "),
            },
            None,
        ),
        CommandLine::Filters { prefix } => (AgentCommand::FilterSuggestions { prefix }, None),
        CommandLine::Metadata { stable_key } => {
            (AgentCommand::GetItemMetadata { stable_key }, None)
        }
        CommandLine::PreviewText {
            stable_key,
            max_chars,
        } => (
            AgentCommand::GetPreviewText {
                stable_key,
                max_chars,
            },
            None,
        ),
        CommandLine::Favorites { limit } => (AgentCommand::ListFavorites { limit }, None),
        CommandLine::Root { command } => match command {
            RootCommand::List => (AgentCommand::ListRoots, None),
            RootCommand::Add {
                path,
                remote_searchable,
                exclusions,
                no_index,
            } => (
                AgentCommand::AddRoot {
                    path: path.to_string_lossy().to_string(),
                    remote_searchable,
                    exclusions,
                },
                (!no_index).then_some(FollowUp::ReindexAddedRoot),
            ),
            RootCommand::Remove { root_id } => (AgentCommand::RemoveRoot { root_id }, None),
        },
        CommandLine::Reindex { root_id } => (AgentCommand::Reindex { root_id }, None),
        CommandLine::Content { command } => match command {
            ContentCommand::Index { paths } => (
                AgentCommand::ContentIndex {
                    paths: paths
                        .into_iter()
                        .map(|path| path.to_string_lossy().to_string())
                        .collect(),
                },
                None,
            ),
            ContentCommand::Status => (AgentCommand::ContentStatus, None),
        },
        CommandLine::Browser { command } => match command {
            BrowserCommand::Refresh => (
                AgentCommand::RefreshBrowserHistory,
                Some(FollowUp::WaitForBrowserRefresh),
            ),
            BrowserCommand::Status => (AgentCommand::BrowserHistoryStatus, None),
            BrowserCommand::Clear => (AgentCommand::ClearBrowserHistory, None),
        },
        CommandLine::File { command } => match command {
            FileCommand::Preview(arguments) => {
                let request = file_request(arguments, false)?;
                (AgentCommand::FileOperation { request }, None)
            }
            FileCommand::Run(arguments) => {
                let request = file_request(arguments, true)?;
                let operation_id = request.operation_id;
                (
                    AgentCommand::FileOperation { request },
                    Some(FollowUp::WaitForFileOperation(operation_id)),
                )
            }
            FileCommand::Status { operation_id } => {
                (AgentCommand::FileOperationStatus { operation_id }, None)
            }
            FileCommand::Cancel { operation_id } => {
                (AgentCommand::CancelFileOperation { operation_id }, None)
            }
            FileCommand::Undo { operation_id } => (
                AgentCommand::UndoFileOperation { operation_id },
                Some(FollowUp::WaitForFileOperation(operation_id)),
            ),
        },
        CommandLine::Favorite {
            stable_key,
            display_name,
            path,
            off,
        } => (
            AgentCommand::SetFavorite {
                stable_key,
                display_name,
                path: path.to_string_lossy().to_string(),
                favorite: !off,
            },
            None,
        ),
        CommandLine::Pin {
            stable_key,
            display_name,
            path,
            off,
        } => (
            AgentCommand::SetPinned {
                stable_key,
                display_name,
                path: path.to_string_lossy().to_string(),
                pinned: !off,
            },
            None,
        ),
        CommandLine::Aliases {
            stable_key,
            aliases,
        } => (
            AgentCommand::SetAliases {
                stable_key,
                aliases,
            },
            None,
        ),
        CommandLine::Usage { stable_key, opened } => (
            AgentCommand::RecordUsage {
                stable_key,
                selected: !opened,
            },
            None,
        ),
        CommandLine::Stop => (AgentCommand::Shutdown, None),
    })
}

fn file_request(arguments: FileRequestArgs, confirmed: bool) -> SearchResult<FileOperationRequest> {
    let kind: FileOperationKind = arguments.kind.into();
    let sources = arguments
        .sources
        .into_iter()
        .map(|path| {
            std::path::absolute(&path)
                .map(|path| path.to_string_lossy().to_string())
                .map_err(|error| crate::error::io_error(path, error))
        })
        .collect::<SearchResult<Vec<_>>>()?;
    let destination = arguments
        .destination
        .map(|path| {
            if kind == FileOperationKind::Rename
                && !path.is_absolute()
                && path.components().count() == 1
            {
                Ok(path.to_string_lossy().to_string())
            } else {
                std::path::absolute(&path)
                    .map(|path| path.to_string_lossy().to_string())
                    .map_err(|error| crate::error::io_error(path, error))
            }
        })
        .transpose()?;
    Ok(FileOperationRequest {
        operation_id: arguments.operation_id.unwrap_or_else(Uuid::new_v4),
        kind,
        sources,
        destination,
        conflict_policy: arguments.conflict.into(),
        confirmation_token: arguments.confirmation_token,
        confirmed,
    })
}

async fn wait_for_file_operation(endpoint: &Path, operation_id: Uuid) -> SearchResult<AgentReply> {
    loop {
        let reply =
            ipc::send_command_at(endpoint, AgentCommand::FileOperationStatus { operation_id })
                .await?;
        if !reply.ok {
            return Ok(reply);
        }
        let status: FileOperationStatus = serde_json::from_value(
            reply
                .data
                .clone()
                .ok_or_else(|| SearchError::Protocol("file status omitted data".to_string()))?,
        )
        .map_err(|error| SearchError::Protocol(format!("file status was invalid: {error}")))?;
        if !status.active {
            return Ok(reply);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_browser_refresh(endpoint: &Path) -> SearchResult<AgentReply> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
    loop {
        let reply = ipc::send_command_at(endpoint, AgentCommand::BrowserHistoryStatus).await?;
        if !reply.ok {
            return Ok(reply);
        }
        let status: BrowserHistoryStatus = serde_json::from_value(
            reply
                .data
                .clone()
                .ok_or_else(|| SearchError::Protocol("browser status omitted data".to_string()))?,
        )
        .map_err(|error| SearchError::Protocol(format!("browser status was invalid: {error}")))?;
        if !status.refreshing {
            return Ok(reply);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(SearchError::Protocol(
                "browser history refresh did not finish within 15 minutes".to_string(),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn start_agent(endpoint: &Path) -> SearchResult<AgentReply> {
    if let Ok(reply) = ipc::send_command_at(endpoint, AgentCommand::Status).await {
        return Ok(reply);
    }
    let executable = agent_executable()?;
    launch_agent_process(&executable)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match ipc::send_command_at(endpoint, AgentCommand::Status).await {
            Ok(reply) => return Ok(reply),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => {
                return Err(SearchError::State(format!(
                    "Spiffy Search agent did not become ready: {error}"
                )));
            }
        }
    }
}

#[cfg(not(windows))]
fn launch_agent_process(executable: &Path) -> SearchResult<()> {
    let mut command = Command::new(executable);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().map_err(|error| {
        SearchError::State(format!("could not start {}: {error}", executable.display()))
    })?;
    Ok(())
}

#[cfg(windows)]
fn launch_agent_process(executable: &Path) -> SearchResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW,
    };
    let path: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // A background owner needs no inherited handles. Stdio::null alone still
    // lets Windows inherit the CLI's original pipe handles, preventing callers
    // from observing stdout EOF until the long-lived agent stops.
    // SAFETY: exact resolved sibling executable, terminated UTF-16 path, no
    // shell/arguments, no inherited handles; process handles are closed below.
    unsafe {
        CreateProcessW(
            PCWSTR(path.as_ptr()),
            None,
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &startup,
            &mut process,
        )
        .map_err(|error| {
            SearchError::State(format!(
                "could not start {} without inherited handles: {error}",
                executable.display()
            ))
        })?;
        let _ = CloseHandle(process.hThread);
        let _ = CloseHandle(process.hProcess);
    }
    Ok(())
}

fn agent_executable() -> SearchResult<PathBuf> {
    let current = std::env::current_exe()
        .map_err(|error| crate::error::io_error("current executable", error))?;
    let filename = if cfg!(windows) {
        "spiffy-search-agent.exe"
    } else {
        "spiffy-search-agent"
    };
    let sibling = current
        .parent()
        .ok_or_else(|| SearchError::State("CLI executable has no parent directory".to_string()))?
        .join(filename);
    if sibling.is_file() {
        Ok(sibling)
    } else {
        Err(SearchError::State(format!(
            "agent executable is missing beside the CLI: {}",
            sibling.display()
        )))
    }
}

fn print_reply(reply: &AgentReply, json_output: bool) -> SearchResult<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(reply)?);
        return Ok(());
    }
    if !reply.ok {
        eprintln!("{}: {}", reply.code, reply.message);
        return Ok(());
    }
    if let Some(data) = &reply.data {
        if let Ok(search) = serde_json::from_value::<SearchResponse>(data.clone()) {
            println!(
                "{} result(s), {} us, index generation {}",
                search.hits.len(),
                search.elapsed_micros,
                search.index_generation
            );
            for hit in search.hits {
                println!("{:.1}\t{}", hit.score, hit.record.display_path);
            }
            return Ok(());
        }
        println!("{}", serde_json::to_string_pretty(data)?);
    } else {
        println!("{}", reply.message);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn saved_shelf_cli_accepts_opaque_continuation_without_endpoint_fallback() {
        let cursor = format!("{}:100", Uuid::new_v4());
        let cli = Cli::try_parse_from([
            "spiffy-searchctl",
            "shelf",
            "search",
            "\"teacher one\"",
            "--cursor",
            &cursor,
        ])
        .unwrap();
        assert!(
            matches!(cli.command,CommandLine::Shelf{command:ShelfCommand::Search{query,cursor:Some(next),..}} if query=="\"teacher one\""&&next==cursor)
        );
        let cli = Cli::try_parse_from([
            "spiffy-searchctl",
            "search",
            "shelf: teacher",
            "--shelf-cursor",
            &cursor,
        ])
        .unwrap();
        assert!(
            matches!(cli.command,CommandLine::Search{shelf_cursor:Some(next),..} if next==cursor)
        );
        let command = AgentCommand::ShelfSearchPage {
            query: "teacher".into(),
            generation: 1,
            limit: 31,
            cursor: Some(cursor),
        };
        assert_eq!(command.minimum_protocol_minor(), 5);
        assert!(!format!("{command:?}").contains("teacher"));
    }

    #[tokio::test]
    async fn saved_shelf_cli_keeps_exact_reference_and_refuses_endpoint_override() {
        let id = Uuid::new_v4().to_string();
        let stamp = "a".repeat(64);
        assert!(Cli::try_parse_from([
            "spiffy-searchctl",
            "shelf",
            "reveal",
            "--shelf-id",
            &id,
            "--shelf-stamp",
            &stamp,
            "--item-id",
            &id
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "spiffy-searchctl",
            "shelf",
            "reveal",
            "--shelf-id",
            &id,
            "--shelf-stamp",
            &stamp,
            "--item-id",
            &id,
            "--item-revision",
            "3",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            CommandLine::Shelf {
                command: ShelfCommand::Reveal {
                    item_revision: Some(3),
                    ..
                }
            }
        ));
        let cli = Cli::try_parse_from([
            "spiffy-searchctl",
            "--endpoint",
            "synthetic-override",
            "shelf",
            "search",
            "synthetic",
        ])
        .unwrap();
        assert!(matches!(run_cli(cli).await, Err(SearchError::Config(_))));
    }

    #[test]
    fn build_info_is_local_and_uses_the_canonical_protocol() {
        let cli = Cli::try_parse_from(["spiffy-searchctl", "build-info"]).unwrap();
        assert!(matches!(cli.command, CommandLine::BuildInfo));

        let reply = build_info_reply();
        let data = reply.data.unwrap();
        assert_eq!(data["product"], "spiffy-search");
        assert_eq!(data["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            serde_json::from_value::<spiffy_shared::ProtocolVersion>(data["protocol"].clone())
                .unwrap(),
            crate::protocol::SEARCH_PROTOCOL_VERSION
        );
        assert_eq!(data["binaries"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn workspace_connect_validates_and_persists_catalog_without_ipc() {
        let temp = tempfile::tempdir().unwrap();
        let launcher = temp.path().join("Launch.command");
        std::fs::write(&launcher, b"#!/bin/zsh\n").unwrap();
        let catalog_path = temp.path().join("workspace_catalog.json");
        std::fs::write(
            &catalog_path,
            serde_json::to_vec(&serde_json::json!({
                "schema": "ss_scripts_workspace_catalog_v1",
                "version": 1,
                "systems": [{
                    "id": "spiffy_workspace",
                    "label": "Spiffy Workspace",
                    "platforms": ["windows", "macos"],
                    "launch_targets": [{
                        "id": "editor",
                        "label": "Spiffy Video Editor",
                        "platform_paths": {
                            "windows": "Launch.command",
                            "macos": "Launch.command"
                        }
                    }]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let config_path = temp.path().join("search-config.json");

        let connected = workspace_catalog_reply(
            &config_path,
            WorkspaceCommand::Connect {
                catalog: catalog_path.clone(),
            },
        )
        .unwrap();
        assert!(connected.ok);
        assert_eq!(connected.data.as_ref().unwrap()["restart_required"], true);
        let config = crate::config::SearchConfig::load_or_create(&config_path).unwrap();
        assert_eq!(
            config.workspace_catalog_path,
            Some(catalog_path.canonicalize().unwrap())
        );

        let status = workspace_catalog_reply(&config_path, WorkspaceCommand::Status).unwrap();
        assert_eq!(status.data.as_ref().unwrap()["connected"], true);
        assert_eq!(status.data.as_ref().unwrap()["restart_required"], false);

        let disconnected =
            workspace_catalog_reply(&config_path, WorkspaceCommand::Disconnect).unwrap();
        assert_eq!(
            disconnected.data.as_ref().unwrap()["restart_required"],
            true
        );
        let config = crate::config::SearchConfig::load_or_create(&config_path).unwrap();
        assert!(config.workspace_catalog_path.is_none());
    }

    #[test]
    fn workspace_command_parses_as_a_local_configuration_surface() {
        let cli = Cli::try_parse_from([
            "spiffy-searchctl",
            "workspace",
            "connect",
            "C:/Spiffy/workspace_catalog.json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            CommandLine::Workspace {
                command: WorkspaceCommand::Connect { .. }
            }
        ));
    }

    #[test]
    fn parses_search_root_and_overlay_commands_without_shell_reconstruction() {
        let search = Cli::try_parse_from([
            "spiffy-searchctl",
            "search",
            "hero",
            "clip",
            "--limit",
            "25",
        ])
        .unwrap();
        let (command, _) = command_for(search.command).unwrap();
        assert!(matches!(
            command,
            AgentCommand::Search { query, limit: Some(25), .. } if query == "hero clip"
        ));

        let root = Cli::try_parse_from([
            "spiffy-searchctl",
            "root",
            "add",
            "C:/Media",
            "--exclude",
            "Cache/**",
            "--no-index",
        ])
        .unwrap();
        let (command, follow_up) = command_for(root.command).unwrap();
        assert!(matches!(command, AgentCommand::AddRoot { .. }));
        assert!(follow_up.is_none());

        let pin = Cli::try_parse_from([
            "spiffy-searchctl",
            "pin",
            "volume:file",
            "Hero.mov",
            "C:/Media/Hero.mov",
            "--off",
        ])
        .unwrap();
        let (command, _) = command_for(pin.command).unwrap();
        assert!(matches!(
            command,
            AgentCommand::SetPinned { pinned: false, .. }
        ));

        let operation_id = Uuid::new_v4();
        let file = Cli::try_parse_from([
            "spiffy-searchctl",
            "file",
            "run",
            "copy",
            "--source",
            "C:/Media/Hero.mov",
            "--destination",
            "C:/Archive",
            "--conflict",
            "keep-both",
            "--operation-id",
            &operation_id.to_string(),
            "--confirmation-token",
            "preview-token",
        ])
        .unwrap();
        let (command, follow_up) = command_for(file.command).unwrap();
        assert!(matches!(
            command,
            AgentCommand::FileOperation {
                request: FileOperationRequest {
                    kind: FileOperationKind::Copy,
                    conflict_policy: FileConflictPolicy::KeepBoth,
                    confirmation_token: Some(_),
                    confirmed: true,
                    ..
                }
            }
        ));
        assert!(matches!(
            follow_up,
            Some(FollowUp::WaitForFileOperation(id)) if id == operation_id
        ));
    }

    #[test]
    fn combines_add_root_and_reindex_as_one_machine_readable_reply() {
        let root = serde_json::json!({"id": "root-1", "canonical_path": "C:/Media"});
        let indexing = AgentReply::success(
            "Indexing started",
            serde_json::json!({"root_id": "root-1", "started": true}),
        );

        let reply = combined_add_root_reply(root, &indexing);
        let encoded = serde_json::to_string(&reply).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();

        assert!(reply.ok);
        assert_eq!(decoded["data"]["root"]["id"], "root-1");
        assert_eq!(decoded["data"]["indexing"]["started"], true);
    }

    #[test]
    fn maps_browser_commands_to_protocol_actions_and_refresh_follow_up() {
        let refresh = Cli::try_parse_from(["spiffy-searchctl", "browser", "refresh"]).unwrap();
        let (command, follow_up) = command_for(refresh.command).unwrap();
        assert!(matches!(command, AgentCommand::RefreshBrowserHistory));
        assert!(matches!(follow_up, Some(FollowUp::WaitForBrowserRefresh)));

        let status = Cli::try_parse_from(["spiffy-searchctl", "browser", "status"]).unwrap();
        let (command, follow_up) = command_for(status.command).unwrap();
        assert!(matches!(command, AgentCommand::BrowserHistoryStatus));
        assert!(follow_up.is_none());

        let clear = Cli::try_parse_from(["spiffy-searchctl", "browser", "clear"]).unwrap();
        let (command, follow_up) = command_for(clear.command).unwrap();
        assert!(matches!(command, AgentCommand::ClearBrowserHistory));
        assert!(follow_up.is_none());
    }

    #[test]
    fn maps_read_only_access_commands_without_mutation_follow_up() {
        let metadata = Cli::try_parse_from(["spiffy-searchctl", "metadata", "stable-key"]).unwrap();
        let (command, follow_up) = command_for(metadata.command).unwrap();
        assert!(matches!(
            command,
            AgentCommand::GetItemMetadata { stable_key } if stable_key == "stable-key"
        ));
        assert!(follow_up.is_none());

        let preview = Cli::try_parse_from([
            "spiffy-searchctl",
            "preview-text",
            "stable-key",
            "--max-chars",
            "1000",
        ])
        .unwrap();
        let (command, follow_up) = command_for(preview.command).unwrap();
        assert!(matches!(
            command,
            AgentCommand::GetPreviewText {
                max_chars: Some(1000),
                ..
            }
        ));
        assert!(follow_up.is_none());

        let favorites =
            Cli::try_parse_from(["spiffy-searchctl", "favorites", "--limit", "20"]).unwrap();
        let (command, follow_up) = command_for(favorites.command).unwrap();
        assert!(matches!(
            command,
            AgentCommand::ListFavorites { limit: Some(20) }
        ));
        assert!(follow_up.is_none());
    }
}
