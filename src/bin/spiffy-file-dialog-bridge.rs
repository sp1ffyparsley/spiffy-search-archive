use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use spiffy_search::dialog::{self, DialogBridgeError};
use spiffy_search::logging::{prune_owned_daily_logs, search_env_filter, MAX_RETAINED_DAILY_LOGS};
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "spiffy-file-dialog-bridge",
    version,
    about = "Narrow native Open/Save dialog adapter for Spiffy Search"
)]
struct Cli {
    #[arg(long, global = true, help = "Print one machine-readable JSON reply")]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Inspect,
    Doctor {
        #[arg(long, help = "Request the macOS Accessibility prompt when needed")]
        request_permission: bool,
    },
    Profiles,
    OpenFolders,
    Navigate {
        #[arg(long)]
        dialog_id: String,
        folder: PathBuf,
    },
    PrepareFiles {
        #[arg(long)]
        dialog_id: String,
        #[arg(required = true, num_args = 1..)]
        files: Vec<PathBuf>,
    },
}

#[derive(Serialize)]
struct Reply {
    ok: bool,
    code: String,
    message: String,
    data: Option<Value>,
}

fn main() {
    let cli = Cli::parse();
    let log_guard = match initialize_logging() {
        Ok(guard) => Some(guard),
        Err(error) => {
            eprintln!("file-dialog bridge logging failed: {error}");
            None
        }
    };
    panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            tracing::error!(
                source_file = location.file(),
                source_line = location.line(),
                source_column = location.column(),
                "Spiffy file-dialog bridge panicked"
            );
        } else {
            tracing::error!("Spiffy file-dialog bridge panicked without a source location");
        }
    }));

    let label = command_label(&cli.command);
    let result = panic::catch_unwind(AssertUnwindSafe(|| run(cli.command)))
        .map_err(|_| {
            DialogBridgeError::Platform(
                "internal file-dialog bridge failure; check the local Search log".to_string(),
            )
        })
        .and_then(|result| result);
    let (reply, exit_code) = match result {
        Ok(data) => {
            tracing::info!(command = label, "file-dialog bridge command completed");
            (
                Reply {
                    ok: true,
                    code: "ok".to_string(),
                    message: format!("File-dialog bridge {label} complete"),
                    data: Some(data),
                },
                0,
            )
        }
        Err(error) => {
            tracing::warn!(
                command = label,
                code = error.code(),
                "file-dialog bridge command failed"
            );
            (
                Reply {
                    ok: false,
                    code: error.code().to_string(),
                    message: error.to_string(),
                    data: None,
                },
                2,
            )
        }
    };
    print_reply(&reply, cli.json);
    drop(log_guard);
    std::process::exit(exit_code);
}

fn run(command: Command) -> Result<Value, DialogBridgeError> {
    match command {
        Command::Inspect => serialize(dialog::inspect_active()?),
        Command::Doctor { request_permission } => serialize(dialog::doctor(request_permission)?),
        Command::Profiles => serialize(dialog::built_in_profiles()),
        Command::OpenFolders => serialize(dialog::list_open_folders()?),
        Command::Navigate { dialog_id, folder } => {
            serialize(dialog::navigate_folder(&dialog_id, &folder)?)
        }
        Command::PrepareFiles { dialog_id, files } => {
            serialize(dialog::prepare_files(&dialog_id, &files)?)
        }
    }
}

fn serialize(value: impl Serialize) -> Result<Value, DialogBridgeError> {
    serde_json::to_value(value).map_err(|error| {
        DialogBridgeError::Platform(format!("could not encode bridge response: {error}"))
    })
}

fn command_label(command: &Command) -> &'static str {
    match command {
        Command::Inspect => "inspect",
        Command::Doctor { .. } => "doctor",
        Command::Profiles => "profiles",
        Command::OpenFolders => "open-folders",
        Command::Navigate { .. } => "navigate",
        Command::PrepareFiles { .. } => "prepare-files",
    }
}

fn print_reply(reply: &Reply, json: bool) {
    if json {
        match serde_json::to_string_pretty(reply) {
            Ok(encoded) => println!("{encoded}"),
            Err(error) => eprintln!("could not encode bridge reply: {error}"),
        }
    } else if reply.ok {
        println!("{}", reply.message);
        if let Some(data) = &reply.data {
            if let Ok(encoded) = serde_json::to_string_pretty(data) {
                println!("{encoded}");
            }
        }
    } else {
        eprintln!("{}: {}", reply.code, reply.message);
    }
}

fn initialize_logging(
) -> Result<tracing_appender::non_blocking::WorkerGuard, Box<dyn std::error::Error + Send + Sync>> {
    let log_dir = spiffy_shared::product_log_dir(spiffy_shared::Product::Search);
    fs::create_dir_all(&log_dir)?;
    if let Err(error) =
        prune_owned_daily_logs(&log_dir, "file-dialog-bridge.log", MAX_RETAINED_DAILY_LOGS)
    {
        eprintln!("could not prune old Spiffy Search file-dialog logs: {error}");
    }
    let appender = tracing_appender::rolling::daily(&log_dir, "file-dialog-bridge.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = search_env_filter();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .try_init()?;
    Ok(guard)
}
