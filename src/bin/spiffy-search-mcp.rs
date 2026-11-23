use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "spiffy-search-mcp",
    version,
    about = "Read-only local MCP server for Spiffy Search"
)]
struct Cli {
    #[arg(long, hide = true)]
    endpoint: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let endpoint = cli
        .endpoint
        .unwrap_or_else(spiffy_search::config::ipc_endpoint_path);
    spiffy_search::mcp::serve_stdio(&endpoint).await
}
