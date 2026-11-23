use crate::access::{bounded_result_limit, scoped_query, AccessSearchScope, MAX_ACCESS_RESULTS};
use crate::ipc;
use crate::protocol::{AgentCommand, AgentReply};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{schemars, tool, tool_handler, tool_router, ServerHandler};
use serde::Deserialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct SearchMcpServer {
    endpoint_path: PathBuf,
    generation: Arc<AtomicU64>,
}

impl SearchMcpServer {
    pub fn new(endpoint_path: PathBuf) -> Self {
        Self {
            endpoint_path,
            generation: Arc::new(AtomicU64::new(1)),
        }
    }

    async fn search(&self, scope: AccessSearchScope, request: SearchParameters) -> CallToolResult {
        let query = match scoped_query(scope, &request.query) {
            Ok(query) => query,
            Err(error) => return tool_error("invalid_query", error.to_string()),
        };
        let limit = bounded_result_limit(request.limit, MAX_ACCESS_RESULTS);
        self.command(AgentCommand::Search {
            query,
            generation: self.generation.fetch_add(1, Ordering::Relaxed),
            limit: Some(limit),
            current_folder: None,
        })
        .await
    }

    async fn command(&self, command: AgentCommand) -> CallToolResult {
        match ipc::send_command_at(&self.endpoint_path, command).await {
            Ok(reply) => result_from_reply(reply),
            Err(error) => tool_error("agent_unavailable", error.to_string()),
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchParameters {
    #[serde(default)]
    #[schemars(description = "Local search text and supported structured filters")]
    query: String,
    #[schemars(description = "Maximum results; values are capped at 100")]
    limit: Option<u16>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct StableKeyParameters {
    #[schemars(description = "Exact stable_key returned by a Spiffy Search result")]
    stable_key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PreviewParameters {
    #[schemars(description = "Exact stable_key returned by a Spiffy Search result")]
    stable_key: String,
    #[schemars(description = "Maximum preview characters; values are capped at 16000")]
    max_chars: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct FavoritesParameters {
    #[schemars(description = "Maximum favorites; values are capped at 100")]
    limit: Option<u16>,
}

#[tool_router]
impl SearchMcpServer {
    #[tool(description = "Search only indexed local files by filename and structured filters")]
    async fn search_files(
        &self,
        Parameters(request): Parameters<SearchParameters>,
    ) -> CallToolResult {
        self.search(AccessSearchScope::Files, request).await
    }

    #[tool(description = "Search only indexed local folders by name and structured filters")]
    async fn search_folders(
        &self,
        Parameters(request): Parameters<SearchParameters>,
    ) -> CallToolResult {
        self.search(AccessSearchScope::Folders, request).await
    }

    #[tool(description = "Search only indexed local applications and workspace launch targets")]
    async fn search_applications(
        &self,
        Parameters(request): Parameters<SearchParameters>,
    ) -> CallToolResult {
        self.search(AccessSearchScope::Applications, request).await
    }

    #[tool(description = "Search the optional local content index; requires a nonempty query")]
    async fn search_content(
        &self,
        Parameters(request): Parameters<SearchParameters>,
    ) -> CallToolResult {
        self.search(AccessSearchScope::Content, request).await
    }

    #[tool(
        description = "Get metadata for an exact indexed stable key; arbitrary paths are not accepted"
    )]
    async fn get_file_metadata(
        &self,
        Parameters(request): Parameters<StableKeyParameters>,
    ) -> CallToolResult {
        self.command(AgentCommand::GetItemMetadata {
            stable_key: request.stable_key,
        })
        .await
    }

    #[tool(
        description = "Get bounded text already stored in the content index; disabled unless explicitly permitted in Search configuration"
    )]
    async fn get_preview_text(
        &self,
        Parameters(request): Parameters<PreviewParameters>,
    ) -> CallToolResult {
        self.command(AgentCommand::GetPreviewText {
            stable_key: request.stable_key,
            max_chars: request.max_chars,
        })
        .await
    }

    #[tool(description = "List bounded local Search favorites without modifying them")]
    async fn list_favorites(
        &self,
        Parameters(request): Parameters<FavoritesParameters>,
    ) -> CallToolResult {
        self.command(AgentCommand::ListFavorites {
            limit: Some(bounded_result_limit(request.limit, MAX_ACCESS_RESULTS)),
        })
        .await
    }
}

#[tool_handler(
    name = "spiffy-search",
    version = "0.1.0",
    instructions = "Read-only access to the user's explicitly indexed local Spiffy Search data. No mutation or arbitrary-path tools are exposed."
)]
impl ServerHandler for SearchMcpServer {}

pub async fn serve_stdio(endpoint_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::{transport::stdio, ServiceExt};

    let service = SearchMcpServer::new(endpoint_path.to_path_buf())
        .serve(stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}

fn result_from_reply(reply: AgentReply) -> CallToolResult {
    if reply.ok {
        CallToolResult::structured(reply.data.unwrap_or(serde_json::Value::Null))
    } else {
        tool_error(&reply.code, reply.message)
    }
}

fn tool_error(code: &str, message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "code": code,
        "message": message.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcServer;
    use rmcp::model::CallToolRequestParams;
    use rmcp::ServiceExt;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn official_mcp_transport_lists_tools_and_delegates_over_authenticated_ipc() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint_path = temp.path().join("ipc-endpoint.json");
        let ipc_server = Arc::new(IpcServer::bind(endpoint_path.clone()).await.unwrap());
        let task_server = Arc::clone(&ipc_server);
        let ipc_task = tokio::spawn(async move {
            let (mut stream, _) = task_server.accept().await.unwrap();
            let request = task_server.read_authenticated(&mut stream).await.unwrap();
            assert!(matches!(
                request.command,
                crate::protocol::SearchIpcCommand::Agent(AgentCommand::Search {
                    ref query,
                    ..
                }) if query == "file: hero"
            ));
            task_server
                .write_reply(
                    &mut stream,
                    &AgentReply::success(
                        "Search complete",
                        json!({
                            "generation": 1,
                            "index_generation": 2,
                            "elapsed_micros": 3,
                            "total_candidates": 0,
                            "category_counts": {},
                            "hits": [],
                        }),
                    ),
                )
                .await
                .unwrap();
        });

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mcp_server = SearchMcpServer::new(endpoint_path);
        let server_task = tokio::spawn(async move {
            let service = mcp_server.serve(server_io).await.unwrap();
            service.waiting().await.unwrap();
        });
        let client = ().serve(client_io).await.unwrap();
        let tools = client.list_all_tools().await.unwrap();
        assert_eq!(tools.len(), 7);
        assert!(tools.iter().any(|tool| tool.name == "search_files"));
        assert!(tools.iter().any(|tool| tool.name == "search_applications"));
        assert!(!tools.iter().any(|tool| tool.name.contains("delete")));
        let mut arguments = serde_json::Map::new();
        arguments.insert("query".to_string(), json!("hero"));
        arguments.insert("limit".to_string(), json!(10));
        let result = client
            .call_tool(CallToolRequestParams::new("search_files").with_arguments(arguments))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.structured_content.unwrap()["hits"], json!([]));
        client.cancel().await.unwrap();
        server_task.await.unwrap();
        ipc_task.await.unwrap();
    }
}
