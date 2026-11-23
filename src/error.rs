use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("query error: {0}")]
    Query(String),
    #[error("index error: {0}")]
    Index(String),
    #[error("state error: {0}")]
    State(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("access denied: {0}")]
    Access(String),
    #[error("content extraction error: {0}")]
    Content(String),
    #[error("browser history error: {0}")]
    Browser(String),
    #[error("file operation error: {0}")]
    FileOperation(String),
    #[error("I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Tantivy(#[from] tantivy::TantivyError),
}

pub type SearchResult<T> = Result<T, SearchError>;

pub fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> SearchError {
    SearchError::Io {
        path: path.into(),
        source,
    }
}
