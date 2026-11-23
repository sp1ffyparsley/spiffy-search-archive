#![deny(unsafe_op_in_unsafe_fn)]

pub mod access;
pub mod agent;
pub mod browser;
pub mod catalog;
pub mod cli;
pub mod config;
pub mod content;
pub mod content_extractor;
pub mod dialog;
pub mod engine;
pub mod error;
pub mod file_ops;
pub mod index;
pub mod ipc;
pub mod local_api;
pub mod logging;
pub mod mcp;
pub mod model;
pub mod platform;
pub mod protocol;
pub mod query;
pub mod ranking;
pub mod remote;
pub mod scanner;
pub mod shelf;
pub mod watcher;
pub mod workspace_catalog;

pub use error::{SearchError, SearchResult};
