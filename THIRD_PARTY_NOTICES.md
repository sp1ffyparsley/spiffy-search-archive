# Third-Party Notices

Exact resolved versions and checksums are recorded in `Cargo.lock`. Spiffy
Search does not vendor or modify third-party source; each dependency remains
governed by its own license.

| Component | License | Use |
| --- | --- | --- |
| Tantivy | MIT | Persistent filename, browser, and content indexes |
| Nucleo Matcher | MPL-2.0 | Deterministic fuzzy reranking |
| notify | CC0-1.0 | Windows and macOS filesystem event adapter |
| rusqlite / SQLite | MIT / public domain | Sparse catalog, settings, and operation receipts |
| Tokio, Axum, and Tower HTTP | MIT | Bounded local IPC and optional loopback HTTP API |
| RMCP | Apache-2.0 | Read-only local MCP transport |
| lopdf | MIT | Bounded PDF text extraction |
| BLAKE3 | CC0-1.0 OR Apache-2.0 | File identity, cache, and copy verification |
| zip | MIT | Bounded OpenXML, OpenDocument, and EPUB extraction |
| trash | MIT | Native Recycle Bin and Trash integration |
| clap | MIT OR Apache-2.0 | Command-line parsing |
| serde / serde_json | MIT OR Apache-2.0 | Versioned local protocol and state serialization |
| Windows crate | MIT OR Apache-2.0 | Native file identity and dialog adapters |
| objc2 AppKit/Foundation | MIT, Apache-2.0, or Zlib | macOS workspace and Accessibility adapters |
| Spiffy Shared | MIT | Product paths, stable identity, IPC, and cross-product contracts |

The full transitive graph is validated by `cargo deny check`; RustSec advisories
are checked by `cargo audit`. Release packages include this notice, the project
MIT license, the exact source revision, and hashes for every payload file.


The bundled `vendor/spiffy-shared-workspace/crates/spiffy-shared` source is original Spiffy Shared code under the MIT license; see `vendor/spiffy-shared-workspace/LICENSE`.
