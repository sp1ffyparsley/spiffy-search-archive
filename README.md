# Spiffy Search (Archive)

> **Archived, read-only source snapshot.** This project is no longer under active development. The source is provided for reference; it does not include machine settings, credentials, personal indexes, or historical private commits.

# Spiffy Search

Spiffy Search is a local-first Windows and macOS file search product. Its
resident Rust agent owns selected-root indexing, event-driven reconciliation,
optional full-text extraction, deterministic structured queries, favorites,
pins, aliases, explicitly enabled local browser-history search, and
authenticated local IPC. Search has no cloud or model dependency.

The current implementation remains backend-first. Native launcher/theme UI is a
separate production surface; no placeholder UI is included.

Runtime data:

- Windows: `%LOCALAPPDATA%\SpiffySearch`
- macOS: `~/Library/Application Support/SpiffySearch`

Implemented backend:

- Persistent Tantivy filename index with atomic root replacement and incremental updates.
- Separate optional Tantivy content index, disabled by default so filename search stays lightweight.
- Isolated, timeout-bounded content worker for text, source, structured data, PDF, RTF, OpenXML, OpenDocument, and EPUB inputs.
- PDF parsing uses maintained lopdf 0.44 with bounded stream decompression and page-by-page extraction.
- Digest-aware extraction cache, bounded snippets/highlights, watcher-driven updates/deletes, and bounded background retries.
- Successful full scans prune stale content records; cancelled or incomplete scans retain the prior snapshot for retry.
- Bounded parallel scanner with stable file identities, exclusions, cancellation, and no symlink traversal.
- Native `ReadDirectoryChangesW`/FSEvents watcher through `notify`, including rename handling, overflow reconciliation, and non-fatal startup when a configured root is temporarily unavailable.
- Sparse WAL-backed SQLite state for roots, favorites, pins, aliases, usage, saved searches, and operation receipts.
- Structured query parser, deterministic Nucleo reranking, current-folder filtering, and Windows extended-path normalization.
- Loopback-only token-authenticated IPC, singleton agent lock, background reindex jobs, diagnostics, and file logs.
- Optional loopback-only HTTP API with an independent bearer token, owner-only endpoint file, rate/body/result/time limits, and no mutation routes; disabled by default.
- Local stdio MCP server with seven read-only tools backed by authenticated Search IPC and no arbitrary-path access.
- Authenticated Cross Shelf search service for explicitly remote-searchable roots, with requester-bound result leases, relative-path-only wire metadata, and exact selected-result resolution.
- Confirmation-bound copy, move, rename, and Trash operations with fail/keep-both conflict policies and durable status receipts.
- Verified staged copies, native no-replace renames, cancellable progress, restart reconciliation, idempotent operation IDs, and identity-checked undo.
- Search reader snapshots remain available while the writer performs a long scan.
- Opt-in Chrome, Edge, Firefox, and macOS Safari history adapters with read-only SQLite online snapshots, bounded retention/counts, per-provider fail-closed replacement, scheduled refresh, cancellation, and complete cached-metadata clearing.
- Browser results share the filename index under isolated synthetic roots, appear only in `browser:` mode, and can match page titles, domains, and URL paths without logging queries or URLs.
- Optional typed workspace-catalog projection turns existing Spiffy launchers into deterministic `Application` records, including producer-owned aliases, without importing sibling runtimes or sharing their databases.
- Separate `spiffy-file-dialog-bridge` process for bounded Open, Save, folder, and multi-file preparation without invoking the host dialog's confirmation action.
- Windows adapter for modern `IFileDialog` and practical legacy `GetOpenFileNameW` dialogs using filtered UI Automation plus common-dialog fallbacks; no injection, elevation, clipboard mutation, or keylogging.
- macOS AXUIElement/AXObserver adapter with NSWorkspace context, Finder folder discovery, explicit Accessibility diagnostics, stable panel identities, and no Accessibility dependency in the Search agent.

No filesystem root or browser source is indexed until it is explicitly enabled.

Saved Shelf search is available while Spiffy Shelf is running in normal mode:

```powershell
spiffy-searchctl --json shelf search "storyboard" --limit 25
spiffy-searchctl --json shelf search "storyboard" --limit 25 --cursor <returned-next-cursor>
spiffy-searchctl --json search "shelf: storyboard"
spiffy-searchctl --json search "shelf: storyboard" --shelf-cursor <returned-next-cursor>
spiffy-searchctl --json shelf reveal --shelf-id <returned-uuid> --shelf-stamp <returned-hash> --item-id <returned-item-uuid> --item-revision <returned-revision>
```

The direct `shelf` commands do not start the Search agent. They use Shelf's
separate private Search capability and return bounded saved Standard shelf names
and item titles, never item contents or local paths. The agent's `shelf:` mode
returns `data.results`, `generation`, `stage`, `scanned`, `has_more`,
`next_cursor` and `complete`; filesystem modes retain their existing `data.hits`
shape. Continue with the same query/generation and returned cursor until
`complete:true`, including pages with `stage:scanning` and no results yet.
The native Shelf owner applies shared all-required-word and quoted-phrase
matching over complete names/titles. Quoted phrases are forwarded unchanged.
Filesystem filters/current-folder context are unavailable in this mode. For a shelf-only
result, omit both item options. Reveal succeeds only after Shelf selects and
acknowledges the exact current result; changed/private/expired results fail.
This does not open a file, modify a shelf, or copy saved content into Search's
indexes. The existing FileDialog bridge below remains responsible for native
dialog preparation.

```powershell
cargo run --bin spiffy-search-agent
cargo run --bin spiffy-searchctl -- --json build-info
cargo run --bin spiffy-searchctl -- status
cargo run --bin spiffy-searchctl -- root add "C:\Media" --exclude "Cache/**"
cargo run --bin spiffy-searchctl -- search "hero clip ext:mov"
cargo run --bin spiffy-searchctl -- content status
cargo run --bin spiffy-searchctl -- content index
cargo run --bin spiffy-searchctl -- search "content: exact phrase"
cargo run --bin spiffy-searchctl -- browser status
cargo run --bin spiffy-searchctl -- browser refresh
cargo run --bin spiffy-searchctl -- search "browser:project reference"
cargo run --bin spiffy-searchctl -- browser clear
cargo run --bin spiffy-searchctl -- workspace connect "..\workspace_catalog.json"
cargo run --bin spiffy-searchctl -- workspace status
cargo run --bin spiffy-searchctl -- search "app: Spiffy Video Editor"
cargo run --bin spiffy-searchctl -- search "Visual Clipboard"
cargo run --bin spiffy-searchctl -- metadata "stable-key-from-search-result"
cargo run --bin spiffy-searchctl -- preview-text "stable-key-from-search-result" --max-chars 4000
cargo run --bin spiffy-searchctl -- favorites --limit 25
$operationId = [guid]::NewGuid().ToString()
$preview = cargo run --quiet --bin spiffy-searchctl -- --json file preview copy --source "C:\Media\Hero.mov" --destination "C:\Archive" --operation-id $operationId | ConvertFrom-Json
cargo run --quiet --bin spiffy-searchctl -- --json file run copy --source "C:\Media\Hero.mov" --destination "C:\Archive" --operation-id $operationId --confirmation-token $preview.data.confirmation_token
cargo run --quiet --bin spiffy-searchctl -- --json file status $operationId
cargo run --quiet --bin spiffy-searchctl -- --json file cancel $operationId
cargo run --quiet --bin spiffy-searchctl -- --json file undo $operationId
cargo run --bin spiffy-searchctl -- doctor
cargo run --bin spiffy-searchctl -- stop
cargo run --bin spiffy-file-dialog-bridge -- --json inspect
cargo run --bin spiffy-file-dialog-bridge -- --json open-folders
cargo run --bin spiffy-file-dialog-bridge -- --json doctor
```

Set `content.enabled` to `true` in `search-config.json` while the agent is
stopped before using content commands. The content worker never runs when the
feature is disabled. `content index` reconciles every configured root;
individual paths may be supplied for a targeted refresh.

Browser history is also disabled by default. Stop the agent, explicitly set
only the desired provider booleans under `browsers` in `search-config.json`,
then restart it. Refreshes use the configured interval, retention window, and
per-provider result cap. Browser databases are opened read-only and copied with
SQLite's online backup API into operation-owned temporary directories; source
database handles and snapshots are closed after each profile. Provider failure
retains that provider's last successful index partition. `browser clear`
removes every browser partition and any owned temporary snapshot cache. It does
not modify browser databases or include private-session history that browsers
do not persist.

`workspace connect <catalog>` validates a workspace-owned catalog and persists
its absolute path in Search configuration. On the next agent start, declared
launch targets for the current platform are projected into the filename index as
`Application` records. Labels and aliases participate in candidate retrieval and
ranking; canonical paths remain the existing producer-owned launcher files.
Missing, escaping, absolute, or symlinked launcher paths fail validation. Search
does not import workspace runtime code or watch sibling application databases.

The optional local API is configured under `local_api` in `search-config.json`.
It always binds `127.0.0.1`, uses a token separate from IPC, and writes the
address/token to the owner-only `local-api-endpoint.json` under the Search data
directory. It exposes only status, scoped file/folder/application/content search, exact
stable-key metadata, bounded indexed preview text, and bounded favorites under
`/v1`. Requests have a 15-second timeout, a configurable body/rate bound, and a
hard 100-result cap. There are no write, open, or arbitrary-path routes.
`enabled` and `allow_preview_text` both default to false; the latter gates
preview text through HTTP, MCP, and CLI. Stop the agent before changing these
settings and restart it afterward. Never log or copy the endpoint token into a
project configuration.

`spiffy-search-mcp` is a stdio MCP server for local AI clients. Start it as the
MCP command with no arguments while the Search agent is running. It discovers
the private IPC endpoint and exposes `search_files`, `search_folders`,
`search_applications`, `search_content`, `get_file_metadata`, `get_preview_text`, and
`list_favorites`. It has no mutation tools and accepts stable keys rather than
arbitrary filesystem paths.

The package produces `spiffy-search-agent`, `spiffy-searchctl`,
`spiffy-search-content-worker`, `spiffy-search-mcp`, and
`spiffy-file-dialog-bridge`. The CLI's `start` command requires the agent and
content-worker binaries beside the CLI. The dialog bridge is an on-demand
process, never a second resident agent.

Dialog actions require the exact `dialog_id` returned by `inspect`, canonical
existing targets, and an unchanged supported dialog. Selecting a folder or
preparing files leaves the dialog open for the host application's own validation.
Windows supports same-folder multi-file preparation. The current macOS AX owner
prepares one file at a time; physical-Mac multi-selection remains an open product
gap. Save navigation captures and restores the typed filename.
macOS Accessibility permission is requested only by `doctor
--request-permission`; ordinary indexing and search do not require it.

File mutation is a two-step contract. `file preview` returns the operation ID,
resolved targets, conflicts, and a confirmation token. `file run` accepts only
that same request and token; source or destination changes invalidate it before
mutation. Existing destinations are never overwritten. Copy output is hashed
before atomic finalization, operation-owned staging files are never indexed,
and completed move/rename/Trash operations can be undone from their durable
receipts. On Windows, Trash undo restores the exact recorded Recycle Bin item
and filename. On macOS, send-to-Trash is supported but undo requires Finder's
Put Back command.

Remote-device search is served only through the authenticated local Search IPC
contract consumed by Cross Shelf. A root must be added with
`--remote-searchable`; otherwise it cannot appear remotely. Queries are bounded
and root-scoped, wire results contain no absolute local path, leases are bound
to the requesting peer and expire, and a selected result is revalidated by
stable identity before Cross Shelf begins its existing verified transfer. Search
does not open a LAN listener or accept remote mutation commands.

## Release Packages

Windows:

```powershell
.\scripts\package-windows.ps1
```

This creates `artifacts\x86_64-pc-windows-msvc\SpiffySearch-x86_64-pc-windows-msvc-portable.zip`
and `SHA256SUMS.txt`. The ZIP carries all five binaries, per-user install and
uninstall scripts, licenses/notices, and `PACKAGE_MANIFEST.txt`. The installer
validates every manifest payload hash before changing its destination. It
installs under `%LOCALAPPDATA%\Programs\SpiffySearch` by default, registers only
the current user's startup entry, and preserves runtime data on normal removal.

macOS:

```bash
./scripts/package-macos.sh aarch64-apple-darwin
./scripts/package-macos.sh x86_64-apple-darwin
```

The macOS package is a per-user backend ZIP with the same five-binary and
manifest contract plus a LaunchAgent installer. Packaging accepts only Apple
Darwin targets and binds a maintained build to the current Search plus Spiffy
Shared source fingerprint, so `--skip-build` cannot package stale binaries. See
`docs/MAC_HANDOFF.md` and `docs/MAC_TEST_MATRIX.md`. No `.app`, DMG, physical Mac
package, signature, or notarization is claimed without Mac-host evidence.

Backend verification:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --test dialog_bridge_windows --all-features -- --ignored --test-threads=1
cargo build --release --bins
cargo audit
cargo deny check --hide-inclusion-graph
```

Windows proof currently includes 100 library tests, one real child-process worker
integration test, two bridge process-contract tests, strict all-feature Clippy,
an optimized five-binary build,
RustSec audit, explicit cargo-deny advisory/license/source policy, native watcher
updates/deletes, authenticated IPC, and healthy release Doctor runs for both
isolated content-enabled and normal content-disabled profiles. A disposable
release corpus indexed in 191-219 ms and representative content queries
completed in 0.648-0.853 ms on this host. A separate release smoke proved
keep-both copy, move/undo, rename/undo, conflict refusal, stale-preview refusal,
exact Windows Recycle Bin restore, receipt persistence across restart, and
mid-copy cancellation of an 8 GiB sparse fixture with no destination or staging
residue. Browser tests use synthetic Chrome, Firefox, and Safari databases to
prove online snapshot extraction, credential/fragment stripping, mode
isolation, domain/path ranking, provider deduplication, cancellation, owned
cache cleanup, disabled-state behavior, and filename-record preservation. No
personal browser history was enabled or read for these tests. The protocol 1.3
release agent was then installed over protocol 1.2: its existing config was
atomically normalized with the new bounded defaults, every provider remained
disabled, browser status reported zero records, the existing 2,021 filename
records remained available, and Doctor reported healthy schema-2 state with no
pending reconciliation. Protocol 1.4 then added independent-token HTTP access,
official-SDK MCP transport, exact stable-key metadata/preview, and bounded
favorites. Real debug and optimized loopback HTTP tests verified bounded request handling, fail-closed preview, error redaction, separation of authorization material, and endpoint cleanup. The live optimized 1.4 agent preserved all
2,021 filename records, reported a healthy schema-2 Doctor result, exposed no
HTTP endpoint while disabled, and passed real file-search, metadata, favorites,
and preview-denial checks.

The one allowed RustSec item is `RUSTSEC-2026-0253` in Tantivy 0.26.1's
transitive `lru 0.16.4`. Tantivy uses `LruCache<usize, OwnedBytes>` through
`get`/`put`, while the advisory requires `pop` plus a key whose `Drop` panics
during unwind, so that path is unreachable in Search. Tantivy 0.26.1 remains
the latest stable release; unreleased upstream 0.27.0 has already moved to fixed
`lru 0.18.2`. The release stays on stable Tantivy instead of a Git dependency.

Protocol 1.5 adds the Spiffy Shared remote-search/service contract used by Cross
Shelf. Tests prove opt-in root scope, requester-bound expiring leases, path-safe
wire results, stable selected-file resolution, authenticated service IPC, and a
real encrypted two-agent search plus verified lazy fetch. The compiled local
`build-info` command now drives release metadata without requiring an agent.
The current Windows package passed exact ZIP/hash validation, an isolated
11-file install/build-info/uninstall cycle with startup registration unchanged,
and tampered-payload rejection before destination mutation.

The dialog adapter also passed five serialized real Windows fixtures: modern
Open, modern Save with filename preservation, folder chooser, multi-file Open,
and legacy `GetOpenFileNameW`. The debug suite completed all five in 8.77
seconds and never invoked confirmation. Optimized bridge CLI tests and Doctor
passed; an optimized interactive rerun correctly failed closed when another
application reclaimed foreground focus.

Strict source-level Clippy passes for both `aarch64-apple-darwin` and
`x86_64-apple-darwin` using linked-SQLite metadata and BLAKE3's pure Rust check
path, including the real AXUIElement/AXObserver adapter. This is not Apple link
or runtime proof. Final FSEvents, Accessibility, panel, idle-resource, signing,
and package validation must run on a Mac host.


## Standalone GitHub source snapshot

This repository includes the versioned MIT-licensed `spiffy-shared` Rust crate under `vendor/spiffy-shared-workspace`, so a fresh clone does not require a sibling `Spiffy Shared` directory. The core application still requires a supported Rust toolchain and platform runtime. Generated binaries, caches, histories, and local data were deliberately excluded. This archived source snapshot is not the installed Spiffy Shelf or Listary application.
