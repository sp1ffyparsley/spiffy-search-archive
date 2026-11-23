# Spiffy Search AI Master Prompt

October 9 source-current standalone optional Search0.1 release: incumbent scripts/package-windows.ps1 published artifacts/x86_64-pc-windows-msvc/SpiffySearch-x86_64-pc-windows-msvc-portable.zip SHA **149DF3E9A16F62D39105E69CADF29CBCCA70F33E001932F6ECE338A3175A3D4E**, 10/10 manifest/loose-file exact member hashes, fingerprint **01D17B449A279785CA9765CD9344AE80CAD92E99866E8F4A8C04E01CA61FB8D2**, current protected Windows token-file endpoint producer, protocol1.5. The original process-session handle became unavailable before its final exit code was recorded; published archive and independent hashes establish output bytes, not an observed script exit0. No Search service startup, new index, app install or Cross Shelf activation. Cross-owner paired receipt ../Spiffy Shelf/artifacts/runtime-verification/clipboard-queue-paired-secure-release-20261009-01/receipt.json SHA **A0BDFD439887F1F9155532D650ECA12F82F7C6E9AED7C0594F7DD3853633FADA**; installed Shelf/Clipboard and real physical Mac acceptance remain open.

October 9 Cross Shelf local Search IPC token hardening (source/dev-binary only): `src/ipc.rs` now protects its existing private token-bearing `ipc-endpoint.json` and sibling lock with an explicit Windows single-current-user protected DACL before the original atomic endpoint publish. This corrects a Windows inherited-ACL gap detected with an actual workstation parent ACL that grants another read-capable group, without modifying any search indexes/watchers/profiles. An incumbent `src/shelf.rs` ACL validator supplies the Windows test assertion (visibility scoped `pub(crate)` only). Consumer `../Spiffy Shelf/cross-shelf-agent/src/search_client.rs` uses the preexisting Cross Shelf bounded 16-KiB regular-file/no-reparse/private-ACL reader; preserves Search 1.5. Producer private ACL failure-first RED then **5/5 IPC tests PASS**, Cross Shelf **5/5 IPC + 4/4 Search client PASS** including World DACL negative and authenticated localhost request. Rust formatting and Windows debug Search agent+control builds PASS. Search source SHA `ipc.rs` **BEBBBBD2DB2EC81713B7069C98939D38D71E865C24EBEAC50898B2EF5C0741C2**, `shelf.rs` **E1CAC7A4FBA589B183A630B73DC22F782C787BDA7284968E5504F2F35E49BC64**; Search debug EXEs **120B52C09302...** / **5C3AD9ABBC78...**. No production Search agent or Cross Shelf process started or installed, and no native cross-device or physical Mac acceptance claimed. The existing Shelf 0.2.1 uninstalled package predates this source fix; the canonical Shelf PROGRESS contains complete scope and rollout boundary.

Updated: 2026-09-08

September 9 package qualification found and fixed a real Windows startup hang:
the CLI exited, but its long-lived agent inherited the caller's original pipe
handles even with `Stdio::null`. Captured PowerShell/.NET startup therefore
waited for agent shutdown before observing EOF. The Windows launch now uses
the already maintained Win32 dependency with the exact sibling executable,
no shell, no console and no inherited handles. Normal owner status/stop and
non-Windows launch policy remain intact. The actual isolated CLI lifecycle
regression passes with stdout closed while the background agent stays healthy;
no live indexes or configured roots are used in this test.

Current final package/installed-profile proof is recorded in the existing
`../_state/spiffy-shelf-r02.json`. Earlier package assembly success does not
override the retained failed startup observations. Physical file dialogs and
macOS remain separate unrun platform gates.

## Ownership

Spiffy Search owns the local filename/content indexes, selected-root scanners,
filesystem event reconciliation, deterministic query and ranking pipeline,
favorites/pins/aliases/usage settings, local authenticated search APIs, browser
history adapters, file-operation receipts, and file-dialog bridge adapters.

It reuses Spiffy Shared for product paths, stable file identity, bounded
framing, tokens, and cross-product contracts. It reads clipboard history only
through Cross Shelf's explicit API and never creates another recorder. It does
not own Shelf storage or Cross Shelf transport.

## Saved Shelf integration

`src/shelf.rs` consumes the separately authenticated saved-Shelf metadata
capability on Shelf's existing ingress listener. It reads only the fixed
`SpiffyShelf/ipc/search-endpoint-v1.json` discovery, validates the opened file's
actual owner-only ACL/mode (and rejects reparse/symlink files), loopback endpoint,
protocol/session/freshness, bounded framing, and exact reply identity. It never
reads Capture credentials. Same-user capability authentication does not claim
executable signing or remote access authority. No new listener, index, scanner,
database, body cache, or global disk search is added to Shelf.

`spiffy-searchctl shelf search [shared-title-query] --limit 50` works while
Shelf is running without starting the Search agent. Existing agent `search
"shelf: title"` delegates to the same adapter and returns `ShelfSearchPage` in
AgentReply.data rather than fabricated filesystem SearchHits. This mode supports
shared all-required-word and quoted-phrase name/title matching; parsed filesystem filters/current-folder scope
are rejected. File-only engine entry points reject Shelf mode explicitly.
HTTP/MCP and Cross Shelf remote root scopes keep their existing scope guards.

`shelf reveal --shelf-id UUID --shelf-stamp HASH [--item-id UUID
--item-revision N]` selects the exact current saved Standard shelf/item in Shelf.
The owner checks its metadata hash/item revision/security, waits for the actual
main renderer ACK, then rechecks before returning applied:true. An unavailable,
expired, changed, private, Secure Temp, or unacknowledged result fails honestly.
Results contain bounded names/titles, kind, missing state and stable references;
no payload, preview, URL or local-path fields. Queries are <=2048 UTF-8 bytes,
pages <=100 with actual has_more; query/navigation deadlines are 2/4 seconds.
Names are metadata and may themselves be user-authored text. Logs contain only
machine actions, elapsed time, and success state, never queries/tokens/titles.

Saved-Shelf capability protocol 1.1 adds owner-bound opaque continuation:
`next_cursor`, `stage`, `scanned` and `complete`. The standalone CLI accepts
`shelf search --cursor`; the existing agent route accepts `search "shelf: ..."
--shelf-cursor`, translated to the explicit `ShelfSearchPage` command. Older
agents reject this new command rather than silently ignoring a cursor. Query,
generation, permissions, owner revision, SQLite data version and owner cache
expiry remain bound by Shelf; the cursor carries no names or payloads. The
fixed discovery path is retained, with exact capability version checks.
Scanning and result pages both continue until `complete:true`; 100 is a page
bound, not an implicit searchable corpus limit. The title query's quoted phrase
bytes and exclusions survive routing to the maintained common core. Shelf
continues to reject file/body/path scope expansion through this capability.

The maintained Windows packager now binds all packaged binaries to a stable
Search/Shared source fingerprint. A changed source snapshot rejects the build;
`SkipBuild` requires a matching previously qualified source receipt. Current
package hashes and activation belong to the generated manifest, not older
historical proof below. Physical macOS package/runtime is unrun on this host.

This connected-workflow addition supports R02 owner reuse/reference/receipt
principles (SS-001/088/089); it is not a newly invented R02 Search requirement.
D13 and SS-021 remain local captured/shelved search inside Shelf. Existing
`spiffy-file-dialog-bridge` remains the sole FileDialog adapter. Windows synthetic
ACL/loopback/store/ACK tests run without live owner data. macOS code is present
but SDK/runtime acceptance remains unavailable on this Windows host.

## Active Scope

The current user direction freezes frontend/UI work. Prioritize production
backend behavior, tests, performance, Windows/macOS adapters, packaging, and
integration. Do not add placeholder UI, fake platform modules, cloud services,
telemetry, resident Python, Elasticsearch, or Everything as a requirement.

## Architecture

One Rust package produces `spiffy-search-agent`, `spiffy-searchctl`, the real
`spiffy-search-content-worker`, the read-only `spiffy-search-mcp` stdio server,
and the on-demand `spiffy-file-dialog-bridge`. Filename and optional content indexes remain
separate. Content indexing is disabled by default and runs extraction in a
bounded child process with timeout/cancellation, signature checks, archive
limits, digest caching, and a fixed worker pool. PDF extraction uses maintained
lopdf 0.44 with load-time stream limits and page-by-page bounded text extraction;
do not restore the advisory-bearing `pdf-extract -> lopdf 0.42 -> ttf-parser`
chain. Top-level content-job failures are surfaced through status and retried
after 1, 5, and 30 seconds before stopping. SQLite stores sparse settings and
receipts, never a duplicate searchable file catalog. Watchers are event-driven
and bounded; overflow, subtree changes, or sleep gaps trigger reconciliation.
Full scans prune stale content records only after complete traversal. Cancelled
or metadata-incomplete scans retain the prior snapshot, and root mutations,
filename replacement, and content jobs use one scheduling gate so they cannot
race. Systemic worker failures enter bounded job retry; transient per-file I/O
and timeout failures are not cached as permanent results.

The implemented read path uses a cloneable Tantivy reader plus a separate WAL
SQLite connection, so committed searches continue while the single writer scans
a root. Full scans stream bounded batches and roll back on cancellation or index
failure. The native watcher uses `notify` (`ReadDirectoryChangesW` on Windows,
FSEvents on macOS) and never blocks its callback when the channel is full.

Local control uses an ephemeral loopback TCP port, a 256-bit bearer token in the
private product data directory, bounded length-prefixed JSON frames, request
freshness checks, and an exclusive singleton lock. Search queries and tokens are
redacted from debug output. The additive Search IPC protocol is version 1.5.
Machine-mode CLI commands emit one parseable JSON reply, including automatic
root indexing, exact-key metadata/preview, bounded favorites, and terminal
browser-refresh/file-operation status.

Protocol 1.5 adds one authenticated local search-service command for Cross
Shelf. Only roots explicitly marked `remote_searchable` can participate. Remote
queries are bounded and requester-scoped; replies expose relative display
metadata rather than absolute paths. Result leases expire and are bound to the
requesting peer, and exact selected-file resolution revalidates root ownership,
stable identity, size, and digest before Cross Shelf uses its existing transfer
owner. Search opens no LAN listener and accepts no remote mutation action.

The optional HTTP API is implemented and disabled by default. It binds only
`127.0.0.1`, generates a bearer token independent from IPC, atomically writes an
owner-only endpoint file, removes only its owned stale endpoint, and applies
authentication before fixed-window rate limiting. Axum enforces a 15-second
timeout and configurable request-body bound; every search is scope-locked and
capped at 100 results. Routes expose only status, file/folder/content search,
exact stable-key metadata, bounded text already stored in the content index, and
bounded favorites. No mutation, shell-open, network bind, or arbitrary-path
route exists. Internal failures are logged locally but returned generically.
Preview text requires the explicit `local_api.allow_preview_text` permission,
which also gates CLI and MCP preview access.

`spiffy-search-mcp` uses the official Rust MCP SDK over stdio and delegates to
the existing authenticated IPC owner. Its six tools are `search_files`,
`search_folders`, `search_content`, `get_file_metadata`, `get_preview_text`, and
`list_favorites`. Query mode/kind escape is rejected, result and preview sizes
are bounded, stable-key tools do not accept paths, and no mutation tool is
registered. Do not add a second Search engine or token store for MCP.

The file-dialog bridge is a separate on-demand process and never joins the
resident indexer. Its contract is inspect first, then act against the exact
bounded dialog ID with canonical existing targets. It never invokes Open, Save,
Choose, or another confirmation control. Windows supports modern `IFileDialog`,
legacy `GetOpenFileNameW`, folder, and multi-file preparation through filtered
UI Automation plus common-dialog fallbacks. macOS uses AXUIElement, AXObserver,
NSWorkspace, stable panel identities, the standard Go to Folder path, and
Finder window context. Only this bridge requires macOS Accessibility. Keep
adapter profiles narrow and do not add process injection, elevation, broad
keyboard interception, clipboard path injection, or a second file index.

Browser history is explicit opt-in and disabled for every provider by default.
The Chrome, Edge, Firefox, and macOS Safari adapters discover only persisted
profile databases, open each source read-only, and use SQLite online backup into
an owner-marked temporary cache before bounded queries. Refreshes enforce
retention and per-provider entry limits, deduplicate URLs, strip credentials and
fragments, close profile handles, and never log URLs or search terms. Each
provider owns a deterministic synthetic root in the existing filename Tantivy
index. Successful refresh replaces only that provider partition; a source
failure retains its prior partition, and disabling a provider clears it on the
next successful refresh involving another enabled provider. Filename mode
excludes browser records; `browser:` mode searches page title, host, and URL path.
The authenticated IPC and CLI expose refresh, status, and complete local cache
clear. Browser refresh shares the mutation gate with scans, content jobs, and
file operations, supports shutdown cancellation, and defers busy scheduled work
instead of polling continuously.

File operations use the same authenticated IPC and scheduling gate as indexing.
Copy, move, rename, and Trash require a preview token bound to stable source
identity, metadata, resolved destinations, destination-parent identity, and
conflict state. Existing paths are never overwritten. Copies use bounded staged
I/O, BLAKE3 verification, metadata preservation, and native no-replace commit;
moves use native rename on one volume and verified copy/delete across volumes.
Durable schema-2 receipts store progress, recovery intent, exact identities, and
idempotent request fingerprints before filesystem mutation. Startup reconciles
interrupted work and removes only operation-owned staging paths. Undo validates
identity and conflicts before every mutation; Windows Trash restore targets the
exact opaque Recycle Bin item and original filename. macOS can send items to
Trash, but programmatic restore is unavailable and must use Finder Put Back.

## Current Proof

- Windows: 100 library tests, one real worker-process integration test, two
  bridge process tests, strict all-feature Clippy, formatting, optimized
  five-binary build, RustSec audit, and cargo-deny advisory/license/source
  policy pass.
- RustSec advisory `RUSTSEC-2026-0253` remains explicitly allowed only through
  latest-stable Tantivy 0.26.1 and `lru 0.16.4`. Tantivy instantiates
  `LruCache<usize, OwnedBytes>` and calls only `get`/`put`; the advisory requires
  `pop`, a key with a panicking `Drop`, and unwind recovery, so the vulnerable
  path is unreachable here. Upstream Tantivy main is unreleased 0.27.0 and has
  moved to fixed `lru 0.18.2`; do not replace the stable release with a Git pin.
- Tests cover both Tantivy indexes, bounded extraction and archive safety, real
  watcher events, authenticated IPC, background jobs and retry policy,
  concurrent reader ownership, SQLite recovery state, and parser/ranker
  determinism.
- An isolated release corpus proved automatic indexing, structured JSON/text
  extraction, snippets/highlights, watcher replacement, watcher deletion,
  single-object CLI JSON, and healthy Doctor state. Two to three documents
  indexed in 191-219 ms; representative queries completed in 0.648-0.853 ms.
- The protocol 1.1 release agent was rebuilt and restored with one root, 2,021
  filename documents, content disabled, and healthy Doctor state after isolated
  cleanup.
- The protocol 1.2 release agent and schema 2 catalog passed a disposable
  end-to-end file-operation smoke: keep-both copy, move/undo, rename/undo,
  conflict refusal, stale-preview refusal, exact Recycle Bin Trash/undo, and an
  observed cancellation while copying an 8 GiB sparse file. The cancelled copy
  left no destination or staging item. Terminal receipts survived an agent
  restart with no pending reconciliation, and all matching test Trash entries
  and fixtures were removed afterward.
- Protocol 1.3 browser source/tests prove synthetic Chromium, Firefox, and Safari
  extraction through read-only online snapshots, credential/fragment removal,
  bounded deduplication, cancellation, owner-only cache cleanup, query-mode
  isolation, title/domain/path search, disabled-agent behavior, and preservation
  of ordinary filename records during clear. No real personal browser history
  was enabled or read during verification.
- The optimized protocol 1.3 release agent replaced protocol 1.2 and normalized
  the existing config atomically to include 365-day retention and a 100,000-entry
  per-provider cap. All provider toggles remained false, browser status reported
  zero records and no error, the existing root retained 2,021 filename records,
  and Doctor remained healthy on schema 2 with no pending reconciliation.
- Protocol 1.4 source, transport, and release proof covers three new read-only IPC
  commands, three matching CLI commands, the six-tool official MCP transport,
  and the independent-token HTTP server. Real loopback tests verify 401 auth,
  separate HTTP/IPC tokens, scope escape rejection, request-body rejection,
  result bounds, preview denial, no-store/nosniff headers, generic internal
  errors, and endpoint cleanup. The same HTTP fixture passed optimized release
  mode. The installed 1.4 agent retained one root and 2,021 filename documents,
  reported healthy schema 2 with no reconciliation, left HTTP absent while
  disabled, and passed live file-search, metadata, bounded-favorites, and
  fail-closed-preview checks.
- Protocol 1.5 proof covers canonical Shared remote-search contracts,
  authenticated local service IPC, opt-in/root-scoped search, path-safe bounded
  wire records, requester-bound expiring resolution leases, and Cross Shelf's
  encrypted two-agent query plus verified lazy fetch.
- The five-binary Windows package includes compiled `build-info`, project and
  third-party licenses, a source-state/payload-hash manifest, per-user
  installer/uninstaller, and an outer checksum. Exact archive validation,
  isolated 11-file install/build-info/uninstall, unchanged startup state, and
  pre-mutation rejection of a tampered payload pass.
- Five real serialized Windows dialog fixtures pass: modern Open, modern Save,
  folder chooser, multi-file Open, and legacy `GetOpenFileNameW`. They navigate
  or prepare selections without confirmation; Save preserves its typed name.
  The debug suite completed in 8.77 seconds. Optimized CLI/Doctor proof passed;
  foreground contention fails closed with `dialog_changed`.
- Strict all-target Clippy source checks pass for both Apple Silicon and Intel
  macOS targets, including the AXUIElement/AXObserver adapter. This uses
  linked-SQLite metadata and BLAKE3 pure mode to avoid C compilation on Windows;
  it is not Apple link/runtime proof. Run final FSEvents, Accessibility/panel,
  idle-resource, signing, and packaging checks on an actual Mac.
- Cross Shelf integration, Suite wiring, Windows build/test orchestration, and
  backend packaging are implemented. Physical macOS build/package/install,
  native host tests, and a clean current-resident lifecycle remain qualification
  boundaries. Search has no Git remote, so publishable CI also waits for a real
  Search/Spiffy Shared checkout contract. UI/app-bundle work stays frozen.

## Quality Gate

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --test dialog_bridge_windows --all-features -- --ignored --test-threads=1
cargo build --release --bins
cargo audit
cargo deny check --hide-inclusion-graph
.\scripts\package-windows.ps1
```

Update this file when ownership, binaries, paths, protocols, commands,
dependencies, or platform behavior changes.
