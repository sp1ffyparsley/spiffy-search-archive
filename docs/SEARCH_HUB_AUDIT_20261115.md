# Spiffy Search, MemoryCore, Voice Archive and Clipboard — November 15, 2026

## Verified current system

Spiffy Search is a functional Rust search backend, not merely a prototype.
It provides a fast indexed filename search, fuzzy ranking, optional content
and browser search, bounded local IPC/API, saved Spiffy Shelf title search,
workspace launcher projection, and a file-dialog bridge. The actual native
search popup/launcher UI is not packaged as part of the installed Search.

The installed Windows 0.1.0 package is from September 9. The Search agent
is stopped. Its configured filesystem root is only the synthetic directory
C:\tmp\spiffy-search-smoke, with 2,023 indexed documents. That is not an
index of the user's C, D or H editing drives. Starting the agent as-is
will not make real project files and footage discoverable.

Listary is installed and running; preserve it as the existing global
file-search UI until a separate search interface is qualified.

Spiffy Shelf 0.2.1 and Spiffy Clipboard/Ditto are active. MemoryCore already
owns the indexed Voice Archive transcripts and the source-bound timed
playback resolver. These systems must not be copied into new databases just
to create a search popup.

## Actual tests and measurements

- Installed Sept Spiffy Search agent, isolated D-drive synthetic profile:
  240 generated files indexed, 30 queries all returned 10 rows. Median
  50.47 ms; p95 56.26 ms; maximum 60.59 ms. Owner start/stop passed.
  No real profile data or root configuration was touched.
- New read-only on-demand scripts/search_hub.py is a command-line,
  concurrently streamed bridge, not an installed popup. It delegates
  files to Spiffy Search, saved Shelf titles to the authenticated Shelf
  owner, and MemoryCore/Voice Archive lexical search to MemoryCore.
  It creates no index, database, hotkey, startup task or service.
  Its current interpreter path and SHA-256 are validated against the
  MemoryCore promoted host-runtime receipt before launching Python.
- Nine focused synthetic Search Hub tests pass. Four content-free Clipboard
  timing parser tests pass.
- The real no-result integrated query returned Shelf in 178 ms, a
  stopped-agent response for files, and Voice Archive through MemoryCore
  in 11.9 seconds. An independent cold MemoryCore lexical query took
  17.2 seconds. Do not block the first popup or dispatch one Python
  process per keystroke.

### Follow-up: stopped-file-agent fast path (source-only)

An additional bounded change to scripts/search_hub.py checks whether
Spiffy Search's private endpoint file exists before starting the file
control CLI. When the daemon is stopped, the previously measured CLI
probe spent roughly 140 ms launching a process only to report that
its IPC endpoint was absent. The new path returns a typed
agent_not_running result immediately, without reading the endpoint's
private token or interfering with saved-Shelf search.

Two new isolated fixture tests were added to test_search_hub.py for
the stopped-agent and existing-endpoint cases. This follow-up's native
test attempt was blocked by the connected workstation's 64 retained
terminal session limit. The preceding 9 Search Hub tests and packaged
native synthetic search benchmark were successful **before** this small
source-only change. Do not mark the new fast-path fix installed or
its additional tests passed until a new local test receipt exists.
The production search agent and Listary hotkeys were not activated.
- Historical installed Clipboard log timings, WITHOUT queries or content:
  search IPC n=297 p50 39 ms/p95 5,138 ms; native search worker n=294
  p95 4,770 ms; worker queue p95 4 ms; authorization lock wait p95 6 ms;
  presentation render p95 269 ms; search render p95 288 ms.
  A November 14 search render was 1,763 ms. This supports intermittent
  latency in native query fulfillment, not primarily worker queue or
  authorization lock. These are different sessions, not a measured
  hotkey-to-first-frame distribution; do not add their percentiles.

## Completed cleanup and safety holds

- The old Spiffy Search target/debug cache was already retired in the
  previous cleanup turn. Do not double-count its reclaimed space.
- An old D-drive test fixture with 240 synthetic filenames and its empty
  test-parent directory were moved to the Windows Recycle Bin. The user
  contents and original files were not touched.
- A new read-only scoped inventory confirmed that remaining Search
  target content is 4.041 GiB logical: release 1.445 GiB, package-build
  1.123 GiB, aarch64-apple-darwin 0.841 GiB, x86_64-apple-darwin
  0.630 GiB. Its installed app and private index are tiny by comparison.
- The package-build Recycle Bin preflight returned HOLD because some
  files have hardlinks outside that subtree. No force deletion was
  performed. Mac cross-target and release artifacts were preserved.
- No Telegram data, Clipboard history, installed apps, media/project
  originals, Voice/Memory databases or scene-analysis caches were removed.

## How to use the new source-only bridge

Run from Spiffy Search root:

    python -B scripts/search_hub.py "my scene" --sources quick --stream
    python -B scripts/search_hub.py "voice note" --sources voice --stream
    python -B scripts/search_hub.py "project" --sources all --diagnostics

quick = Spiffy Search local file agent (if running) plus Shelf saved-title
metadata. all = file + Shelf + MemoryCore, with no redundant Voice query.
voice = MemoryCore's existing source:voicearchive lexical search.
There is no new AI inference and no implicit model download.

Clipboard content is intentionally NOT sent to Spiffy Search, because
the verified Search CLI has authenticated saved Shelf metadata but does
not expose the private Clipboard search history capability. Integrate
that through the existing native Clipboard owner only, with privacy,
stale-query and revocation tests.

The CLI passes query text as command arguments to owner processes;
local process inspection can see those arguments. It writes no new
query/history log, but it is not a substitute for a private IPC surface.

## Product direction and next qualification

Keep the Rust Search backend. Use Listary as the existing global
file launcher today. The differentiated Spiffy experience should be
one owner-delegating Search Everywhere panel that contains:

1. Fast filename/path/launcher results through an explicit, bounded
   Spiffy Search root list, excluding test/build/H recovery data.
2. Saved Shelf titles through the current authenticated owner.
3. Clipboard results through the actual native Clipboard provider;
   avoid a second Clipboard index or background history duplication.
4. MemoryCore and Voice Archive transcripts through their current
   read-only search/playback owners, using warmed native service or
   explicit user submission rather than cold Python per keystroke.
5. Scene search through the existing Video Editor shot/scene evidence
   registry and revision/clip/timestamp resolver. Search is not a
   reason to re-run AI extraction of already analyzed footage.

Before any native packaged rollout: test at realistic file/clipboard
history scale under CPU and memory pressure, measure cold hotkey-to-first
paint and warm first useful row, native query p50/p95/p99, stale results,
rights/revocation, metadata opening, scene timestamp seeking, and real
installer rollback. Do not treat the new command-line bridge as a
finished native popup or a full Clipboard performance repair.

## Receipts

- scripts/search_hub.py and scripts/test_search_hub.py
- scripts/smoke_isolated_agent.py
- scripts/diagnose_clipboard_latency.py and scripts/test_clipboard_latency.py
- scripts/audit_search_storage.py, scripts/inspect_search_profile.py
- scripts/recycle_old_package_build.py: HOLD, never applied
- SS Scripts/_reports/ss-scripts-cleanup/20261115_spiffy_search_native_synthetic_smoke.json
- SS Scripts/_reports/ss-scripts-cleanup/20261115_spiffy_clipboard_content_free_latency.json
- SS Scripts/_reports/ss-scripts-cleanup/20261115_spiffy_search_profile_activation_audit.json
- SS Scripts/_reports/ss-scripts-cleanup/20261115_spiffy_search_storage_post_audit.json
- SS Scripts/_reports/ss-scripts-cleanup/20261115_spiffy_search_package_build_recycle.json
- SS Scripts/_reports/ss-scripts-cleanup/20261115_spiffy_search_synthetic_fixture_recycle.json

## External technical references

- https://help.listary.com/search-file
- https://www.flowlauncher.com/
- https://docs.rs/crate/tantivy/0.26.0
- https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.fileio.filesystem.deletedirectory
- https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/windows-search-performance-issues
