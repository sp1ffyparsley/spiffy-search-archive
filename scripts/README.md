# Spiffy Search scripts

This folder contains the existing package owners and focused source-only
development tools. It is intentionally **not** a second installed search app.

## Release and installation

- package-windows.ps1 / package-macos.sh — canonical existing package owners.
- Install and uninstall scripts shipped with packages — retain their original
  paths; do not replace current installed apps with unqualified source.

## Search Hub (experimental, on demand)

- search_hub.py — read-only CLI for file search, saved Shelf titles and optional
  existing MemoryCore/Voice Archive search. Fast and slow owners respond
  independently; no new index or database.
- test_search_hub.py — synthetic regression and refusal tests.

## Performance and health diagnostics

- smoke_isolated_agent.py — isolated synthetic Search-agent profile on D:.
  Never points at your production roots, installs no service and stops its agent.
- diagnose_clipboard_latency.py / test_clipboard_latency.py — parses only
  content-free native Clipboard timing stages, not any clipboard text/query.
- inspect_search_profile.py — read-only counts/settings from the existing Search
  owner. Never prints the actual indexed paths, contents or authentication tokens.
- audit_search_storage.py — read-only Search build/index/log storage inventory.
- recycle_old_package_build.py — exact old package-build preflight and optional
  Recycle Bin operation. Presently **HOLD** because NTFS hardlinks cross folders.
  Never force the deletion.

## Release status

These tools are source-only. No new native global Search popup, MemoryCore
warm-service bridge, Clipboard private-search capability, or updated
installed Search package is claimed. The installed Search agent is currently
stopped and its configured root is a synthetic test root. Existing Listary,
Spiffy Shelf, Ditto and Voice Archive retain their current hotkeys and data.

Find verified performance numbers, cleanup holds and next qualification
steps in ../docs/SEARCH_HUB_AUDIT_20261115.md. Testing the current
stopped-agent fast path remains open due to the local terminal-session limit;
earlier synthetic backend tests are separately verified.
