# Spiffy Search macOS Test Matrix

Updated: 2026-09-27

Status meanings: `SOURCE-PASS` is Windows-host cross-target source proof,
`MAC-REQUIRED` needs a physical Mac, `NOT-IMPLEMENTED` is an explicit product
gap under the current UI freeze, and `N/A` is intentionally outside Search.

| Area | Required check and pass condition | Status |
| --- | --- | --- |
| Apple Silicon build | Locked release build emits all five arm64 Mach-O binaries; each reports build-info protocol 1.5 | MAC-REQUIRED |
| Intel build | Locked release build emits all five x86_64 Mach-O binaries on a supported SDK | MAC-REQUIRED |
| Cross-target lint | Strict all-target Clippy for arm64 and Intel | SOURCE-PASS |
| Unit/integration | All library, worker, bridge process, IPC, watcher, HTTP, MCP, and file-operation tests pass | MAC-REQUIRED |
| Dependency policy | RustSec has no unreviewed vulnerability; cargo-deny advisories/licenses/sources/bans pass | MAC-REQUIRED |
| Package | ZIP contains five binaries, installers, licenses/notices, manifest, and valid payload/outer SHA-256 hashes | MAC-REQUIRED |
| Ad-hoc signing | Every Mach-O verifies with `codesign --verify --strict`; receipt says ad-hoc, not notarized | MAC-REQUIRED |
| Install/uninstall | Per-user atomic install and normal uninstall succeed; data remains unless explicit removal is requested | MAC-REQUIRED |
| Launch at login | LaunchAgent passes `plutil`, bootstraps, starts after login, and does not loop after a clean stop | MAC-REQUIRED |
| Agent doctor | Fresh installed agent reports protocol 1.5, healthy catalog/index, and no pending recovery | MAC-REQUIRED |
| Initial indexing | A disposable mixed file/folder root indexes completely without following symlinks or touching originals | MAC-REQUIRED |
| FSEvents | Create, rename, modify, and delete become bounded incremental updates; overflow/sleep gap reconciles | MAC-REQUIRED |
| Search accuracy | Exact name, fuzzy, extension, date, size, kind, location, phrase, exclusion, current-folder, pin, and alias queries match fixtures | MAC-REQUIRED |
| Content search | Supported text/PDF/OpenXML/OpenDocument/EPUB fixtures index in the bounded worker; corrupt/oversized files fail closed | MAC-REQUIRED |
| Spotlight bootstrap | Search remains complete without Spotlight; any optional bootstrap comparison cannot replace Tantivy | N/A |
| Browser history | Explicit fixture-only Chromium/Firefox/Safari refresh is read-only, bounded, mode-isolated, and fully clearable | MAC-REQUIRED |
| Local API/MCP | Loopback auth, file/folder/application/content scope bounds, preview permission, stdio MCP tools, token separation, and endpoint cleanup pass | MAC-REQUIRED |
| File operations | Copy/move/rename/Trash preview-confirm-run, keep-both, cancellation, receipts, and safe failure pass on disposable files | MAC-REQUIRED |
| Trash recovery | Send to Trash succeeds; docs clearly require Finder Put Back because programmatic restore is unavailable | MAC-REQUIRED |
| Accessibility onboarding | Ordinary agent causes no prompt; explicit bridge doctor requests only Accessibility and reports denial clearly | MAC-REQUIRED |
| Open panel single file | Exact dialog ID navigates/prepares one file without invoking Open | MAC-REQUIRED |
| Open panel multiple files | Same-folder multi-file selection remains unsupported by the current macOS AX owner | NOT-IMPLEMENTED |
| Save panel | Folder navigation preserves the typed filename and never invokes Save | MAC-REQUIRED |
| Folder panel | Exact supported chooser navigates without confirmation; stale/foreign panels fail closed | MAC-REQUIRED |
| Finder context | Adapter discovers a real Finder folder only for an explicit bridge request | MAC-REQUIRED |
| Spaces/displays | Panel identity and focus remain correct across Spaces and multiple displays; no unrelated window is acted on | MAC-REQUIRED |
| Quick Look UI | No Search UI/action owner exists while UI work is frozen | NOT-IMPLEMENTED |
| Global hotkey UI | No launcher/window hotkey owner exists yet | NOT-IMPLEMENTED |
| Sleep/wake | Index and endpoint recover after sleep without duplicate residents, busy loops, or full rescan unless reconciliation requires it | MAC-REQUIRED |
| Network change | Local Search stays healthy; Cross Shelf reconnect behavior does not expose a Search listener | MAC-REQUIRED |
| Crash recovery | Kill during scan/content/file staging, restart, and verify prior readable snapshot plus owned-residue cleanup | MAC-REQUIRED |
| Cross Shelf search | A paired second device can search only opted-in roots; results expose bounded relative metadata | MAC-REQUIRED |
| Clipboard source | Disabled history yields no results; enabled Cross Shelf history remains owned and clearable by Cross Shelf | MAC-REQUIRED |
| Remote file fetch | Selecting a remote result performs verified resumable transfer without deleting or opening the source | MAC-REQUIRED |
| Revocation/security | Revoked peer, wrong pin/token, replay, public bind, path escape, and tampered chunk all fail closed | MAC-REQUIRED |
| Performance | Record corpus size, initial/incremental index time, p50/p95 query latency, idle CPU/RSS, worker peak, and package time | MAC-REQUIRED |
| `.app` / DMG | The current product ships a backend ZIP and LaunchAgent; no app bundle is produced yet | NOT-IMPLEMENTED |
| Developer ID/notarization | No credentials or notarized artifact are available in the Windows environment | MAC-REQUIRED |

After real execution, replace each completed status with `PASS` or `FAIL` and
append the exact command/evidence location in the same row. Do not erase
remaining gaps or convert source proof into host proof.
