# Spiffy Search macOS Handoff

Updated: 2026-09-27

## Baseline

- Project: the local Spiffy Search source checkout (portable path)
- Branch: `main`
- Backend/package baseline: `66a04f9`
- Rust package: `spiffy-search 0.1.0`, MSRV 1.88
- Verified Windows toolchain: `rustc 1.97.1`, `cargo 1.97.1`
- macOS deployment target: `13.0` unless `MACOSX_DEPLOYMENT_TARGET` is set explicitly
- LaunchAgent label: `com.spiffyscenes.spiffysearch.agent`
- Application bundle ID: none; Search is currently a backend/CLI package

Key locked dependencies include Tantivy 0.26.1, notify 8.2.0, rusqlite
0.40.1 with bundled SQLite, lopdf 0.44.0, RMCP 3.1.2, Tokio 1.53.1,
trash 5.2.6, and objc2 AppKit/Foundation 0.3.2. `Cargo.lock` is the
authoritative full graph.

## Current Evidence

- Search protocol 1.5 is sourced from Spiffy Shared, not duplicated in the CLI.
- Windows strict Clippy passes and 100 library tests pass. The complete Suite
  gate also passed the real worker integration and two bridge process tests.
- Strict source-level Clippy passed for `aarch64-apple-darwin` and
  `x86_64-apple-darwin` before this handoff. This is not Apple link/runtime proof.
- `cargo audit` reports the explicitly allowed Tantivy-owned
  `RUSTSEC-2026-0253` advisory. Search cannot reach it: Tantivy's cache key is
  `usize`, its value is `OwnedBytes`, and this code path uses only `get`/`put`,
  while the advisory requires `pop` with a panicking key destructor. Retain
  latest-stable Tantivy 0.26.1 until the fixed 0.27 line is released.
- The Windows package contains five optimized binaries, install/uninstall
  scripts, project and third-party licenses, compiled build metadata, a payload
  hash manifest, and an outer SHA-256 checksum. Untampered disposable install
  and uninstall passed; a modified payload failed before destination mutation.
- No physical Mac build, package, install, Accessibility, FSEvents, launchd,
  signing, or two-device test has been claimed.
- The package owner records a deterministic Search + Spiffy Shared source
  fingerprint and refuses `--skip-build` when the qualified binaries no longer
  match current source. Unsupported non-Apple targets fail before build work.
- Workspace launch targets are platform-specific catalog metadata. macOS `.command`
  launchers are projected as `Application` records through the same strict path
  validation used by Windows; runtime proof still requires a Mac host.
- This repository currently has no Git remote. Valid macOS CI cannot be wired
  until Search and its sibling Spiffy Shared dependency have publishable checkout
  locations; do not add a workflow that cannot resolve the real path dependency.

## Build And Test

Run on an Apple Silicon Mac with current Xcode Command Line Tools:

```bash
cd "/path/to/SS Scripts/Spiffy Search"
rustup target add aarch64-apple-darwin x86_64-apple-darwin
export MACOSX_DEPLOYMENT_TARGET=13.0
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo audit --file Cargo.lock
cargo deny check --hide-inclusion-graph
cargo build --locked --release --target aarch64-apple-darwin --bins
```

Run the serialized native panel tests only in an interactive desktop session:

```bash
cargo test --test dialog_bridge_macos --locked -- --ignored --test-threads=1
```

If that test target is absent or a required case remains ignored, record it as
unverified and fix the existing adapter/test owner rather than creating a
second bridge.

The current AX adapter prepares one Open-panel file per request. Same-folder
multi-file selection is still unimplemented on macOS and must remain marked as
a product gap until the canonical AX owner supports and passes it on real panels.

## Package, Install, Uninstall

```bash
./scripts/package-macos.sh aarch64-apple-darwin
./scripts/package-macos.sh x86_64-apple-darwin
shasum -a 256 -c artifacts/aarch64-apple-darwin/SHA256SUMS.txt
ditto -x -k artifacts/aarch64-apple-darwin/SpiffySearch-aarch64-apple-darwin-portable.zip /tmp/spiffy-search-package
/tmp/spiffy-search-package/SpiffySearch/install-macos.sh
~/Applications/SpiffySearch/spiffy-searchctl --json doctor
~/Applications/SpiffySearch/uninstall-macos.sh
```

The package script emits a target-specific ZIP and checksum. The installer
verifies every manifest hash before mutation, atomically replaces only the
selected per-user directory, and registers a per-user LaunchAgent. It requires
no root access. Data is preserved by default; pass `--remove-data` as the
uninstaller's second argument only after explicit review.

For a personal ad-hoc signed package, sign all five staged Mach-O binaries with
`codesign --force --sign - --timestamp=none`, verify with `codesign --verify
--strict --verbose=2`, then recreate the ZIP and checksum. No Developer ID,
notarization, DMG, `.app`, Intel, or universal artifact has been produced on
this Windows host.

## Runtime Paths

- Install: `~/Applications/SpiffySearch`
- Config: `~/Library/Application Support/SpiffySearch/search-config.json`
- Catalog/receipts: `~/Library/Application Support/SpiffySearch/search.db`
- Filename index: `~/Library/Application Support/SpiffySearch/indexes/filename`
- Content index: `~/Library/Application Support/SpiffySearch/indexes/content`
- Product logs: `~/Library/Application Support/SpiffySearch/logs`
- Browser snapshot cache: `~/Library/Caches/SpiffySearch/browser-snapshots`
- LaunchAgent: `~/Library/LaunchAgents/com.spiffyscenes.spiffysearch.agent.plist`
- launchd stdout/stderr: `~/Library/Logs/SpiffySearch`

## Permissions And Network

The resident indexer does not require Accessibility. Grant ordinary filesystem
access only to roots the user selects. Safari history may require additional
macOS privacy permission when that provider is explicitly enabled; do not grant
Full Disk Access for normal filename search. Only
`spiffy-file-dialog-bridge doctor --request-permission` may request
Accessibility, and only for Open/Save panel preparation.

Search stores local IPC/API bearer tokens in owner-only files, not Keychain.
Cross Shelf owns Keychain credentials and remote transport. Search itself binds
only loopback and should not require a firewall exception; remote-device search
is delegated over Cross Shelf's authenticated private-LAN channel.

## Required Host Proof

Execute every `MAC-REQUIRED` row in `MAC_TEST_MATRIX.md`, fix real failures in
the existing owner, and record exact command output, OS/hardware, durations,
artifact hashes, and pass/fail state. Preserve Windows behavior. Do not mark
hotkeys, Finder UI, Quick Look UI, `.app`/DMG, signing, or notarization complete
while those surfaces remain frozen or unrun.
