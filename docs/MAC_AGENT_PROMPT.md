# Spiffy Search Mac Agent Prompt

You are qualifying the existing Spiffy Search backend on a physical Apple
Silicon Mac. Do not redesign the architecture or add UI while the UI freeze is
active.

1. Read `README.md`, `AI_MASTER_PROMPT.md`, `THIRD_PARTY_NOTICES.md`,
   `docs/MAC_HANDOFF.md`, and `docs/MAC_TEST_MATRIX.md` before changing code.
2. Confirm the exact `main` revision and record any pre-existing dirty files.
   Preserve them; never reset or overwrite another task's work.
3. Keep Spiffy Search as the owner of filename/content indexes, local IPC/API,
   MCP, file operations, browser adapters, and the dialog bridge. Reuse Spiffy
   Shared contracts and Cross Shelf transport. Add no parallel index, database,
   clipboard recorder, remote server, or bridge.
4. Install current Xcode Command Line Tools and Rust stable. Use the locked
   dependency graph and `MACOSX_DEPLOYMENT_TARGET=13.0`.
5. Build and test Apple Silicon first. Run formatting, strict Clippy, all tests,
   RustSec audit, cargo-deny, and an optimized five-binary build. Leave no
   required failure or skipped platform test unexplained.
6. Run Intel source/build checks where the installed SDK supports them. Produce
   only artifacts that actually link and validate; do not call separate files a
   universal package unless `lipo -verify_arch` proves both architectures.
7. Package with `scripts/package-macos.sh`, verify the outer checksum and every
   payload hash, install under `~/Applications/SpiffySearch`, and validate the
   generated LaunchAgent with `plutil` and `launchctl`.
8. Grant only selected-folder access needed for indexing. Request Accessibility
   only through the dialog bridge's explicit doctor command. Do not grant Full
   Disk Access unless an explicitly enabled Safari-history test proves it is
   required and the receipt records why.
9. Execute every `MAC-REQUIRED` test in `docs/MAC_TEST_MATRIX.md`, including
   FSEvents, content search, Open/Save panels, launch at login, crash recovery,
   sleep/wake, network changes, and two-device Cross Shelf search/fetch.
10. Use disposable roots, files, browser-history fixtures, and transfer
    destinations. Do not read personal history, mutate originals, or stop a
    resident owned by another task.
11. Measure initial indexing, incremental update latency, representative query
    latency, idle CPU/RSS, content-worker bounds, and package/install time. Keep
    correctness and result identity fixed while profiling.
12. Fix real platform defects in the existing adapter or contract owner and
    rerun the affected workflow. Preserve all Windows tests and package behavior.
13. Update the canonical docs with the exact Mac revision, hardware, macOS,
    Xcode/Rust versions, commands, durations, hashes, permissions granted, and
    pass/fail results. Create one concise Mac host receipt only after real proof.
    Never claim an unrun test, signature, package, or notarization passed.
