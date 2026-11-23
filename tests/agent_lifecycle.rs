#![cfg(windows)]

use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn control(profile: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_spiffy-searchctl"));
    command
        .env("LOCALAPPDATA", profile.join("local"))
        .env("APPDATA", profile.join("roaming"))
        .current_dir(profile)
        .creation_flags(0x0800_0000)
        .stdin(Stdio::null());
    command
}

#[test]
fn redirected_start_finishes_while_the_isolated_agent_stays_available() {
    let profile = tempfile::tempdir().unwrap();
    // This exact profile is the only owner cleanup may address, even on failure.
    struct StopOwner<'a>(&'a std::path::Path);
    impl Drop for StopOwner<'_> {
        fn drop(&mut self) {
            let _ = control(self.0).args(["--json", "stop"]).output();
        }
    }
    let _cleanup = StopOwner(profile.path());
    let mut start = control(profile.path())
        .args(["--json", "start"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = start.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = String::new();
        let read = stdout.take(32768).read_to_string(&mut output);
        let _ = sender.send((read, output));
    });
    let started = receiver.recv_timeout(Duration::from_secs(15));
    if started.is_err() {
        // Release a leaked pipe in the regression case before joining its reader.
        let _ = control(profile.path()).args(["--json", "stop"]).output();
    }
    let (read, output) =
        started.expect("start kept stdout open while its background agent was alive");
    read.unwrap();
    reader.join().unwrap();
    assert!(start.wait().unwrap().success());
    let reply: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(reply["ok"], true);
    let status = control(profile.path())
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["ok"], true);
    assert_eq!(status["data"]["roots"], 0);
    assert_eq!(status["data"]["content_enabled"], false);
    assert_eq!(status["data"]["browser_enabled"], false);
}
