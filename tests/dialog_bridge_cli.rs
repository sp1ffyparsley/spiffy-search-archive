use serde_json::Value;
use std::process::{Command, Output};

#[test]
fn profiles_emit_one_machine_readable_reply() {
    let output = bridge_output(["--json", "profiles"]);
    assert!(
        output.status.success(),
        "bridge stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["code"], "ok");
    let profiles = reply["data"].as_array().unwrap();
    if cfg!(any(target_os = "windows", target_os = "macos")) {
        assert_eq!(profiles.len(), 1);
    } else {
        assert!(profiles.is_empty());
    }
}

#[test]
fn malformed_dialog_id_fails_before_platform_action() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().to_string_lossy().into_owned();
    let output = bridge_output(["--json", "navigate", "--dialog-id", "", folder.as_str()]);
    assert_eq!(output.status.code(), Some(2));
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["code"], "invalid_target");
    assert!(reply["data"].is_null());
}

fn bridge_output<const N: usize>(arguments: [&str; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_spiffy-file-dialog-bridge"))
        .args(arguments)
        .output()
        .unwrap()
}
