use serde_json::json;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[test]
fn isolated_worker_extracts_a_real_file_over_the_bounded_frame() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("Worker Note.txt");
    std::fs::write(&source, b"isolated worker production transcript").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_spiffy-search-content-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({
        "protocol_version": 1,
        "path": source.to_string_lossy(),
        "max_file_bytes": 65536,
        "max_extracted_bytes": 4096
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "worker stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut stdout = output.stdout.as_slice();
    let mut header_size = [0_u8; 4];
    stdout.read_exact(&mut header_size).unwrap();
    let header_size = u32::from_le_bytes(header_size) as usize;
    assert!((1..=64 * 1024).contains(&header_size));
    let mut header = vec![0_u8; header_size];
    stdout.read_exact(&mut header).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
    assert_eq!(header["ok"], true);
    assert_eq!(header["mime_type"], "text/plain");
    let content_bytes = header["content_bytes"].as_u64().unwrap() as usize;
    assert!(content_bytes <= 4096);
    let mut content = vec![0_u8; content_bytes];
    stdout.read_exact(&mut content).unwrap();
    assert_eq!(
        String::from_utf8(content).unwrap(),
        "isolated worker production transcript"
    );
    assert!(stdout.is_empty());
}
