use std::path::PathBuf;
use std::process::Command;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo-monorepo")
}

#[test]
fn scan_fixture_as_text_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_sknr"))
        .arg("scan")
        .arg(fixture_root())
        .output()
        .expect("failed to run sknr scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("services: 4"));
    assert!(stdout.contains("api-gateway"));
    assert!(stdout.contains("lodash@4.17.20"));
}

#[test]
fn scan_fixture_as_json_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_sknr"))
        .arg("scan")
        .arg(fixture_root())
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run sknr scan --format json");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");

    assert_eq!(json["services"].as_array().map(Vec::len), Some(4));
    assert_eq!(json["services"][0]["path"], "apps/api-gateway");
}

#[test]
fn scan_invalid_path_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_sknr"))
        .arg("scan")
        .arg(fixture_root().join("missing"))
        .output()
        .expect("failed to run sknr scan against invalid path");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
}
