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
        .arg("--offline")
        .output()
        .expect("failed to run sknr scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("services: 4"));
    assert!(stdout.contains("topology nodes: 5"));
    assert!(stdout.contains("topology edges: 3"));
    assert!(stdout.contains("packages: 6"));
    assert!(stdout.contains("vulnerable packages: 0"));
    assert!(stdout.contains("KEV matches: 0"));
    assert!(stdout.contains("reachable packages: 4"));
    assert!(stdout.contains("prioritized packages: 0"));
    assert!(stdout.contains("api-gateway"));
    assert!(stdout.contains("lodash@4.17.20"));
    assert!(stdout.contains("inventory:"));
}

#[test]
fn scan_fixture_as_json_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_sknr"))
        .arg("scan")
        .arg(fixture_root())
        .arg("--offline")
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
    assert_eq!(json["topology"]["nodes"].as_array().map(Vec::len), Some(5));
    assert_eq!(json["topology"]["edges"].as_array().map(Vec::len), Some(3));
    assert_eq!(json["inventory"].as_array().map(Vec::len), Some(6));
    assert_eq!(json["services"][0]["path"], "apps/api-gateway");
    assert_eq!(json["services"][0]["internet_facing"], true);
    assert_eq!(json["inventory"][0]["name"], "axios");
    assert_eq!(
        json["inventory"][0]["used_by"][0]["reachability"]["imported"],
        true
    );
    assert_eq!(json["inventory"][0]["priority"], serde_json::Value::Null);
    assert_eq!(
        json["inventory"][0]["advisories"].as_array().map(Vec::len),
        Some(0)
    );
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
