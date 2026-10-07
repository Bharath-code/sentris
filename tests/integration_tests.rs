use std::path::PathBuf;
use std::process::Command;

fn get_sentris_bin() -> PathBuf {
    let release_bin = PathBuf::from("./target/release/sentris");
    if release_bin.exists() {
        return release_bin;
    }
    PathBuf::from("./target/debug/sentris")
}

#[test]
fn test_cli_scan_clean_file() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args(["scan", "src/error.rs"])
        .output()
        .expect("Failed to execute sentris scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Zero secrets detected") || stdout.contains("clean"));
}

#[test]
fn test_cli_scan_synthetic_fixtures() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args(["scan", "tests/fixtures/synthetic_secrets.txt"])
        .output()
        .expect("Failed to execute sentris scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stripe-secret-key"));
    assert!(stdout.contains("aws-access-key-id"));
    assert!(stdout.contains("github-pat"));
    assert!(stdout.contains("slack-webhook"));
    // Verify false positives and inline ignores are NOT in table
    assert!(!stdout.contains("999999"));
    assert!(!stdout.contains("123e4567"));
}

#[test]
fn test_cli_fail_on_secret_flag() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args([
            "scan",
            "tests/fixtures/synthetic_secrets.txt",
            "--fail-on-secret",
        ])
        .output()
        .expect("Failed to execute sentris scan");

    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_cli_format_json() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args([
            "scan",
            "tests/fixtures/synthetic_secrets.txt",
            "--format",
            "json",
        ])
        .output()
        .expect("Failed to execute sentris scan");

    assert!(output.status.success());
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse JSON output");

    assert!(json_val.get("findings").is_some());
    let findings = json_val["findings"].as_array().expect("findings is array");
    assert!(findings.len() >= 4);
    assert!(json_val["version"].is_string());
}

#[test]
fn test_cli_format_sarif() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args([
            "scan",
            "tests/fixtures/synthetic_secrets.txt",
            "--format",
            "sarif",
        ])
        .output()
        .expect("Failed to execute sentris scan");

    assert!(output.status.success());
    let sarif_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Failed to parse SARIF output");

    assert_eq!(sarif_val["version"], "2.1.0");
    assert_eq!(sarif_val["runs"][0]["tool"]["driver"]["name"], "sentris");
    let results = sarif_val["runs"][0]["results"]
        .as_array()
        .expect("results is array");
    assert!(results.len() >= 4);
}

#[test]
fn test_cli_completions() {
    let bin = get_sentris_bin();
    for shell in ["bash", "zsh", "fish"] {
        let output = Command::new(&bin)
            .args(["completions", shell])
            .output()
            .expect("Failed to execute sentris completions");

        assert!(output.status.success());
        let script = String::from_utf8_lossy(&output.stdout);
        assert!(!script.is_empty());
        assert!(script.contains("sentris"));
    }
}

#[test]
fn test_cli_quiet_mode_silence() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args(["-q", "scan", "src/error.rs"])
        .output()
        .expect("Failed to execute sentris quiet scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().is_empty());
}
