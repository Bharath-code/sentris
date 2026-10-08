use std::path::PathBuf;
use std::process::Command;

fn get_sentris_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sentris"))
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
    assert!(!stdout.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!stdout.contains("your-api-key-here"));
    assert!(!stdout.contains("STRIPE_SECRET_KEY"));
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

#[test]
fn test_cli_false_positive_suppression() {
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

    let findings = json_val["findings"].as_array().expect("findings is array");
    // Synthetic fixture has exactly 4 true positives:
    // 1. Stripe live key
    // 2. AWS access key
    // 3. GitHub PAT
    // 4. Slack webhook URL
    // All other 12 candidates are false positive candidates / inline ignores and must be suppressed.
    assert_eq!(findings.len(), 4);

    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(!output_str.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!output_str.contains("AKIAI44QH8DHBEXAMPLE"));
    assert!(!output_str.contains("your-api-key-here"));
    assert!(!output_str.contains("STRIPE_SECRET_KEY"));
    assert!(!output_str.contains("AWS_SECRET_KEY"));
    assert!(!output_str.contains("sk_test_"));
}

#[test]
fn test_cli_init_command() {
    let bin = get_sentris_bin();
    let temp_dir = tempfile::tempdir().unwrap();

    let output = Command::new(&bin)
        .current_dir(temp_dir.path())
        .arg("init")
        .output()
        .expect("Failed to execute sentris init");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Created Sentris configuration file"));

    let config_file = temp_dir.path().join(".sentris.toml");
    assert!(config_file.exists());
    let content = std::fs::read_to_string(&config_file).unwrap();
    assert!(content.contains("[scanner]"));
    assert!(content.contains("[[rules]]"));
}

#[test]
fn test_cli_format_github() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args([
            "scan",
            "tests/fixtures/synthetic_secrets.txt",
            "--format",
            "github",
        ])
        .output()
        .expect("Failed to execute sentris scan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("::error file=tests/fixtures/synthetic_secrets.txt"));
    assert!(stdout.contains("title=Hardcoded Secret Detected"));
    assert!(stdout.contains("stripe-secret-key"));
}

#[test]
fn test_cli_help_flags_discovery() {
    let bin = get_sentris_bin();

    // Global --offline
    let out = Command::new(&bin).arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--offline"));

    // Scan --webhook
    let out = Command::new(&bin)
        .args(["scan", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--webhook"));

    // Remediate --backend
    let out = Command::new(&bin)
        .args(["remediate", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--backend"));
}

#[test]
fn test_cli_scan_offline_suppresses_webhook() {
    let bin = get_sentris_bin();
    let output = Command::new(&bin)
        .args([
            "--offline",
            "scan",
            "tests/fixtures/synthetic_secrets.txt",
            "--webhook",
            "https://hooks.slack.com/services/MOCK/WEBHOOK/URL",
        ])
        .output()
        .expect("Failed to execute scan with webhook");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Zero-egress offline mode active"));
}

#[test]
fn test_cli_remediate_dry_run_backends() {
    let bin = get_sentris_bin();

    for backend in ["env", "vault", "aws", "doppler"] {
        let output = Command::new(&bin)
            .args([
                "--offline",
                "remediate",
                "tests/fixtures/synthetic_secrets.txt",
                "--dry-run",
                "--yes",
                "--backend",
                backend,
            ])
            .output()
            .expect("Failed to execute remediate dry-run");

        assert!(
            output.status.success(),
            "Backend {} failed with stderr: {}",
            backend,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Autonomous Remediation Session"));
        assert!(stdout.contains("Zero-egress offline mode active"));
        assert!(stdout.contains("PROVISIONED"));
        assert!(stdout.contains("PATCHED"));
    }
}
