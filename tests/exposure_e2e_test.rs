#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "AKIAJ5Q7X2M9R4T6W8YB";

macro_rules! fx {
    ($name:literal) => {
        include_str!(concat!("fixtures/exposure/", $name))
    };
}

struct Env {
    repo: tempfile::TempDir,
    shim: tempfile::TempDir,
}

impl Env {
    /// An IAM user holding AdministratorAccess owns the leaked key.
    fn new() -> Self {
        let env = Self {
            repo: tempfile::tempdir().unwrap(),
            shim: tempfile::tempdir().unwrap(),
        };
        let d = env.shim.path();
        for (sub, body) in [
            ("get-access-key-last-used", fx!("aws_last_used.json")),
            ("list-access-keys", fx!("aws_list_access_keys_active.json")),
            (
                "list-attached-user-policies",
                fx!("aws_attached_admin.json"),
            ),
            ("list-user-policies", fx!("aws_names_none.json")),
            ("list-groups-for-user", fx!("aws_groups_none.json")),
        ] {
            fs::write(d.join(format!("{sub}.out")), body).unwrap();
        }
        let script = format!(
            "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nif [ -f \"{d}/$2.out\" ]; then cat \"{d}/$2.out\"; exit 0; fi\nexit 1\n",
            d = d.display()
        );
        fs::write(d.join("aws"), script).unwrap();
        fs::set_permissions(d.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            env.repo.path().join("app.py"),
            format!("aws_access_key_id = \"{KEY}\"\n"),
        )
        .unwrap();
        env
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, None)
    }

    fn run_with(&self, args: &[&str], ambient_key: Option<&str>) -> Output {
        let mut c = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_sentris")));
        c.current_dir(self.repo.path())
            .env("SENTRIS_AWS_BIN", self.shim.path().join("aws"))
            .env_remove("AWS_ACCESS_KEY_ID");
        if let Some(k) = ambient_key {
            c.env("AWS_ACCESS_KEY_ID", k);
        }
        c.args(args).output().unwrap()
    }

    fn aws_calls(&self) -> String {
        fs::read_to_string(self.shim.path().join("calls.log")).unwrap_or_default()
    }

    fn audit_ledger(&self) -> String {
        fs::read_to_string(self.repo.path().join(".sentris/audit_ledger.json")).unwrap_or_default()
    }
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

#[test]
fn without_probe_no_provider_call_is_made_and_the_report_has_no_exposures() {
    let env = Env::new();
    let out = env.run(&["--json", "scan", "."]);
    let report = json(&out);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert!(report.get("exposures").is_none());
    assert_eq!(env.aws_calls(), "");
    assert!(!env.audit_ledger().contains("ExposureProbed"));
}

#[test]
fn probe_reports_the_tier_uses_read_only_calls_and_audits_the_probe() {
    let env = Env::new();
    let out = env.run(&["--json", "scan", ".", "--probe"]);
    let report = json(&out);
    let fp = report["findings"][0]["fingerprint"].as_str().unwrap();
    let exposure = &report["exposures"][fp];
    assert_eq!(exposure["tier"], "critical");
    assert_eq!(exposure["provider"], "AWS");
    assert!(exposure.get("measured_usd").is_none());

    let calls = env.aws_calls();
    assert!(!calls.is_empty());
    for line in calls.lines() {
        let verb = line.trim_start_matches("ARGV: ").split(' ').nth(1).unwrap();
        assert!(
            verb.starts_with("get-") || verb.starts_with("list-"),
            "{line}"
        );
    }
    let ledger = env.audit_ledger();
    assert!(ledger.contains("ExposureProbed"), "{ledger}");
    assert!(
        ledger.contains(&format!(
            "probe performed with credential fingerprint {}",
            &fp[..12]
        )),
        "{ledger}"
    );
}

#[test]
fn probe_is_suppressed_offline() {
    let env = Env::new();
    let out = env.run(&["--offline", "--json", "scan", ".", "--probe"]);
    assert!(json(&out).get("exposures").is_none());
    assert_eq!(env.aws_calls(), "");
    assert!(String::from_utf8_lossy(&out.stderr).contains("offline"));
}

#[test]
fn probing_with_the_leaked_key_as_ambient_credential_is_refused_and_falls_back_to_severity() {
    let env = Env::new();
    let out = env.run_with(&["--json", "scan", ".", "--probe"], Some(KEY));
    let report = json(&out);
    let fp = report["findings"][0]["fingerprint"].as_str().unwrap();
    let exposure = &report["exposures"][fp];
    assert!(exposure["live"]["Unverified"]
        .as_str()
        .unwrap()
        .contains("signing with the key being probed"));
    assert_eq!(
        exposure["tier"].as_str().unwrap().to_uppercase(),
        report["findings"][0]["severity"].as_str().unwrap()
    );
    assert_eq!(env.aws_calls(), "");
}

#[test]
fn text_output_lists_what_the_probe_observed() {
    let env = Env::new();
    let out = env.run(&["--no-color", "scan", ".", "--probe"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Exposure (read-only provider probes)"),
        "{text}"
    );
    assert!(text.contains("CRITICAL"), "{text}");
    assert!(
        text.contains("attached policy AdministratorAccess (AWS managed)"),
        "{text}"
    );
}
