#![allow(clippy::unwrap_used)]

//! `--from-report`: findings produced by Betterleaks (same JSON schema as Gitleaks) flow through
//! Sentris' ranking and remediation. The report shape below is real Betterleaks 1.9.0 output.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SECRET: &str = concat!("sk_", "live_", "51H8xK2mQ9rT4vW7yZ3aB6cD");
const SOURCE: &str = concat!(
    "import os\nSTRIPE = \"sk_",
    "live_",
    "51H8xK2mQ9rT4vW7yZ3aB6cD\"\n"
);

struct Repo(tempfile::TempDir);

impl Repo {
    fn new() -> Self {
        let r = Self(tempfile::tempdir().unwrap());
        fs::write(r.path("app.py"), SOURCE).unwrap();
        r.report("app.py", 2, SECRET);
        r
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.path().join(name)
    }

    fn report(&self, file: &str, line: usize, secret: &str) {
        let entry = serde_json::json!([{
            "RuleID": "stripe-access-token",
            "Description": "Found a Stripe Access Token",
            "StartLine": line, "EndLine": line, "StartColumn": 11, "EndColumn": 43,
            "Match": format!("{secret}\""), "Secret": secret,
            "Attributes": {"confidence": "high", "path": file, "resource": "fs.content"},
            "Tags": [], "Fingerprint": format!("{file}:stripe-access-token:{line}"),
            "File": file, "SymlinkFile": "", "Commit": "", "Entropy": 4.875,
            "Author": "", "Email": "", "Date": "", "Message": ""
        }]);
        fs::write(self.path("report.json"), entry.to_string()).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sentris"))
            .current_dir(self.0.path())
            .args(args)
            .output()
            .unwrap()
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn scan_imports_the_finding_without_echoing_the_secret() {
    let repo = Repo::new();
    let out = repo.run(&["scan", "--from-report", "report.json", "-f", "json"]);
    let body = text(&out);
    assert!(out.status.success(), "{body}");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = &json["findings"][0];
    assert_eq!(f["rule_id"], "stripe-secret-key");
    assert_eq!(f["severity"], "CRITICAL");
    assert_eq!(f["file_path"], "app.py");
    assert_eq!(f["recommended_env_var"], "STRIPE_SECRET_KEY");
    assert!(!body.contains(SECRET), "{body}");
}

#[test]
fn fail_on_secret_trips_on_imported_findings() {
    let repo = Repo::new();
    let out = repo.run(&[
        "scan",
        "--from-report",
        "report.json",
        "--fail-on-secret",
        "-f",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}

#[test]
fn remediate_moves_the_secret_to_env_and_rolls_back_byte_for_byte() {
    let repo = Repo::new();
    let out = repo.run(&["remediate", "--from-report", "report.json", "--yes"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!fs::read_to_string(repo.path("app.py"))
        .unwrap()
        .contains(SECRET));
    assert!(fs::read_to_string(repo.path(".env"))
        .unwrap()
        .contains(SECRET));

    let out = repo.run(&["rollback"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(fs::read_to_string(repo.path("app.py")).unwrap(), SOURCE);
}

#[test]
fn stale_or_escaping_entries_are_skipped_and_nothing_is_edited() {
    let repo = Repo::new();
    fs::write(repo.path("app.py"), "import os\nSTRIPE = os.environ['K']\n").unwrap();
    let out = repo.run(&["remediate", "--from-report", "report.json", "--yes"]);
    assert!(
        text(&out).contains("no longer at that line"),
        "{}",
        text(&out)
    );
    assert!(!repo.path(".env").exists());

    repo.report("../outside.py", 1, SECRET);
    let out = repo.run(&["scan", "--from-report", "report.json", "-f", "json"]);
    assert!(
        text(&out).contains("outside the working directory"),
        "{}",
        text(&out)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json["findings"].as_array().unwrap().is_empty());
}
