#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const KEY: &str = "AKIAJ5Q7X2M9R4T6W8YB";
const STRIPE: &str = concat!("sk_live_", "51Nq8xT2LmV7pRz0aBcDeFgHiJk9WsYuXo3Zt4");

/// Three IPs, four events, all within the last few days so the 90-day query window always covers them.
fn fixture_events() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ev = |age_days: u64, ip: &str, name: &str| {
        let at = now - age_days * 86_400;
        let inner = serde_json::json!({
            "eventTime": at, "eventSource": "s3.amazonaws.com", "eventName": name,
            "awsRegion": "us-east-1", "sourceIPAddress": ip, "userAgent": "aws-cli/2.15",
        })
        .to_string();
        serde_json::json!({"EventName": name, "EventTime": at, "CloudTrailEvent": inner})
    };
    serde_json::json!({"Events": [
        ev(1, "203.0.113.10", "ListBuckets"),
        ev(2, "203.0.113.10", "ListBuckets"),
        ev(3, "198.51.100.7", "GetCallerIdentity"),
        ev(4, "192.0.2.55", "DescribeInstances"),
    ]})
    .to_string()
}

struct Env {
    repo: tempfile::TempDir,
    shim: tempfile::TempDir,
}

impl Env {
    fn new(source: &str) -> Self {
        let env = Self {
            repo: tempfile::tempdir().unwrap(),
            shim: tempfile::tempdir().unwrap(),
        };
        let d = env.shim.path();
        fs::write(d.join("lookup-events.out"), fixture_events()).unwrap();
        let script = format!(
            "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nif [ -f \"{d}/$2.out\" ]; then cat \"{d}/$2.out\"; exit 0; fi\nexit 1\n",
            d = d.display()
        );
        fs::write(d.join("aws"), script).unwrap();
        fs::set_permissions(d.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();

        env.git(&["init", "-q"]);
        fs::write(env.repo.path().join("app.py"), source).unwrap();
        env.git(&["add", "."]);
        env.git(&["commit", "-q", "-m", "init"]);
        env
    }

    fn git(&self, args: &[&str]) {
        let ok = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(self.repo.path())
            .env("GIT_AUTHOR_DATE", "2026-10-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-10-01T00:00:00Z")
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_sentris")));
        c.current_dir(self.repo.path())
            .env("SENTRIS_AWS_BIN", self.shim.path().join("aws"))
            .env_remove("AWS_ACCESS_KEY_ID");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    fn aws_calls(&self) -> String {
        fs::read_to_string(self.shim.path().join("calls.log")).unwrap_or_default()
    }

    fn audit_ledger(&self) -> String {
        fs::read_to_string(self.repo.path().join(".sentris/audit_ledger.json")).unwrap_or_default()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn aws_env() -> Env {
    Env::new(&format!("aws_access_key_id = \"{KEY}\"\n"))
}

#[test]
fn json_report_flags_unknown_ips_and_audits_without_the_key() {
    let env = aws_env();
    let out = env.run(&["--json", "investigate", "--known-ip", "203.0.113.10"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["supported"], true);
    assert_eq!(v["usage"]["event_count"], 4);
    let flagged = v["usage"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["unknown_ip"] == true)
        .count();
    assert_eq!(flagged, 2);
    assert!(v["exposure"]["note"]
        .as_str()
        .unwrap()
        .contains("not the push time"));
    assert!(!stdout(&out).contains(KEY));

    let calls = env.aws_calls();
    assert!(
        calls
            .lines()
            .all(|l| l.contains("cloudtrail lookup-events")),
        "{calls}"
    );
    assert!(!calls.contains(KEY) || calls.contains(&format!("AttributeValue={KEY}")));
    let ledger = env.audit_ledger();
    assert!(ledger.contains("InvestigationRun") && !ledger.contains(KEY));
    assert!(env.run(&["audit", "--verify"]).status.success());
}

#[test]
fn human_output_never_says_safe_and_states_limits() {
    let env = aws_env();
    let out = stdout(&env.run(&["investigate"]));
    assert!(
        out.contains("management events only, last 90 days"),
        "{out}"
    );
    assert!(!out.to_lowercase().contains("safe"));
}

#[test]
fn unsupported_provider_exits_zero_and_skips_aws() {
    let env = Env::new(&format!("key = \"{STRIPE}\"\n"));
    let out = env.run(&["investigate"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no forensics for stripe-secret-key yet"));
    assert!(env.aws_calls().is_empty());
    assert!(!env.audit_ledger().contains("InvestigationRun"));
}

#[test]
fn mcp_tool_returns_the_same_json_as_the_cli() {
    let env = aws_env();
    let cli: serde_json::Value = serde_json::from_str(&stdout(&env.run(&[
        "--json",
        "investigate",
        "--known-ip",
        "203.0.113.10",
    ])))
    .unwrap();

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sentris_investigate","arguments":{"known_ips":["203.0.113.10"]}}}"#;
    let mut child = env
        .cmd()
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{req}").unwrap();
    let out = child.wait_with_output().unwrap();
    let resp: serde_json::Value =
        serde_json::from_str(stdout(&out).lines().next().unwrap()).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let (mut mcp, mut cli): (serde_json::Value, serde_json::Value) =
        (serde_json::from_str(text).unwrap(), cli);
    // the scan root differs (confined absolute path vs "."), so the path spelling does too
    // and the 90-day window start is derived from the clock at call time
    for v in [&mut mcp, &mut cli] {
        v["finding"]["file_path"] = serde_json::Value::Null;
        v["usage"]["since"] = serde_json::Value::Null;
    }
    assert_eq!(mcp, cli);
}
