#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OLD_KEY: &str = "AKIAJ3F7Q2X9KD5MLR8W";
const NEW_KEY: &str = "AKIAIOSFODNN7NEWKEY1";
const NEW_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLENEWSECRET";

struct Env {
    repo: tempfile::TempDir,
    state: tempfile::TempDir,
    shim: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            repo: tempfile::tempdir().unwrap(),
            state: tempfile::tempdir().unwrap(),
            shim: tempfile::tempdir().unwrap(),
        };
        let replies = [
            (
                "get-access-key-last-used",
                r#"{"UserName":"bob","AccessKeyLastUsed":{"LastUsedDate":"2025-01-01T00:00:00+00:00","ServiceName":"s3","Region":"us-east-1"}}"#.to_string(),
            ),
            (
                "list-access-keys",
                format!(
                    r#"{{"AccessKeyMetadata":[{{"UserName":"bob","AccessKeyId":"{OLD_KEY}","Status":"Active"}}]}}"#
                ),
            ),
            (
                "create-access-key",
                format!(
                    r#"{{"AccessKey":{{"UserName":"bob","AccessKeyId":"{NEW_KEY}","Status":"Active","SecretAccessKey":"{NEW_SECRET}"}}}}"#
                ),
            ),
            ("update-access-key", String::new()),
            ("delete-access-key", String::new()),
        ];
        let d = env.shim.path();
        for (sub, body) in replies {
            fs::write(d.join(format!("{sub}.out")), body).unwrap();
        }
        let script = format!(
            "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nif [ -f \"{d}/$2.out\" ]; then cat \"{d}/$2.out\"; exit 0; fi\nexit 1\n",
            d = d.display()
        );
        fs::write(d.join("aws"), script).unwrap();
        fs::set_permissions(d.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();

        env.git(&["init", "-q"]);
        fs::write(
            env.repo.path().join("app.py"),
            format!("aws_access_key_id = \"{OLD_KEY}\"\n"),
        )
        .unwrap();
        env.git(&["add", "."]);
        env.git(&["commit", "-q", "-m", "init"]);
        env
    }

    fn git(&self, args: &[&str]) {
        let ok = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(self.repo.path())
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(PathBuf::from(env!("CARGO_BIN_EXE_sentris")))
            .args(args)
            .current_dir(self.repo.path())
            .env("SENTRIS_AWS_BIN", self.shim.path().join("aws"))
            .env("SENTRIS_STATE_DIR", self.state.path())
            .env_remove("AWS_ACCESS_KEY_ID")
            .output()
            .unwrap()
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.shim.path().join("calls.log")).unwrap_or_default()
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.repo.path().join(rel)).unwrap_or_default()
    }
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "not json ({e}): {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn rotate_fixed(env: &Env) -> String {
    let out = env.run(&["--json", "remediate", "app.py", "--rotate", "--yes"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    json(&out)["sessions"][0]["rotation_id"]
        .as_str()
        .expect("rotation_id in JSON")
        .to_string()
}

#[test]
fn rotate_leaves_old_key_active_and_stores_new_pair() {
    let env = Env::new();
    let id = rotate_fixed(&env);
    assert!(id.starts_with("rot_"));

    let app = env.read("app.py");
    assert!(!app.contains(OLD_KEY), "{app}");
    let dotenv = env.read(".env");
    assert!(
        dotenv.contains(&format!("AWS_ACCESS_KEY_ID={NEW_KEY}")),
        "{dotenv}"
    );
    assert!(
        dotenv.contains(&format!("AWS_SECRET_ACCESS_KEY={NEW_SECRET}")),
        "{dotenv}"
    );
    assert!(!dotenv.contains(OLD_KEY));

    let calls = env.calls();
    assert!(calls.contains("create-access-key"));
    assert!(
        !calls.contains("update-access-key"),
        "old key must stay active: {calls}"
    );
    assert!(!calls.contains("wJalr"), "secret in argv");

    let ledger = env.read(".sentris/rotation_ledger.json");
    assert!(
        ledger.contains("Stored") && !ledger.contains("wJalr"),
        "{ledger}"
    );

    let audit = env.run(&["--no-color", "audit", "--verify"]);
    assert!(audit.status.success());
    assert!(String::from_utf8_lossy(&audit.stdout).contains("Chain Integrity: PASS"));
    assert!(env
        .read(".sentris/audit_ledger.json")
        .contains("KeyRotated"));
}

#[test]
fn finish_is_refused_before_grace_then_forced_then_undone() {
    let env = Env::new();
    let id = rotate_fixed(&env);

    let refused = env.run(&["rotate", "finish", &id]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!env.calls().contains("update-access-key"));

    let forced = env.run(&["rotate", "finish", &id, "--force"]);
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(env
        .calls()
        .contains(&format!("--access-key-id {OLD_KEY} --status Inactive")));
    assert!(env
        .read(".sentris/audit_ledger.json")
        .contains("KeyDeactivated"));

    let undo = env.run(&["rotate", "undo", &id]);
    assert!(
        undo.status.success(),
        "{}",
        String::from_utf8_lossy(&undo.stderr)
    );
    let calls = env.calls();
    assert!(calls.contains(&format!("--access-key-id {OLD_KEY} --status Active")));
    assert!(calls.contains(&format!(
        "delete-access-key --user-name bob --access-key-id {NEW_KEY}"
    )));
}

#[test]
fn rotate_status_lists_the_rotation() {
    let env = Env::new();
    let id = rotate_fixed(&env);
    let out = env.run(&["--json", "rotate", "status"]);
    assert!(out.status.success());
    let v = json(&out);
    assert_eq!(v["rotations"][0]["id"], id.as_str());
    assert_eq!(v["rotations"][0]["state"], "Stored");
    assert!(!v.to_string().contains("wJalr"));
}

#[test]
fn rollback_of_a_rotated_session_points_at_rotate_undo() {
    let env = Env::new();
    let id = rotate_fixed(&env);
    let out = env.run(&["rollback"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&id) && text.contains("rotate undo"), "{text}");
    assert!(env.read("app.py").contains(OLD_KEY));
}

#[test]
fn dry_run_rotation_only_reads() {
    let env = Env::new();
    let out = env.run(&["--json", "remediate", "app.py", "--rotate", "--dry-run"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = env.calls();
    assert!(!calls.is_empty());
    for verb in ["create-", "update-", "delete-"] {
        assert!(!calls.contains(verb), "{calls}");
    }
    assert!(env.read("app.py").contains(OLD_KEY));
    assert!(!Path::new(&env.repo.path().join(".sentris/rotation_ledger.json")).exists());
}

#[test]
fn offline_rotation_is_refused_before_any_call() {
    let env = Env::new();
    let out = env.run(&["--offline", "remediate", "app.py", "--rotate", "--yes"]);
    assert!(!out.status.success());
    assert!(env.calls().is_empty());
    assert!(env.read("app.py").contains(OLD_KEY));
}

#[test]
fn unsupported_provider_rotate_changes_nothing() {
    let env = Env::new();
    fs::write(
        env.repo.path().join("pay.py"),
        concat!(
            "key = \"sk_live_",
            "51Nq8xT2LmV7pRz0aBcDeFgHiJk9WsYuXo3Zt4\"\n"
        ),
    )
    .unwrap();
    let out = env.run(&["remediate", "pay.py", "--rotate", "--yes"]);
    assert!(!out.status.success());
    assert!(env.read("pay.py").contains("sk_live_"));
    assert!(env.calls().is_empty());
}
