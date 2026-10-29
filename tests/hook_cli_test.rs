#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const STRIPE: &str = concat!("sk_live_", "51Nq8xT2LmV7pRz0aBcDeFgHiJk9WsYuXo3Zt4");

fn hook(args: &[&str], stdin: &str) -> Output {
    hook_in(None, args, stdin)
}

fn hook_in(dir: Option<&std::path::Path>, args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_sentris")));
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .arg("hook")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The hook may stop reading early (oversize input) and close the pipe; that is not a test failure
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().unwrap()
}

fn event(v: serde_json::Value) -> String {
    v.to_string()
}

#[test]
fn prompt_with_a_secret_exits_2_and_names_the_rule_not_the_value() {
    let out = hook(
        &[],
        &event(serde_json::json!({
            "session_id": "s", "cwd": "/p", "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("use {STRIPE} for the test")
        })),
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stripe-secret-key"), "{err}");
    assert!(!err.contains("51Nq8x"), "{err}");
    assert!(out.stdout.is_empty());
}

#[test]
fn clean_prompt_exits_0_silently() {
    let out = hook(
        &[],
        &event(serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": "add a test"})),
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
}

#[test]
fn reading_dot_env_is_blocked_but_the_example_is_not() {
    let read = |p: &str| {
        hook(
            &[],
            &event(serde_json::json!({
                "hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": p}, "tool_use_id": "t"
            })),
        )
    };
    assert_eq!(read("/proj/.env").status.code(), Some(2));
    assert_eq!(read("/proj/.env.example").status.code(), Some(0));
}

#[test]
fn malformed_input_follows_the_fail_mode() {
    let open = hook(&[], "not json at all");
    assert_eq!(open.status.code(), Some(0));
    let closed = hook(&["--fail-closed"], "not json at all");
    assert_eq!(closed.status.code(), Some(2));
    assert!(!closed.stderr.is_empty());
}

#[test]
fn print_config_emits_valid_settings_json() {
    let out = hook(&["--print-config"], "");
    assert!(out.status.success());
    let cfg: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        cfg["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
        "sentris hook"
    );
}

#[test]
fn a_broken_repo_config_cannot_switch_the_guard_off() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(
        repo.path().join(".sentris.toml"),
        "[[rules]]\nrule_id = \"x\"\nname = \"x\"\ndescription = \"x\"\nseverity = \"HIGH\"\npattern = \"(\"\nmin_entropy = 0.0\n",
    )
    .unwrap();
    let out = hook_in(
        Some(repo.path()),
        &[],
        &event(serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("key {STRIPE}")
        })),
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("stripe-secret-key"));
}

#[test]
fn oversize_input_is_blocked_even_when_failing_open() {
    let pad = "a".repeat(9 * 1024 * 1024);
    let out = hook(
        &[],
        &event(serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": pad})),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("too large"));
}
