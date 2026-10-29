use serde_json::{json, Value};
use std::path::PathBuf;

use super::tools::{require_writes, text_result, workspace, ToolErr};
use crate::audit::{AuditAction, AuditLedger};
use crate::error::SentrisError;
use crate::rotator::{flow, rotator_for_rule, unix_now, RotationLedger, RotationState};

fn ledger_path() -> Result<PathBuf, ToolErr> {
    Ok(workspace()?.join(".sentris/rotation_ledger.json"))
}

fn internal(e: SentrisError) -> ToolErr {
    match e {
        SentrisError::Refused(msg) => (-32001, msg),
        other => (-32603, other.to_string()),
    }
}

fn finish_token(id: &str, state: RotationState) -> Result<String, ToolErr> {
    crate::keystore::mac_hex("mcp-confirm", format!("finish|{id}|{state:?}").as_bytes())
        .map(|m| m[..16].to_string())
        .map_err(internal)
}

pub(super) fn status() -> Result<Value, ToolErr> {
    let ledger = RotationLedger::load_from(&ledger_path()?).map_err(internal)?;
    let rotations: Vec<Value> = ledger
        .records
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "provider": r.provider,
                "principal": r.principal,
                "state": format!("{:?}", r.state),
                "old_key_id": r.old_key_id,
                "new_key_id": r.new_key_id,
                "grace_until": r.grace_until,
            })
        })
        .collect();
    Ok(text_result(json!({"rotations": rotations}), false))
}

/// Deactivates the old key of a stored rotation. `force` is deliberately not exposed to agents.
pub(super) fn finish(args: &Value) -> Result<Value, ToolErr> {
    let id = args.get("rotation_id").and_then(Value::as_str).ok_or((
        -32602,
        "Missing required argument 'rotation_id'".to_string(),
    ))?;
    let dry_run = args.get("dry_run").and_then(Value::as_bool).unwrap_or(true);
    let confirm = args.get("confirm").and_then(Value::as_str).unwrap_or("");
    if !dry_run {
        require_writes()?;
    }
    let path = ledger_path()?;
    let ledger = RotationLedger::load_from(&path).map_err(internal)?;
    let rec = ledger
        .get(id)
        .cloned()
        .ok_or((-32602, format!("Rotation '{id}' not found")))?;
    let token = finish_token(id, rec.state)?;
    if dry_run {
        return Ok(text_result(
            json!({
                "status": "preview",
                "rotation_id": id,
                "state": format!("{:?}", rec.state),
                "old_key_id": rec.old_key_id,
                "grace_until": rec.grace_until,
                "confirm_token": token,
                "note": "finish refuses inside the grace window or while the old key shows use since the rotation began; --force is only available on the CLI",
            }),
            false,
        ));
    }
    if !crate::keystore::ct_eq(confirm, &token) {
        return Err((
            -32602,
            "Missing or stale 'confirm': run with dry_run=true first and pass its confirm_token"
                .to_string(),
        ));
    }
    let rotator = rotator_for_rule(&rec.rule_id)
        .ok_or((-32603, format!("No rotator for rule '{}'", rec.rule_id)))?;
    flow::finish(rotator.as_ref(), &path, id, unix_now(), false).map_err(internal)?;
    record_deactivation(id, &rec.provider, &rec.old_key_id);
    Ok(text_result(
        json!({"status": "old_key_deactivated", "rotation_id": id, "old_key_id": rec.old_key_id}),
        false,
    ))
}

fn record_deactivation(id: &str, provider: &str, old_key_id: &str) {
    let Ok(root) = workspace() else { return };
    if let Ok(mut ledger) = AuditLedger::load_or_init(root.join(".sentris/audit_ledger.json")) {
        let _ = ledger.record_event(
            AuditAction::KeyDeactivated {
                rotation_id: id.to_string(),
                provider: provider.to_string(),
            },
            json!({"old_key_id": old_key_id, "via": "mcp"}),
        );
        let _ = ledger.save();
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::mcp::McpServer;
    use crate::rotator::{RotationLedger, RotationPlan, RotationRecord, RotationState};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const OLD_KEY: &str = "AKIAJ3F7Q2X9KD5MLR8W";

    struct Rig {
        ws: tempfile::TempDir,
        shim: tempfile::TempDir,
        _state: tempfile::TempDir,
    }

    impl Rig {
        fn new() -> Self {
            let tmp = || tempfile::tempdir().expect("tempdir");
            let (ws, shim, state) = (tmp(), tmp(), tmp());
            let d = shim.path();
            let replies = [
                ("get-access-key-last-used", r#"{"UserName":"bob","AccessKeyLastUsed":{"LastUsedDate":"2025-01-01T00:00:00+00:00","ServiceName":"s3","Region":"us-east-1"}}"#.to_string()),
                ("list-access-keys", format!(r#"{{"AccessKeyMetadata":[{{"AccessKeyId":"{OLD_KEY}","Status":"Active"}}]}}"#)),
            ];
            for (sub, body) in replies {
                std::fs::write(d.join(format!("{sub}.out")), body).unwrap();
            }
            let script = format!(
                "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nif [ -f \"{d}/$2.out\" ]; then cat \"{d}/$2.out\"; exit 0; fi\nexit 1\n",
                d = d.display()
            );
            std::fs::write(d.join("aws"), script).unwrap();
            std::fs::set_permissions(d.join("aws"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::fs::write(
                ws.path().join("app.py"),
                format!("aws_access_key_id = \"{OLD_KEY}\"\n"),
            )
            .unwrap();
            std::env::set_var("SENTRIS_WORKSPACE", ws.path());
            std::env::set_var("SENTRIS_AWS_BIN", d.join("aws"));
            std::env::set_var("SENTRIS_STATE_DIR", state.path());
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("SENTRIS_MCP_ALLOW_WRITES");
            Self {
                ws,
                shim,
                _state: state,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.shim.path().join("calls.log")).unwrap_or_default()
        }

        fn call(
            &self,
            name: &str,
            args: serde_json::Value,
        ) -> Result<serde_json::Value, (i32, String)> {
            McpServer::call_tool(Some(&json!({"name": name, "arguments": args})), false)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            for k in [
                "SENTRIS_WORKSPACE",
                "SENTRIS_AWS_BIN",
                "SENTRIS_STATE_DIR",
                "SENTRIS_MCP_ALLOW_WRITES",
            ] {
                std::env::remove_var(k);
            }
        }
    }

    fn payload(v: &serde_json::Value) -> serde_json::Value {
        serde_json::from_str(v["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::keystore::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn stored_rotation(rig: &Rig, created: u64, grace_until: u64) {
        let plan = RotationPlan {
            provider: "AWS".into(),
            rule_id: "aws-access-key-id".into(),
            principal: "bob".into(),
            old_key_id: OLD_KEY.into(),
            old_fingerprint: "fp".into(),
        };
        let mut rec = RotationRecord::new("rot_t", "env", &plan, created, 0);
        rec.grace_until = grace_until;
        rec.new_key_id = Some("AKIANEWNEWNEWNEWNEW1".into());
        let mut l = RotationLedger::default();
        l.insert(rec).unwrap();
        l.advance("rot_t", RotationState::Minted).unwrap();
        l.advance("rot_t", RotationState::Stored).unwrap();
        std::fs::create_dir_all(rig.ws.path().join(".sentris")).unwrap();
        l.save_to(&rig.ws.path().join(".sentris/rotation_ledger.json"))
            .unwrap();
    }

    #[test]
    fn rotate_preview_is_read_only_and_its_token_does_not_authorise_a_plain_write() {
        let _g = lock();
        let rig = Rig::new();
        let rotating = rig
            .call(
                "sentris_remediate_finding",
                json!({"file_path":"app.py","rotate":true}),
            )
            .unwrap();
        let p = payload(&rotating);
        assert_eq!(p["mode"], "provider_rotation");
        let rotate_token = p["confirm_token"].as_str().unwrap().to_string();
        let plain = rig
            .call("sentris_remediate_finding", json!({"file_path":"app.py"}))
            .unwrap();
        assert_ne!(
            payload(&plain)["confirm_token"].as_str().unwrap(),
            rotate_token
        );
        let calls = rig.calls();
        assert!(!calls.is_empty());
        for verb in ["create-", "update-", "delete-"] {
            assert!(!calls.contains(verb), "{calls}");
        }
    }

    #[test]
    fn rotate_write_with_a_non_rotating_token_makes_no_provider_call() {
        let _g = lock();
        let rig = Rig::new();
        let plain = rig
            .call("sentris_remediate_finding", json!({"file_path":"app.py"}))
            .unwrap();
        let token = payload(&plain)["confirm_token"]
            .as_str()
            .unwrap()
            .to_string();
        std::env::set_var("SENTRIS_MCP_ALLOW_WRITES", "1");
        let before = rig.calls();
        let err = rig
            .call(
                "sentris_remediate_finding",
                json!({"file_path":"app.py","rotate":true,"dry_run":false,"confirm":token}),
            )
            .unwrap_err();
        assert!(err.1.contains("confirm"), "{err:?}");
        assert_eq!(rig.calls(), before);
        assert!(std::fs::read_to_string(rig.ws.path().join("app.py"))
            .unwrap()
            .contains(OLD_KEY));
    }

    #[test]
    fn rotate_status_lists_rotations_without_secret_material() {
        let _g = lock();
        let rig = Rig::new();
        stored_rotation(&rig, 1_000, 2_000);
        let out = payload(&rig.call("sentris_rotate_status", json!({})).unwrap());
        assert_eq!(out["rotations"][0]["id"], "rot_t");
        assert_eq!(out["rotations"][0]["state"], "Stored");
        assert!(!out.to_string().contains("wJalr"));
    }

    #[test]
    fn rotate_finish_needs_writes_a_matching_token_and_obeys_the_grace_guard() {
        let _g = lock();
        let rig = Rig::new();
        stored_rotation(&rig, 1_000, u64::MAX / 2);
        let preview = payload(
            &rig.call("sentris_rotate_finish", json!({"rotation_id":"rot_t"}))
                .unwrap(),
        );
        assert_eq!(preview["status"], "preview");
        let token = preview["confirm_token"].as_str().unwrap().to_string();

        let no_writes = rig
            .call(
                "sentris_rotate_finish",
                json!({"rotation_id":"rot_t","dry_run":false,"confirm":token}),
            )
            .unwrap_err();
        assert!(no_writes.1.contains("disabled"), "{no_writes:?}");

        std::env::set_var("SENTRIS_MCP_ALLOW_WRITES", "1");
        let bad = rig
            .call(
                "sentris_rotate_finish",
                json!({"rotation_id":"rot_t","dry_run":false,"confirm":"nope"}),
            )
            .unwrap_err();
        assert!(bad.1.contains("confirm"), "{bad:?}");

        let refused = rig
            .call(
                "sentris_rotate_finish",
                json!({"rotation_id":"rot_t","dry_run":false,"confirm":token}),
            )
            .unwrap_err();
        assert!(refused.1.contains("Grace window"), "{refused:?}");
        assert!(!rig.calls().contains("update-access-key"));
    }
}
