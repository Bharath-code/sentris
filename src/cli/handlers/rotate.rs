use owo_colors::OwoColorize;

use super::{die, fail, print_json, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::{Cli, RotateSubcommand};
use crate::error::SentrisError;
use crate::rotator::flow;
use crate::rotator::timefmt::format_utc;
use crate::rotator::{rotator_for_rule, unix_now, RotationLedger, RotationRecord, Rotator};

/// A refusal is a policy outcome (exit 2), not a failure.
fn exit_for(context: &str, err: SentrisError) -> ! {
    match err {
        SentrisError::Refused(msg) => {
            eprintln!("{} {msg}", "REFUSED:".yellow().bold());
            std::process::exit(2)
        }
        other => die(context, other),
    }
}

fn load() -> (RotationLedger, std::path::PathBuf) {
    let path = RotationLedger::path();
    let ledger = RotationLedger::load_from(&path)
        .unwrap_or_else(|err| die("Failed to load rotation ledger", err));
    (ledger, path)
}

fn record_and_rotator(ledger: &RotationLedger, id: &str) -> (RotationRecord, Box<dyn Rotator>) {
    let rec = ledger.get(id).cloned().unwrap_or_else(|| {
        fail(&format!(
            "Rotation '{id}' not found. Run `sentris rotate status`."
        ))
    });
    let rotator = rotator_for_rule(&rec.rule_id)
        .unwrap_or_else(|| fail(&format!("No rotator for rule '{}'", rec.rule_id)));
    (rec, rotator)
}

pub fn handle_rotate(cli: &Cli, sub: RotateSubcommand) {
    let agent = cli.is_agent_mode();
    match sub {
        RotateSubcommand::Status => status(agent),
        RotateSubcommand::Finish {
            id,
            force,
            delete_old,
        } => finish(agent, &id, force, delete_old),
        RotateSubcommand::Undo { id } => undo(agent, &id),
    }
}

fn status(agent: bool) {
    let (ledger, _) = load();
    if agent {
        let rotations: Vec<_> = ledger
            .records
            .iter()
            .map(|r| {
                serde_json::json!({
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
        print_json(
            serde_json::json!({"ok": true, "command": "rotate status", "rotations": rotations}),
        );
        return;
    }
    if ledger.records.is_empty() {
        println!("No rotations recorded.");
    }
    for r in &ledger.records {
        println!(
            "{}  {:?}  {} ({})  old {} → new {}  grace until {}",
            r.id.bold(),
            r.state,
            r.provider,
            r.principal,
            r.old_key_id,
            r.new_key_id.as_deref().unwrap_or("-"),
            format_utc(r.grace_until)
        );
    }
}

fn finish(agent: bool, id: &str, force: bool, delete_old: bool) {
    let (ledger, path) = load();
    let (rec, rotator) = record_and_rotator(&ledger, id);
    if rec.state == crate::rotator::RotationState::Stored {
        flow::finish(rotator.as_ref(), &path, id, unix_now(), force)
            .unwrap_or_else(|err| exit_for("Rotation finish failed", err));
        record_audit_event(
            AuditAction::KeyDeactivated {
                rotation_id: id.to_string(),
                provider: rec.provider.clone(),
            },
            serde_json::json!({"old_key_id": rec.old_key_id, "forced": force}),
        );
    }
    if delete_old {
        flow::delete_old(rotator.as_ref(), &path, id)
            .unwrap_or_else(|err| exit_for("Deleting the old key failed", err));
    }
    if agent {
        print_json(
            serde_json::json!({"ok": true, "command": "rotate finish", "rotation_id": id, "deleted_old": delete_old}),
        );
    } else {
        println!(
            "{} old key {} is now inactive{}. Undo with `sentris rotate undo {id}`.",
            "✔".green(),
            rec.old_key_id,
            if delete_old { " and deleted" } else { "" }
        );
    }
}

fn undo(agent: bool, id: &str) {
    let (ledger, path) = load();
    let (rec, rotator) = record_and_rotator(&ledger, id);
    flow::undo(rotator.as_ref(), &path, id)
        .unwrap_or_else(|err| exit_for("Rotation undo failed", err));
    let session = format!("rm_{}", crate::model::short(&rec.old_fingerprint, 8));
    if agent {
        print_json(
            serde_json::json!({"ok": true, "command": "rotate undo", "rotation_id": id, "rollback_session": session}),
        );
    } else {
        println!(
            "{} rotation {id} undone: old key reactivated, new key deleted.",
            "✔".green()
        );
        println!("The source file still reads from the environment; restore it with `sentris rollback --session {session}`.");
    }
}
