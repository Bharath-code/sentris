use owo_colors::OwoColorize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use super::{die, fail, print_json, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::Cli;
use crate::model::{Finding, ScanReport};
use crate::remediator::backend::SecretBackendFactory;
use crate::remediator::rollback::RollbackLedger;
use crate::remediator::Remediator;
use crate::rotator::RotationLedger;
use crate::scanner::Scanner;

pub fn handle_remediate(
    cli: &Cli,
    finding_id: Option<String>,
    dry_run: bool,
    yes: bool,
    backend: String,
    rotate: bool,
    all: bool,
) {
    let agent_mode = cli.is_agent_mode();
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let scan_target = scan_target_for(finding_id.as_deref());
    let report = scanner
        .scan_path(&scan_target)
        .unwrap_or_else(|err| die("Failed to scan target", err));

    if report.findings.is_empty() {
        print_clean(agent_mode);
        return;
    }

    let targets = select_targets(&report, finding_id.as_deref(), all);
    if targets.is_empty() {
        fail("Could not find matching finding to remediate.");
    }
    if !dry_run
        && !(yes || agent_mode)
        && !confirm_interactive_remediation(&targets, &scan_target, &backend)
    {
        return;
    }

    let remediator = Remediator::new();
    let sessions: Vec<_> = targets
        .iter()
        .map(|finding| {
            remediate_one(
                cli,
                &scanner,
                &remediator,
                finding,
                &backend,
                dry_run,
                rotate,
            )
        })
        .collect();

    if agent_mode {
        print_json(serde_json::json!({
            "ok": true,
            "command": "remediate",
            "backend": backend,
            "dry_run": dry_run,
            "rotate": rotate,
            "mock": !dry_run && SecretBackendFactory::from_name(&backend)
                .map(|b| b.is_mock())
                .unwrap_or(false),
            "remediated_count": sessions.len(),
            "sessions": sessions,
            "next_agent_actions": [
                "sentris scan . --json",
                "sentris rollback --json"
            ]
        }));
    } else if !all && report.findings.len() > 1 {
        println!(
            "{} {} additional secret(s) remain in target. Run with {} to batch-remediate all findings at once.",
            "ℹ️ ".cyan(),
            (report.findings.len() - 1).to_string().bold(),
            "--all".cyan().bold()
        );
    }
}

/// A finding id that is a real file or directory narrows the scan to it; anything else scans the cwd.
fn scan_target_for(finding_id: Option<&str>) -> PathBuf {
    match finding_id.map(Path::new) {
        Some(p) if p.is_file() || p.is_dir() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn print_clean(agent_mode: bool) {
    if agent_mode {
        print_json(serde_json::json!({
            "ok": true,
            "command": "remediate",
            "status": "clean",
            "remediated_count": 0,
            "sessions": []
        }));
    } else {
        println!(
            "{}",
            "✔ No findings detected to remediate. Target is clean!"
                .green()
                .bold()
        );
    }
}

fn matches_id(f: &Finding, id: &str) -> bool {
    f.rule_id == id
        || f.fingerprint.starts_with(id)
        || f.file_path == id
        || f.file_path.ends_with(id)
        || Path::new(&f.file_path) == Path::new(id)
}

fn select_targets<'a>(
    report: &'a ScanReport,
    finding_id: Option<&str>,
    all: bool,
) -> Vec<&'a Finding> {
    if all {
        return report.findings.iter().collect();
    }
    let preferred = match finding_id {
        Some(id) => report.findings.iter().find(|f| matches_id(f, id)),
        None => report
            .findings
            .iter()
            .find(|f| f.rule_id == "stripe-secret-key" || f.rule_id == "stripe-restricted-key"),
    };
    preferred.or(report.findings.first()).into_iter().collect()
}

/// Remediates one finding and returns its session record; any failure aborts the command.
fn remediate_one(
    cli: &Cli,
    scanner: &Scanner,
    remediator: &Remediator,
    finding: &Finding,
    backend: &str,
    dry_run: bool,
    rotate: bool,
) -> serde_json::Value {
    let content = fs::read_to_string(&finding.file_path).unwrap_or_else(|err| {
        die(
            &format!("Failed to read target file {}", finding.file_path),
            err,
        )
    });
    let mut raw_secret = scanner
        .resolve_finding_secret(&content, finding)
        .unwrap_or_else(|err| fail(&err.to_string()));
    let env_var_name = Remediator::resolve_env_var_name(finding, &raw_secret, backend);

    let result = remediator.remediate_finding_with_options(
        finding,
        raw_secret.as_str(),
        dry_run,
        Some(backend),
        cli.offline,
        rotate,
        cli.quiet || cli.is_agent_mode(),
    );
    Remediator::zeroize_secret_string(&mut raw_secret);
    let session_id = result.unwrap_or_else(|err| match err {
        crate::error::SentrisError::Refused(msg) => {
            eprintln!("{} {msg}", "REFUSED:".yellow().bold());
            process::exit(2)
        }
        other => die("Remediation failed", other),
    });
    let rotation_id = (rotate && !dry_run)
        .then(|| record_rotation_audit(finding))
        .flatten();

    record_audit_event(
        AuditAction::SecretRemediated {
            session_id: session_id.clone(),
            rule_id: finding.rule_id.clone(),
            backend: backend.to_string(),
        },
        serde_json::json!({
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "dry_run": dry_run,
        }),
    );
    serde_json::json!({
        "session_id": session_id,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "rule_id": finding.rule_id,
        "env_var_injected": env_var_name,
        "rotation_id": rotation_id,
    })
}

/// Records the rotation in the audit chain and returns its id.
fn record_rotation_audit(finding: &Finding) -> Option<String> {
    let ledger = RotationLedger::load().ok()?;
    let rec = ledger.active_for(&finding.fingerprint)?;
    record_audit_event(
        AuditAction::KeyRotated {
            rotation_id: rec.id.clone(),
            provider: rec.provider.clone(),
        },
        serde_json::json!({
            "principal": rec.principal,
            "old_key_id": rec.old_key_id,
            "new_key_id": rec.new_key_id,
            "backend": rec.backend,
        }),
    );
    Some(rec.id.clone())
}

fn confirm_interactive_remediation(
    targets: &[&Finding],
    scan_target: &Path,
    backend: &str,
) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        fail("Non-interactive terminal detected. Run with '--yes' to auto-approve remediation in scripts or CI/CD.");
    }

    print_plan(targets, scan_target, backend);
    print!("Proceed with live remediation? [y/N]: ");
    let _ = std::io::stdout().flush();

    let mut response = String::new();
    if std::io::stdin().read_line(&mut response).is_err() {
        eprintln!("\nOperation cancelled.");
        process::exit(0);
    }
    let trimmed = response.trim().to_lowercase();
    if trimmed != "y" && trimmed != "yes" {
        println!("{}", "Operation cancelled by user.".yellow());
        return false;
    }
    true
}

fn print_plan(targets: &[&Finding], scan_target: &Path, backend: &str) {
    println!();
    println!(
        "{}",
        "⚠️  Sentris Autonomous Remediation Confirmation"
            .yellow()
            .bold()
    );
    match targets {
        [finding] => {
            println!(
                "   Target:          {}:{}",
                finding.file_path.bold(),
                finding.line_number
            );
            println!("   Secret rule:     {}", finding.rule_id.cyan());
        }
        _ => println!(
            "   Targets:         {} secret finding(s) in {}",
            targets.len().to_string().bold(),
            scan_target.display().to_string().bold()
        ),
    }
    println!("   Backend:         {}", backend.cyan().bold());
    println!("   Planned actions: 1. Verify credential via provider API");
    println!("                    2. Create atomic local git backup branch");
    println!("                    3. Extract working credential (no rotation)");
    println!(
        "                    4. Store credential in {} backend",
        backend.cyan()
    );
    println!("                    5. Replace literal in code with environment variable");
    println!("                    6. Remind you to revoke the old key at the provider");
    println!("                    7. Record transaction in rollback ledger");
    println!();
}

pub fn handle_rollback(cli: &Cli, session: Option<String>) {
    let agent_mode = cli.is_agent_mode();
    let mut ledger =
        RollbackLedger::load().unwrap_or_else(|err| die("Failed to load rollback ledger", err));

    let target = if ledger.transactions.is_empty() {
        None
    } else {
        session.or_else(|| ledger.transactions.last().map(|t| t.session_id.clone()))
    };
    let Some(target_session) = target else {
        if agent_mode {
            print_json(serde_json::json!({
                "ok": true,
                "command": "rollback",
                "status": "no_sessions"
            }));
        } else {
            println!(
                "{}",
                "No active remediation sessions found in rollback ledger.".yellow()
            );
        }
        return;
    };

    let fingerprint = ledger
        .transactions
        .iter()
        .find(|t| t.session_id == target_session)
        .map(|t| t.secret_fingerprint.clone());
    let msg = ledger
        .revert(&target_session)
        .unwrap_or_else(|err| die("Rollback failed", err));
    let pending_rotation = fingerprint.and_then(|fp| {
        RotationLedger::load()
            .ok()?
            .active_for(&fp)
            .map(|r| r.id.clone())
    });
    if agent_mode {
        print_json(serde_json::json!({
            "ok": true,
            "command": "rollback",
            "session_id": target_session,
            "message": msg,
            "pending_rotation": pending_rotation
        }));
    } else {
        println!("{}", msg.green().bold());
        if let Some(id) = pending_rotation {
            println!(
                "{} rotation {id} is still active: its new key stays in your backend and the old key is still live. Run `sentris rotate undo {id}` to reverse it.",
                "ℹ️ ".cyan()
            );
        }
    }
}
