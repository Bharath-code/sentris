use owo_colors::OwoColorize;
use std::fs;
use std::process;

use crate::audit::{AuditAction, AuditLedger};
use crate::cli::Cli;
use crate::remediator::rollback::RollbackLedger;
use crate::remediator::Remediator;
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
    let scanner = match Scanner::new() {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "{} Failed to initialize scanner: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    };

    let scan_target = if let Some(id) = &finding_id {
        let p = std::path::Path::new(id);
        if p.is_file() || p.is_dir() {
            p.to_path_buf()
        } else {
            std::path::PathBuf::from(".")
        }
    } else {
        std::path::PathBuf::from(".")
    };

    let report = match scanner.scan_path(&scan_target) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{} Failed to scan target: {}", "ERROR:".red().bold(), err);
            process::exit(1);
        }
    };

    let effective_yes = yes || agent_mode;

    if report.findings.is_empty() {
        if agent_mode {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "command": "remediate",
                    "status": "clean",
                    "remediated_count": 0,
                    "sessions": []
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "{}",
                "✔ No findings detected to remediate. Target is clean!"
                    .green()
                    .bold()
            );
        }
        return;
    }

    let targets: Vec<&crate::model::Finding> = if all {
        report.findings.iter().collect()
    } else {
        let single = if let Some(id) = &finding_id {
            report
                .findings
                .iter()
                .find(|f| {
                    f.rule_id == *id
                        || f.fingerprint.starts_with(id)
                        || f.file_path == *id
                        || f.file_path.ends_with(id)
                        || std::path::Path::new(&f.file_path) == std::path::Path::new(id)
                })
                .or_else(|| report.findings.first())
        } else {
            report
                .findings
                .iter()
                .find(|f| f.rule_id == "stripe-secret-key" || f.rule_id == "stripe-restricted-key")
                .or_else(|| report.findings.first())
        };
        single.into_iter().collect()
    };

    if targets.is_empty() {
        eprintln!(
            "{} Could not find matching finding to remediate.",
            "ERROR:".red().bold()
        );
        process::exit(1);
    }

    if !dry_run
        && !effective_yes
        && !confirm_interactive_remediation(&targets, &scan_target, &backend)
    {
        return;
    }

    let remediator = Remediator::new();
    let mut completed_sessions = Vec::new();
    for finding in &targets {
        let content = match fs::read_to_string(&finding.file_path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!(
                    "{} Failed to read target file {}: {}",
                    "ERROR:".red().bold(),
                    finding.file_path,
                    err
                );
                process::exit(1);
            }
        };

        let mut raw_secret_owned = match scanner.resolve_finding_secret(&content, finding) {
            Ok(secret) => secret,
            Err(err) => {
                eprintln!("{} {}", "ERROR:".red().bold(), err);
                process::exit(1);
            }
        };
        let env_var_name = Remediator::resolve_env_var_name(finding, &raw_secret_owned, &backend);

        let result = remediator.remediate_finding_with_options(
            finding,
            raw_secret_owned.as_str(),
            dry_run,
            Some(&backend),
            cli.offline,
            rotate,
            cli.quiet || agent_mode,
        );
        Remediator::zeroize_secret_string(&mut raw_secret_owned);

        match result {
            Ok(session_id) => {
                completed_sessions.push(serde_json::json!({
                    "session_id": session_id,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "rule_id": finding.rule_id,
                    "env_var_injected": env_var_name,
                }));
                if let Ok(mut ledger) = AuditLedger::load_or_init(".sentris/audit_ledger.json") {
                    let _ = ledger.record_event(
                        AuditAction::SecretRemediated {
                            session_id,
                            rule_id: finding.rule_id.clone(),
                            backend: backend.clone(),
                        },
                        serde_json::json!({
                            "file_path": finding.file_path,
                            "line_number": finding.line_number,
                            "dry_run": dry_run,
                        }),
                    );
                    let _ = ledger.save();
                }
            }
            Err(err) => {
                eprintln!("{} Remediation failed: {}", "ERROR:".red().bold(), err);
                process::exit(1);
            }
        }
    }

    if agent_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "command": "remediate",
                "backend": backend,
                "dry_run": dry_run,
                "rotate": rotate,
                "mock": !dry_run && crate::remediator::backend::SecretBackendFactory::from_name(&backend)
                    .map(|b| b.is_mock())
                    .unwrap_or(false),
                "remediated_count": completed_sessions.len(),
                "sessions": completed_sessions,
                "next_agent_actions": [
                    "sentris scan . --json",
                    "sentris rollback --json"
                ]
            }))
            .unwrap_or_default()
        );
    } else if !all && report.findings.len() > 1 {
        println!(
            "{} {} additional secret(s) remain in target. Run with {} to batch-remediate all findings at once.",
            "ℹ️ ".cyan(),
            (report.findings.len() - 1).to_string().bold(),
            "--all".cyan().bold()
        );
    }
}

fn confirm_interactive_remediation(
    targets: &[&crate::model::Finding],
    scan_target: &std::path::Path,
    backend: &str,
) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{} Non-interactive terminal detected. Run with '--yes' to auto-approve remediation in scripts or CI/CD.",
            "ERROR:".red().bold()
        );
        process::exit(1);
    }

    println!();
    println!(
        "{}",
        "⚠️  Sentris Autonomous Remediation Confirmation"
            .yellow()
            .bold()
    );
    if targets.len() == 1 {
        let finding = targets[0];
        println!(
            "   Target:          {}:{}",
            finding.file_path.bold(),
            finding.line_number
        );
        println!("   Secret rule:     {}", finding.rule_id.cyan());
    } else {
        println!(
            "   Targets:         {} secret finding(s) in {}",
            targets.len().to_string().bold(),
            scan_target.display().to_string().bold()
        );
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

pub fn handle_rollback(cli: &Cli, session: Option<String>) {
    let agent_mode = cli.is_agent_mode();
    let mut ledger = match RollbackLedger::load() {
        Ok(l) => l,
        Err(err) => {
            eprintln!(
                "{} Failed to load rollback ledger: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    };

    if ledger.transactions.is_empty() {
        if agent_mode {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "command": "rollback",
                    "status": "no_sessions"
                }))
                .unwrap_or_default()
            );
        } else {
            println!(
                "{}",
                "No active remediation sessions found in rollback ledger.".yellow()
            );
        }
        return;
    }

    let target_session =
        session.unwrap_or_else(|| ledger.transactions.last().unwrap().session_id.clone());

    match ledger.revert(&target_session) {
        Ok(msg) => {
            if agent_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "command": "rollback",
                        "session_id": target_session,
                        "message": msg
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!("{}", msg.green().bold());
            }
        }
        Err(err) => {
            eprintln!("{} Rollback failed: {}", "ERROR:".red().bold(), err);
            process::exit(1);
        }
    }
}

pub fn handle_quarantine(cli: &Cli, finding_id: String, branch: Option<String>) {
    let is_agent_mode = cli.is_agent_mode();
    let scanner = match Scanner::new() {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "{} Failed to initialize scanner: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    };

    let report = match scanner.scan_git_history() {
        Ok(r) if !r.findings.is_empty() => r,
        _ => match scanner.scan_path(".") {
            Ok(r) => r,
            Err(err) => {
                eprintln!(
                    "{} Failed to scan directory: {}",
                    "ERROR:".red().bold(),
                    err
                );
                process::exit(1);
            }
        },
    };

    let finding = match report.findings.iter().find(|f| {
        f.rule_id == finding_id
            || f.fingerprint.starts_with(&finding_id)
            || f.file_path == finding_id
            || f.file_path.ends_with(&finding_id)
    }) {
        Some(f) => f,
        None => {
            eprintln!(
                "{} Could not find finding matching '{}'. Run 'sentris scan --git-history' to inspect findings.",
                "ERROR:".red().bold(),
                finding_id
            );
            process::exit(1);
        }
    };

    match crate::git::quarantine::QuarantineManager::quarantine_finding(
        finding,
        branch.as_deref(),
        None,
    ) {
        Ok(report) => {
            if is_agent_mode {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "command": "quarantine",
                        "session_id": report.session_id,
                        "target_file": report.target_file,
                        "line_number": report.line_number,
                        "rule_id": report.rule_id,
                        "commit_hash": report.commit_hash,
                        "branch_name": report.branch_name,
                        "playbook_path": report.playbook_path
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!();
                println!(
                    "{} {}",
                    "🛡️  Sentris Zone 3 Quarantine Created:".cyan().bold(),
                    report.session_id.bold()
                );
                println!(
                    "Target File: {}:{}",
                    report.target_file.bold(),
                    report.line_number
                );
                println!("Rule ID:     {}", report.rule_id.yellow());
                if let Some(hash) = &report.commit_hash {
                    println!("Commit:      {}", hash.dimmed());
                }
                println!("Branch:      {}", report.branch_name.green().bold());
                println!(
                    "Playbook:    {}",
                    report.playbook_path.display().to_string().cyan()
                );
                println!();
                println!("{}", "⚠️  Safety Notice:".yellow().bold());
                println!("Never run 'git push --force' without team coordination.");
                println!("Review the step-by-step scrub guide at:");
                println!("  👉 {}", report.playbook_path.display().to_string().bold());
                println!();
            }
            if let Ok(mut ledger) = AuditLedger::load_or_init(".sentris/audit_ledger.json") {
                let _ = ledger.record_event(
                    AuditAction::QuarantineCreated {
                        finding_id: report.session_id.clone(),
                        branch: report.branch_name.clone(),
                    },
                    serde_json::json!({
                        "target_file": report.target_file,
                        "line_number": report.line_number,
                        "rule_id": report.rule_id,
                    }),
                );
                let _ = ledger.save();
            }
        }
        Err(err) => {
            eprintln!(
                "{} Failed to quarantine finding: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    }
}
