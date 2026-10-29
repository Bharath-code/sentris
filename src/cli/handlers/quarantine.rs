use owo_colors::OwoColorize;

use super::{die, fail, print_json, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::Cli;
use crate::git::quarantine::{QuarantineManager, QuarantineReport};
use crate::model::{Finding, ScanReport};
use crate::scanner::Scanner;

pub fn handle_quarantine(cli: &Cli, finding_id: String, branch: Option<String>) {
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let report = scan_for_quarantine(&scanner);
    let finding = find_finding(&report, &finding_id).unwrap_or_else(|| {
        fail(&format!(
            "Could not find finding matching '{finding_id}'. Run 'sentris scan --git-history' to inspect findings."
        ))
    });

    let created = QuarantineManager::quarantine_finding(finding, branch.as_deref(), None)
        .unwrap_or_else(|err| die("Failed to quarantine finding", err));
    if cli.is_agent_mode() {
        print_json(serde_json::json!({
            "ok": true,
            "command": "quarantine",
            "session_id": created.session_id,
            "target_file": created.target_file,
            "line_number": created.line_number,
            "rule_id": created.rule_id,
            "commit_hash": created.commit_hash,
            "branch_name": created.branch_name,
            "playbook_path": created.playbook_path
        }));
    } else {
        print_quarantine(&created);
    }
    record_audit_event(
        AuditAction::QuarantineCreated {
            finding_id: created.session_id.clone(),
            branch: created.branch_name.clone(),
        },
        serde_json::json!({
            "target_file": created.target_file,
            "line_number": created.line_number,
            "rule_id": created.rule_id,
        }),
    );
}

/// History first (that is where quarantine matters); fall back to the working tree.
fn scan_for_quarantine(scanner: &Scanner) -> ScanReport {
    match scanner.scan_git_history() {
        Ok(r) if !r.findings.is_empty() => r,
        _ => scanner
            .scan_path(".")
            .unwrap_or_else(|err| die("Failed to scan directory", err)),
    }
}

fn find_finding<'a>(report: &'a ScanReport, id: &str) -> Option<&'a Finding> {
    report.findings.iter().find(|f| {
        f.rule_id == id
            || f.fingerprint.starts_with(id)
            || f.file_path == id
            || f.file_path.ends_with(id)
    })
}

fn print_quarantine(report: &QuarantineReport) {
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
