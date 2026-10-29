use owo_colors::OwoColorize;
use std::fs;
use std::path::{Path, PathBuf};

use super::{die, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::{BaselineSubcommand, Cli};
use crate::detector::baseline::BaselineFile;
use crate::git::GitManager;
use crate::model::{Finding, Severity};
use crate::remediator::Remediator;
use crate::scanner::Scanner;
use crate::tui::TuiAction;

pub fn handle_review(cli: &Cli, path: PathBuf, min_severity: Option<Severity>) {
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let mut report = scanner
        .scan_path(&path)
        .unwrap_or_else(|err| die("Failed to scan directory", err));
    if let Some(min_sev) = min_severity {
        report.findings.retain(|f| f.severity >= min_sev);
    }

    let findings = report.findings.clone();
    match crate::tui::run_interactive_review(report.findings) {
        Ok(Some(TuiAction::Remediate(idx))) => remediate_selected(cli, &scanner, findings.get(idx)),
        Ok(Some(TuiAction::AddToBaseline(idx))) => add_to_baseline(findings.get(idx)),
        Ok(Some(TuiAction::IgnoreFinding(idx))) => ignore_inline(findings.get(idx)),
        Ok(None) => {}
        Err(err) => die("TUI review error", err),
    }
}

/// The finding's source line, if the file is readable and the line still exists.
fn source_line(finding: &Finding) -> Option<String> {
    let content = fs::read_to_string(&finding.file_path).ok()?;
    let index = finding.line_number.checked_sub(1)?;
    content.lines().nth(index).map(str::to_string)
}

fn remediate_selected(cli: &Cli, scanner: &Scanner, finding: Option<&Finding>) {
    println!(
        "{}",
        "✔ Initiating autonomous remediation workflow for selected finding..."
            .green()
            .bold()
    );
    let Some(finding) = finding else { return };
    let Some(target_line) = source_line(finding) else {
        return;
    };
    let raw_secret = scanner
        .extract_raw_secret(&target_line, &finding.rule_id)
        .unwrap_or_else(|| target_line.trim().to_string());
    let _ =
        Remediator::new().remediate_finding(finding, &raw_secret, false, Some("env"), cli.offline);
}

fn add_to_baseline(finding: Option<&Finding>) {
    if let Some(finding) = finding {
        let baseline_path = Path::new(".sentris-baseline.json");
        let commit = GitManager::get_head_commit().ok().flatten();
        let mut base_file = BaselineFile::load_from_path(baseline_path)
            .unwrap_or_else(|_| BaselineFile::from_findings(&[], commit));
        base_file.add_finding(finding);
        let _ = base_file.save_to_path(baseline_path);
    }
    println!(
        "{}",
        "✔ Finding recorded into .sentris-baseline.json snapshot.".green()
    );
}

fn ignore_comment(file_path: &str) -> &'static str {
    let ext = Path::new(file_path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "py" | "sh" | "bash" | "zsh" | "rb" | "yml" | "yaml" | "toml" | "env" => {
            " # sentris-ignore"
        }
        _ => " // sentris-ignore",
    }
}

fn ignore_inline(finding: Option<&Finding>) {
    if let Some(finding) = finding {
        suppress_line(finding);
    }
    println!(
        "{}",
        "✔ Inline 'sentris-ignore' suppression applied to finding.".yellow()
    );
}

fn suppress_line(finding: &Finding) {
    let Ok(content) = fs::read_to_string(&finding.file_path) else {
        return;
    };
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let Some(line) = finding
        .line_number
        .checked_sub(1)
        .and_then(|i| lines.get_mut(i))
    else {
        return;
    };
    if !line.contains("sentris-ignore") {
        line.push_str(ignore_comment(&finding.file_path));
        let _ = fs::write(&finding.file_path, format!("{}\n", lines.join("\n")));
    }
}

pub fn handle_baseline(subcommand: BaselineSubcommand) {
    let BaselineSubcommand::Record { path, output } = subcommand;
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let report = scanner
        .scan_path(&path)
        .unwrap_or_else(|err| die("Failed to scan directory", err));

    let git_commit = GitManager::get_head_commit().ok().flatten();
    let baseline = BaselineFile::from_findings(&report.findings, git_commit.clone());
    if let Err(err) = baseline.save_to_path(&output) {
        die(
            &format!("Failed to save baseline to {}", output.display()),
            err,
        );
    }
    println!(
        "{} Recorded {} findings into baseline snapshot at {}",
        "✔".green().bold(),
        baseline.findings.len(),
        output.display().to_string().cyan().bold()
    );
    record_audit_event(
        AuditAction::BaselineRecorded {
            entries_count: baseline.findings.len(),
            git_commit,
        },
        serde_json::json!({ "output_file": output.to_string_lossy() }),
    );
}
