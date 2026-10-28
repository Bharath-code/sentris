use owo_colors::OwoColorize;
use std::fs;
use std::path::PathBuf;
use std::process;

use crate::audit::{AuditAction, AuditLedger};
use crate::cli::{BaselineSubcommand, Cli};
use crate::detector::baseline::BaselineFile;
use crate::git::GitManager;
use crate::model::Severity;
use crate::remediator::Remediator;
use crate::scanner::Scanner;

pub fn handle_review(cli: &Cli, path: PathBuf, min_severity: Option<Severity>) {
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

    let mut report = match scanner.scan_path(&path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!(
                "{} Failed to scan directory: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    };

    if let Some(min_sev) = min_severity {
        report.findings.retain(|f| f.severity >= min_sev);
    }

    let findings_snapshot = report.findings.clone();
    match crate::tui::run_interactive_review(report.findings) {
        Ok(Some(crate::tui::TuiAction::Remediate(idx))) => {
            println!(
                "{}",
                "✔ Initiating autonomous remediation workflow for selected finding..."
                    .green()
                    .bold()
            );
            if let Some(finding) = findings_snapshot.get(idx) {
                if let Ok(content) = fs::read_to_string(&finding.file_path) {
                    let lines: Vec<&str> = content.lines().collect();
                    if finding.line_number > 0 && finding.line_number <= lines.len() {
                        let target_line = lines[finding.line_number - 1];
                        let raw_secret = scanner
                            .extract_raw_secret(target_line, &finding.rule_id)
                            .unwrap_or_else(|| target_line.trim().to_string());
                        let remediator = Remediator::new();
                        let _ = remediator.remediate_finding(
                            finding,
                            &raw_secret,
                            false,
                            Some("env"),
                            cli.offline,
                        );
                    }
                }
            }
        }
        Ok(Some(crate::tui::TuiAction::AddToBaseline(idx))) => {
            if let Some(finding) = findings_snapshot.get(idx) {
                let baseline_path = std::path::Path::new(".sentris-baseline.json");
                let commit = GitManager::get_head_commit().ok().flatten();
                let mut base_file = BaselineFile::load_from_path(baseline_path)
                    .unwrap_or_else(|_| BaselineFile::from_findings(&[], commit.clone()));
                base_file.add_finding(finding);
                let _ = base_file.save_to_path(baseline_path);
            }
            println!(
                "{}",
                "✔ Finding recorded into .sentris-baseline.json snapshot.".green()
            );
        }
        Ok(Some(crate::tui::TuiAction::IgnoreFinding(idx))) => {
            if let Some(finding) = findings_snapshot.get(idx) {
                if let Ok(content) = fs::read_to_string(&finding.file_path) {
                    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                    if finding.line_number > 0 && finding.line_number <= lines.len() {
                        let ext = std::path::Path::new(&finding.file_path)
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_lowercase();
                        let comment_suffix = match ext.as_str() {
                            "py" | "sh" | "bash" | "zsh" | "rb" | "yml" | "yaml" | "toml"
                            | "env" => " # sentris-ignore",
                            _ => " // sentris-ignore",
                        };
                        if !lines[finding.line_number - 1].contains("sentris-ignore") {
                            lines[finding.line_number - 1].push_str(comment_suffix);
                            let _ =
                                fs::write(&finding.file_path, format!("{}\n", lines.join("\n")));
                        }
                    }
                }
            }
            println!(
                "{}",
                "✔ Inline 'sentris-ignore' suppression applied to finding.".yellow()
            );
        }
        Ok(None) => {}
        Err(err) => {
            eprintln!("{} TUI review error: {}", "ERROR:".red().bold(), err);
            process::exit(1);
        }
    }
}

pub fn handle_baseline(subcommand: BaselineSubcommand) {
    match subcommand {
        BaselineSubcommand::Record { path, output } => {
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

            let report = match scanner.scan_path(&path) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!(
                        "{} Failed to scan directory: {}",
                        "ERROR:".red().bold(),
                        err
                    );
                    process::exit(1);
                }
            };

            let git_commit = GitManager::get_head_commit().ok().flatten();
            let baseline = BaselineFile::from_findings(&report.findings, git_commit.clone());
            if let Err(err) = baseline.save_to_path(&output) {
                eprintln!(
                    "{} Failed to save baseline to {}: {}",
                    "ERROR:".red().bold(),
                    output.display(),
                    err
                );
                process::exit(1);
            }

            println!(
                "{} Recorded {} findings into baseline snapshot at {}",
                "✔".green().bold(),
                baseline.findings.len(),
                output.display().to_string().cyan().bold()
            );

            if let Ok(mut ledger) = AuditLedger::load_or_init(".sentris/audit_ledger.json") {
                let _ = ledger.record_event(
                    AuditAction::BaselineRecorded {
                        entries_count: baseline.findings.len(),
                        git_commit,
                    },
                    serde_json::json!({
                        "output_file": output.to_string_lossy(),
                    }),
                );
                let _ = ledger.save();
            }
        }
    }
}
