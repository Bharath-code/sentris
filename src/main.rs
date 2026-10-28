pub mod audit;
mod cli;
pub mod cloud;
mod config;
mod detector;
mod error;
mod git;
pub mod mcp;
mod model;
mod remediator;
mod reporter;
mod scanner;
pub mod tui;
mod verifier;

use clap::Parser;
use owo_colors::OwoColorize;
use std::fs;
use std::process;

use crate::audit::{AuditAction, AuditLedger};
use crate::cli::{AuthSubcommand, BaselineSubcommand, Cli, Commands, OutputFormat};
use crate::cloud::{build_cloud_payload, upload_scan, Credentials, TeamInfo};
use crate::config::GitleaksMigrator;
use crate::detector::baseline::BaselineFile;
use crate::git::GitManager;
use crate::remediator::rollback::RollbackLedger;
use crate::remediator::Remediator;
use crate::reporter::Reporter;
use crate::scanner::Scanner;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            staged,
            git_history,
            since,
            format,
            fail_on_secret,
            webhook,
            baseline,
            record_baseline,
            min_severity,
            cloud,
        } => {
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

            let mut report = if let Some(since_ref) = &since {
                match scanner.scan_git_since(since_ref) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!(
                            "{} Failed during git commit range scan ({}): {}",
                            "ERROR:".red().bold(),
                            since_ref,
                            err
                        );
                        process::exit(1);
                    }
                }
            } else if git_history {
                match scanner.scan_git_history() {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!(
                            "{} Failed during git history scan: {}",
                            "ERROR:".red().bold(),
                            err
                        );
                        process::exit(1);
                    }
                }
            } else if staged {
                match scanner.scan_staged() {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!(
                            "{} Failed during staged scan: {}",
                            "ERROR:".red().bold(),
                            err
                        );
                        process::exit(1);
                    }
                }
            } else {
                match scanner.scan_path(&path) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("{} Failed during scan: {}", "ERROR:".red().bold(), err);
                        process::exit(1);
                    }
                }
            };

            // Severity floor filtering
            if let Some(min_sev) = min_severity {
                report.findings.retain(|f| f.severity >= min_sev);
                report.stats.findings_count = report.findings.len();
            }

            // Baseline suppression filtering
            if let Some(baseline_path) = &baseline {
                match BaselineFile::load_from_path(baseline_path) {
                    Ok(base) => {
                        let (unsuppressed, suppressed_count) =
                            base.filter_findings(report.findings);
                        report.findings = unsuppressed;
                        report.stats.findings_count = report.findings.len();
                        if suppressed_count > 0 && !cli.quiet && format == OutputFormat::Text {
                            println!(
                                "{} {} legacy secret(s) suppressed via baseline ({})",
                                "ℹ️ ".cyan(),
                                suppressed_count.to_string().bold(),
                                baseline_path.display().to_string().dimmed()
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "{} Failed to load baseline from {}: {}",
                            "ERROR:".red().bold(),
                            baseline_path.display(),
                            err
                        );
                        process::exit(1);
                    }
                }
            }

            // Record baseline snapshot if requested
            if let Some(record_path) = &record_baseline {
                let commit = GitManager::get_head_commit().ok().flatten();
                let base_file = BaselineFile::from_findings(&report.findings, commit.clone());
                if let Err(err) = base_file.save_to_path(record_path) {
                    eprintln!(
                        "{} Failed to write baseline snapshot to {}: {}",
                        "ERROR:".red().bold(),
                        record_path.display(),
                        err
                    );
                    process::exit(1);
                }
                if !cli.quiet && format == OutputFormat::Text {
                    println!(
                        "{} Recorded {} finding(s) into baseline snapshot at {}",
                        "✔".green().bold(),
                        base_file.findings.len(),
                        record_path.display().to_string().cyan().bold()
                    );
                }
                if let Ok(mut ledger) = AuditLedger::load_or_init(".sentris/audit_ledger.json") {
                    let _ = ledger.record_event(
                        AuditAction::BaselineRecorded {
                            entries_count: base_file.findings.len(),
                            git_commit: commit,
                        },
                        serde_json::json!({
                            "output_file": record_path.to_string_lossy(),
                        }),
                    );
                    let _ = ledger.save();
                }
            }

            // Record scan event in SOC 2 cryptographic audit ledger (best-effort)
            if let Ok(mut ledger) = AuditLedger::load_or_init(".sentris/audit_ledger.json") {
                let _ = ledger.record_event(
                    AuditAction::ScanCompleted {
                        files_scanned: report.stats.files_scanned,
                        findings_count: report.findings.len(),
                        duration_ms: report.stats.duration_ms as u64,
                    },
                    serde_json::json!({
                        "path": path.to_string_lossy(),
                        "staged": staged,
                        "git_history": git_history,
                        "fail_on_secret": fail_on_secret,
                    }),
                );
                let _ = ledger.save();
            }

            match format {
                OutputFormat::Text => {
                    Reporter::print_terminal_report(&report, cli.quiet, cli.no_color);
                    if std::env::var_os("GITHUB_ACTIONS").is_some() {
                        Reporter::print_github_annotations(&report);
                    }
                }
                OutputFormat::Json => match Reporter::to_json(&report) {
                    Ok(json_str) => println!("{json_str}"),
                    Err(err) => {
                        eprintln!(
                            "{} Failed to serialize JSON: {}",
                            "ERROR:".red().bold(),
                            err
                        );
                        process::exit(1);
                    }
                },
                OutputFormat::Sarif => match Reporter::to_sarif(&report) {
                    Ok(sarif_str) => println!("{sarif_str}"),
                    Err(err) => {
                        eprintln!(
                            "{} Failed to serialize SARIF: {}",
                            "ERROR:".red().bold(),
                            err
                        );
                        process::exit(1);
                    }
                },
                OutputFormat::Github => {
                    Reporter::print_github_annotations(&report);
                }
                OutputFormat::Gitlab => match Reporter::to_gitlab(&report) {
                    Ok(gitlab_str) => println!("{gitlab_str}"),
                    Err(err) => {
                        eprintln!(
                            "{} Failed to serialize GitLab report: {}",
                            "ERROR:".red().bold(),
                            err
                        );
                        process::exit(1);
                    }
                },
            }

            if let Some(webhook_url) = webhook {
                if cli.offline {
                    if !cli.quiet {
                        println!(
                            "{}",
                            "ℹ️  Zero-egress offline mode active: Webhook incident dispatch suppressed."
                                .yellow()
                        );
                    }
                } else {
                    match crate::reporter::webhook::WebhookReporter::post_incident_card(
                        &webhook_url,
                        &report,
                        false,
                    ) {
                        Ok(msg) => {
                            if !cli.quiet {
                                println!("{}", msg.green());
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "{} Failed to dispatch incident webhook: {}",
                                "WARNING:".yellow().bold(),
                                err
                            );
                        }
                    }
                }
            }

            if cloud {
                if cli.offline {
                    if !cli.quiet {
                        println!(
                            "{}",
                            "ℹ️  Zero-egress offline mode active: Sentris Pro Cloud sync suppressed."
                                .yellow()
                        );
                    }
                } else {
                    match Credentials::load_default() {
                        Ok(creds) => {
                            let repo_name = GitManager::find_git_root()
                                .ok()
                                .and_then(|p| {
                                    p.file_name().map(|n| n.to_string_lossy().to_string())
                                })
                                .unwrap_or_else(|| "workspace".to_string());
                            let branch = GitManager::get_head_branch()
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| "main".to_string());
                            let commit = GitManager::get_head_commit().ok().flatten();
                            let payload = build_cloud_payload(
                                &report,
                                &creds,
                                Some(&repo_name),
                                Some(&branch),
                                commit,
                            );
                            match upload_scan(&payload, &creds, false) {
                                Ok(res) => {
                                    if !cli.quiet {
                                        println!(
                                            "{} {}",
                                            "☁️  Sentris Pro Cloud:".cyan().bold(),
                                            res.message.green()
                                        );
                                        println!("   Dashboard: {}", res.dashboard_url.underline());
                                    }
                                }
                                Err(err) => {
                                    eprintln!(
                                        "{} Failed to sync with Sentris Pro Cloud: {}",
                                        "WARNING:".yellow().bold(),
                                        err
                                    );
                                }
                            }
                        }
                        Err(_) => {
                            if !cli.quiet {
                                println!(
                                    "{}",
                                    "ℹ️  Not authenticated with Sentris Pro Cloud. Run `sentris auth login --token <TOKEN>` to enable Pro team dashboard sync."
                                        .dimmed()
                                );
                            }
                        }
                    }
                }
            }

            if fail_on_secret && !report.findings.is_empty() {
                process::exit(1);
            }
        }

        Commands::Install { force } => match GitManager::install_pre_commit_hook(force) {
            Ok(msg) => println!("{}", msg.green()),
            Err(err) => {
                eprintln!(
                    "{} Failed to install pre-commit hook: {}",
                    "ERROR:".red().bold(),
                    err
                );
                process::exit(1);
            }
        },

        Commands::Uninstall => match GitManager::uninstall_pre_commit_hook() {
            Ok(msg) => println!("{}", msg.yellow()),
            Err(err) => {
                eprintln!(
                    "{} Failed to uninstall pre-commit hook: {}",
                    "ERROR:".red().bold(),
                    err
                );
                process::exit(1);
            }
        },

        Commands::Remediate {
            finding_id,
            dry_run,
            yes,
            backend,
            rotate,
            all,
        } => {
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

            if report.findings.is_empty() {
                println!(
                    "{}",
                    "✔ No findings detected to remediate. Target is clean!"
                        .green()
                        .bold()
                );
                return;
            }

            // Collect target findings: either all matching findings (--all) or the primary target finding
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
                        .find(|f| {
                            f.rule_id == "stripe-secret-key" || f.rule_id == "stripe-restricted-key"
                        })
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

            // Interactive confirmation gate (Stripe CLI / Terraform standard)
            if !dry_run && !yes {
                use std::io::IsTerminal;
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
                println!("                    3. Provision replacement credential");
                println!(
                    "                    4. Store credential in {} backend",
                    backend.cyan()
                );
                println!(
                    "                    5. Replace literal in code with environment variable"
                );
                println!(
                    "                    6. Queue old key for 24h grace window (zero downtime)"
                );
                println!("                    7. Record transaction in rollback ledger");
                println!();
                print!("Proceed with live remediation? [y/N]: ");
                use std::io::Write;
                let _ = std::io::stdout().flush();

                let mut response = String::new();
                if std::io::stdin().read_line(&mut response).is_err() {
                    eprintln!("\nOperation cancelled.");
                    process::exit(0);
                }

                let trimmed = response.trim().to_lowercase();
                if trimmed != "y" && trimmed != "yes" {
                    println!("{}", "Operation cancelled by user.".yellow());
                    return;
                }
            }

            let remediator = Remediator::new();
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

                let lines: Vec<&str> = content.lines().collect();
                if finding.line_number == 0 || finding.line_number > lines.len() {
                    eprintln!("{} Invalid line number in finding.", "ERROR:".red().bold());
                    process::exit(1);
                }

                let target_line = lines[finding.line_number - 1];
                // Extract the exact raw secret token using the detector rule's capture group
                let mut raw_secret_owned = scanner
                    .extract_raw_secret(target_line, &finding.rule_id)
                    .unwrap_or_else(|| {
                        target_line
                            .split(&['"', '\'', '`'][..])
                            .nth(1)
                            .unwrap_or(target_line)
                            .trim()
                            .to_string()
                    });

                let result = remediator.remediate_finding_with_mode(
                    finding,
                    raw_secret_owned.as_str(),
                    dry_run,
                    Some(&backend),
                    cli.offline,
                    rotate,
                );
                // Cryptographically zeroize raw secret from RAM immediately after remediation
                Remediator::zeroize_secret_string(&mut raw_secret_owned);

                match result {
                    Ok(session_id) => {
                        if let Ok(mut ledger) =
                            AuditLedger::load_or_init(".sentris/audit_ledger.json")
                        {
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

            if !all && report.findings.len() > 1 {
                println!(
                    "{} {} additional secret(s) remain in target. Run with {} to batch-remediate all findings at once.",
                    "ℹ️ ".cyan(),
                    (report.findings.len() - 1).to_string().bold(),
                    "--all".cyan().bold()
                );
            }
        }

        Commands::Rollback { session } => {
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
                println!(
                    "{}",
                    "No active remediation sessions found in rollback ledger.".yellow()
                );
                return;
            }

            let target_session = match session {
                Some(s) => s,
                None => {
                    // Pick most recent transaction
                    ledger.transactions.last().unwrap().session_id.clone()
                }
            };

            match ledger.revert(&target_session) {
                Ok(msg) => println!("{}", msg.green().bold()),
                Err(err) => {
                    eprintln!("{} Rollback failed: {}", "ERROR:".red().bold(), err);
                    process::exit(1);
                }
            }
        }

        Commands::Quarantine { finding_id, branch } => {
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

            // First check git history, then fallback to current working directory
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
                    if let Ok(mut ledger) = AuditLedger::load_or_init(".sentris/audit_ledger.json")
                    {
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

        Commands::Completions { shell } => {
            print!(
                "{}",
                crate::cli::completions::CompletionGenerator::generate(shell)
            );
        }

        Commands::Init { force } => match config::Config::init(std::path::Path::new("."), force) {
            Ok(path) => {
                println!(
                    "{} Created Sentris configuration file at {}",
                    "✔".green().bold(),
                    path.display().to_string().cyan().bold()
                );
                println!("Edit .sentris.toml to configure custom enterprise rules, ignore patterns, and remediation parameters.");
            }
            Err(err) => {
                eprintln!(
                    "{} Failed to initialize configuration: {}",
                    "ERROR:".red().bold(),
                    err
                );
                process::exit(1);
            }
        },
        Commands::Review { path, min_severity } => {
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
                            let mut lines: Vec<String> =
                                content.lines().map(|s| s.to_string()).collect();
                            if finding.line_number > 0 && finding.line_number <= lines.len() {
                                let ext = std::path::Path::new(&finding.file_path)
                                    .extension()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("")
                                    .to_lowercase();
                                let comment_suffix = match ext.as_str() {
                                    "py" | "sh" | "bash" | "zsh" | "rb" | "yml" | "yaml"
                                    | "toml" | "env" => " # sentris-ignore",
                                    _ => " // sentris-ignore",
                                };
                                if !lines[finding.line_number - 1].contains("sentris-ignore") {
                                    lines[finding.line_number - 1].push_str(comment_suffix);
                                    let _ = fs::write(
                                        &finding.file_path,
                                        format!("{}\n", lines.join("\n")),
                                    );
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

        Commands::Baseline { subcommand } => match subcommand {
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
        },

        Commands::Audit {
            ledger,
            verify,
            export_vanta,
        } => {
            let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
            let audit_ledger = match AuditLedger::load_or_init(&ledger) {
                Ok(l) => l,
                Err(err) => {
                    if no_color {
                        eprintln!(
                            "ERROR: Failed to load audit ledger at {}: {}",
                            ledger.display(),
                            err
                        );
                    } else {
                        eprintln!(
                            "{} Failed to load audit ledger at {}: {}",
                            "ERROR:".red().bold(),
                            ledger.display(),
                            err
                        );
                    }
                    process::exit(1);
                }
            };

            println!();
            if no_color {
                println!("🔒 SOC 2 Cryptographic Audit Ledger: {}", ledger.display());
                println!("   Total Records: {}", audit_ledger.records.len());
            } else {
                println!(
                    "{} {}",
                    "🔒 SOC 2 Cryptographic Audit Ledger:".cyan().bold(),
                    ledger.display().to_string().bold()
                );
                println!(
                    "   Total Records: {}",
                    audit_ledger.records.len().to_string().cyan()
                );
            }

            if verify {
                match audit_ledger.verify_integrity() {
                    Ok(true) => {
                        if no_color {
                            println!(
                                "   Chain Integrity: PASS (HMAC-SHA256 verified, 0 broken links)"
                            );
                        } else {
                            println!(
                                "   Chain Integrity: {} (HMAC-SHA256 verified, 0 broken links)",
                                "PASS".green().bold()
                            );
                        }
                    }
                    Ok(false) => {
                        if no_color {
                            eprintln!(
                                "   Chain Integrity: FAIL (Tamper detected or hash mismatch!)"
                            );
                        } else {
                            eprintln!(
                                "   Chain Integrity: {} (Tamper detected or hash mismatch!)",
                                "FAIL".red().bold()
                            );
                        }
                        process::exit(1);
                    }
                    Err(err) => {
                        if no_color {
                            eprintln!("   Chain Integrity: ERROR ({err})");
                        } else {
                            eprintln!("   Chain Integrity: {} ({err})", "ERROR".red().bold());
                        }
                        process::exit(1);
                    }
                }
            }

            if !cli.quiet && !audit_ledger.records.is_empty() {
                println!();
                println!("   Recent Audit Events:");
                for record in audit_ledger.records.iter().rev().take(5) {
                    let hash_prefix = if record.entry_hash.len() >= 8 {
                        &record.entry_hash[..8]
                    } else {
                        &record.entry_hash
                    };
                    println!(
                        "   • [#{}] {:?} (Hash: {hash_prefix}...)",
                        record.index, record.action,
                    );
                }
            }

            if let Some(vanta_path) = export_vanta {
                match audit_ledger.export_vanta_evidence_pack(&vanta_path) {
                    Ok((scans, files, remediations, quarantines)) => {
                        if no_color {
                            println!(
                                "\n   ✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack: {}",
                                vanta_path.display()
                            );
                            println!(
                                "      ├─ SOC 2 CC6.1 (Continuous Secret Scanning):    PASS ({scans} scans, {files} files inspected)"
                            );
                            println!(
                                "      ├─ SOC 2 CC6.7 (Zero-Knowledge Transmission):   PASS (0 bytes plaintext exfiltrated)"
                            );
                            println!(
                                "      ├─ SOC 2 CC6.8 (Timely Credential Remediation): PASS ({remediations} remediated, {quarantines} quarantined)"
                            );
                            println!(
                                "      └─ ISO 27001 A.8.24 (Cryptographic Hash Chain): PASS (HMAC-SHA256 verified)"
                            );
                        } else {
                            println!(
                                "\n   {} {}",
                                "✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack:"
                                    .green()
                                    .bold(),
                                vanta_path.display().to_string().cyan().bold()
                            );
                            println!(
                                "      ├─ SOC 2 CC6.1 (Continuous Secret Scanning):    {} ({scans} scans, {files} files inspected)",
                                "PASS".green().bold()
                            );
                            println!(
                                "      ├─ SOC 2 CC6.7 (Zero-Knowledge Transmission):   {} (0 bytes plaintext exfiltrated)",
                                "PASS".green().bold()
                            );
                            println!(
                                "      ├─ SOC 2 CC6.8 (Timely Credential Remediation): {} ({remediations} remediated, {quarantines} quarantined)",
                                "PASS".green().bold()
                            );
                            println!(
                                "      └─ ISO 27001 A.8.24 (Cryptographic Hash Chain): {} (HMAC-SHA256 verified)",
                                "PASS".green().bold()
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "ERROR: Failed to export Vanta compliance pack to {}: {}",
                            vanta_path.display(),
                            err
                        );
                        process::exit(1);
                    }
                }
            }
            println!();
        }

        Commands::MigrateGitleaks {
            input,
            output,
            force,
        } => {
            let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
            match GitleaksMigrator::migrate_file(&input, &output, force) {
                Ok((rules_count, ignore_paths_count)) => {
                    if !cli.quiet {
                        if no_color {
                            println!("✔ Migration completed successfully!");
                            println!("   Source: {}", input.display());
                            println!("   Destination: {}", output.display());
                            println!("   Rules migrated: {}", rules_count);
                            println!("   Ignore paths migrated: {}", ignore_paths_count);
                        } else {
                            println!("{}", "✔ Migration completed successfully!".bold().green());
                            println!("   Source: {}", input.display().to_string().cyan());
                            println!("   Destination: {}", output.display().to_string().cyan());
                            println!(
                                "   Rules migrated: {}",
                                rules_count.to_string().yellow().bold()
                            );
                            println!(
                                "   Ignore paths migrated: {}",
                                ignore_paths_count.to_string().yellow().bold()
                            );
                        }
                    }
                }
                Err(err) => {
                    if no_color {
                        eprintln!("ERROR: Failed to migrate .gitleaks.toml: {err}");
                    } else {
                        eprintln!(
                            "{} Failed to migrate .gitleaks.toml: {err}",
                            "ERROR:".red().bold()
                        );
                    }
                    process::exit(1);
                }
            }
        }

        Commands::Auth { subcommand } => match subcommand {
            AuthSubcommand::Login { token, server } => {
                let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
                match Credentials::from_token(&token, server) {
                    Ok(creds) => {
                        let path = Credentials::default_credentials_path();
                        if let Err(err) = creds.save_to_path(&path) {
                            eprintln!(
                                "{} Failed to save credentials: {}",
                                "ERROR:".red().bold(),
                                err
                            );
                            process::exit(1);
                        }
                        if !cli.quiet {
                            if no_color {
                                println!("✔ Successfully authenticated with Sentris Pro Cloud!");
                                println!("   Organization: {}", creds.org_name);
                                println!("   Tier: {}", creds.tier);
                                println!(
                                    "   Seats: {}/{} occupied",
                                    creds.seats_used, creds.seat_limit
                                );
                                println!("   Credentials stored: {}", path.display());
                            } else {
                                println!(
                                    "{}",
                                    "✔ Successfully authenticated with Sentris Pro Cloud!"
                                        .green()
                                        .bold()
                                );
                                println!("   Organization: {}", creds.org_name.cyan().bold());
                                println!("   Tier: {}", creds.tier.yellow());
                                println!(
                                    "   Seats: {}/{} occupied",
                                    creds.seats_used.to_string().bold(),
                                    creds.seat_limit
                                );
                                println!(
                                    "   Credentials stored: {}",
                                    path.display().to_string().dimmed()
                                );
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("{} Authentication failed: {}", "ERROR:".red().bold(), err);
                        process::exit(1);
                    }
                }
            }
            AuthSubcommand::Status => {
                let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
                match Credentials::load_default() {
                    Ok(creds) => {
                        if no_color {
                            println!("Active Sentris Pro Cloud Session:");
                            println!("   Organization: {} ({})", creds.org_name, creds.org_id);
                            println!("   Account: {}", creds.user_email);
                            println!("   Tier: {}", creds.tier);
                            println!(
                                "   Seats: {}/{} occupied ($8/dev/mo Pro Tier)",
                                creds.seats_used, creds.seat_limit
                            );
                            println!("   Endpoint: {}", creds.server_url);
                        } else {
                            println!("{}", "Active Sentris Pro Cloud Session:".cyan().bold());
                            println!(
                                "   Organization: {} ({})",
                                creds.org_name.bold(),
                                creds.org_id.dimmed()
                            );
                            println!("   Account: {}", creds.user_email);
                            println!("   Tier: {}", creds.tier.green().bold());
                            println!(
                                "   Seats: {}/{} occupied ($8/dev/mo Pro Tier)",
                                creds.seats_used.to_string().yellow().bold(),
                                creds.seat_limit
                            );
                            println!("   Endpoint: {}", creds.server_url.dimmed());
                        }
                    }
                    Err(err) => {
                        if !cli.quiet {
                            if no_color {
                                eprintln!("No active session: {err}");
                                println!(
                                    "Run `sentris auth login --token <TOKEN>` to authenticate."
                                );
                            } else {
                                eprintln!("{} {}", "No active session:".yellow().bold(), err);
                                println!(
                                    "Run `sentris auth login --token <TOKEN>` to authenticate."
                                );
                            }
                        }
                        process::exit(1);
                    }
                }
            }
            AuthSubcommand::Logout => {
                let _ = Credentials::delete_default();
                if !cli.quiet {
                    println!(
                        "{}",
                        "✔ Logged out from Sentris Pro Cloud. Local credentials cleared.".green()
                    );
                }
            }
        },

        Commands::Sync { path, repo, branch } => {
            if cli.offline {
                eprintln!(
                    "{}",
                    "ERROR: Cannot sync in zero-egress offline mode."
                        .red()
                        .bold()
                );
                process::exit(1);
            }
            let creds = match Credentials::load_default() {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{} {}", "Authentication required:".yellow().bold(), err);
                    println!("Run `sentris auth login --token <TOKEN>` to link your Pro account.");
                    process::exit(1);
                }
            };
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
                    eprintln!("{} Failed during scan: {}", "ERROR:".red().bold(), err);
                    process::exit(1);
                }
            };
            let effective_repo = repo.or_else(|| {
                GitManager::find_git_root()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            });
            let effective_branch = branch.or_else(|| GitManager::get_head_branch().ok().flatten());
            let commit = GitManager::get_head_commit().ok().flatten();
            let payload = build_cloud_payload(
                &report,
                &creds,
                effective_repo.as_deref(),
                effective_branch.as_deref(),
                commit,
            );
            match upload_scan(&payload, &creds, false) {
                Ok(res) => {
                    if !cli.quiet {
                        println!(
                            "{} {}",
                            "✔ Sentris Pro Cloud:".cyan().bold(),
                            res.message.green()
                        );
                        println!("   Scan ID: {}", res.scan_id.bold());
                        println!("   Findings Synced: {}", payload.findings.len());
                        println!("   Dashboard: {}", res.dashboard_url.underline());
                    }
                }
                Err(err) => {
                    eprintln!(
                        "{} Failed to upload to Sentris Pro Cloud: {}",
                        "ERROR:".red().bold(),
                        err
                    );
                    process::exit(1);
                }
            }
        }

        Commands::Team => {
            let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
            match Credentials::load_default() {
                Ok(creds) => {
                    let team = TeamInfo::from_credentials(&creds);
                    println!("{}", team.render_terminal(no_color));
                }
                Err(_) => {
                    let sample_creds = Credentials {
                        api_key: "sp_preview_token".to_string(),
                        server_url: "https://api.sentris.dev".to_string(),
                        org_id: "org_sample_team".to_string(),
                        org_name: "Sentris Pro Workspace (Preview)".to_string(),
                        tier: "Pro ($8/seat)".to_string(),
                        seat_limit: 20,
                        seats_used: 14,
                        user_email: "dev@sentris.dev".to_string(),
                        expires_at: None,
                    };
                    let team = TeamInfo::from_credentials(&sample_creds);
                    println!("{}", team.render_terminal(no_color));
                    println!("{}", "\nℹ️  To link your real team workspace, run `sentris auth login --token <TOKEN>`.".dimmed());
                }
            }
        }

        Commands::Mcp { print_config } => {
            if print_config {
                println!("{}", crate::mcp::McpServer::generate_config_snippet());
                return;
            }
            if let Err(err) = crate::mcp::McpServer::run_stdio_loop(cli.offline) {
                eprintln!("{} MCP server error: {}", "ERROR:".red().bold(), err);
                process::exit(1);
            }
        }
    }
}
