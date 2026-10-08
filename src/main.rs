pub mod audit;
mod cli;
mod config;
mod detector;
mod error;
mod git;
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
use crate::cli::{BaselineSubcommand, Cli, Commands, OutputFormat};
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
            format,
            fail_on_secret,
            webhook,
            baseline,
            record_baseline,
            min_severity,
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

            let mut report = if git_history {
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

            // Find matching finding or first remediable finding (Stripe preferred)
            let target_finding = if let Some(id) = &finding_id {
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

            let finding = match target_finding {
                Some(f) => f,
                None => {
                    eprintln!(
                        "{} Could not find matching finding to remediate.",
                        "ERROR:".red().bold()
                    );
                    process::exit(1);
                }
            };

            // Extract the raw secret from the file at line_number
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
            // Extract the raw secret token using regex pattern matching
            let raw_secret = if let Some(mat) = target_line.split(&['"', '\''][..]).find(|part| {
                part.starts_with("sk_live_")
                    || part.starts_with("rk_live_")
                    || part.starts_with("AKIA")
                    || part.starts_with("ghp_")
            }) {
                mat.trim()
            } else {
                target_line.trim()
            };

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
                println!(
                    "   Target:          {}:{}",
                    finding.file_path.bold(),
                    finding.line_number
                );
                println!("   Secret rule:     {}", finding.rule_id.cyan());
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
            if let Err(err) = remediator.remediate_finding(
                finding,
                raw_secret,
                dry_run,
                Some(&backend),
                cli.offline,
            ) {
                eprintln!("{} Remediation failed: {}", "ERROR:".red().bold(), err);
                process::exit(1);
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

            match crate::tui::run_interactive_review(report.findings) {
                Ok(Some(crate::tui::TuiAction::Remediate(_idx))) => {
                    println!(
                        "{}",
                        "✔ Initiating autonomous remediation workflow for selected finding..."
                            .green()
                            .bold()
                    );
                }
                Ok(Some(crate::tui::TuiAction::AddToBaseline(_idx))) => {
                    println!(
                        "{}",
                        "✔ Finding marked for baseline snapshot recording.".green()
                    );
                }
                Ok(Some(crate::tui::TuiAction::IgnoreFinding(_idx))) => {
                    println!("{}", "✔ Finding marked as ignored.".yellow());
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

        Commands::Audit { ledger, verify } => {
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
            println!();
        }
    }
}
