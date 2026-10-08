mod cli;
mod config;
mod detector;
mod error;
mod git;
mod model;
mod remediator;
mod reporter;
mod scanner;
mod verifier;

use clap::Parser;
use owo_colors::OwoColorize;
use std::fs;
use std::process;

use crate::cli::{Cli, Commands, OutputFormat};
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

            let report = if git_history {
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
    }
}
