use owo_colors::OwoColorize;
use std::fs;
use std::path::PathBuf;
use std::process;

use crate::audit::{AuditAction, AuditLedger};
use crate::cli::{Cli, OutputFormat};
use crate::cloud::{build_cloud_payload, upload_scan, Credentials};
use crate::detector::baseline::BaselineFile;
use crate::git::GitManager;
use crate::model::{ScanReport, Severity};
use crate::remediator::Remediator;
use crate::reporter::Reporter;
use crate::scanner::Scanner;

#[allow(clippy::too_many_arguments)]
pub fn handle_scan(
    cli: &Cli,
    path: PathBuf,
    staged: bool,
    git_history: bool,
    since: Option<String>,
    format: OutputFormat,
    fail_on_secret: bool,
    webhook: Option<String>,
    baseline: Option<PathBuf>,
    record_baseline: Option<PathBuf>,
    min_severity: Option<Severity>,
    cloud: bool,
    verify: bool,
) {
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
                let (unsuppressed, suppressed_count) = base.filter_findings(report.findings);
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

    let effective_format = if is_agent_mode && matches!(format, OutputFormat::Text) {
        OutputFormat::Json
    } else {
        format
    };

    render_scan_report(cli, &report, effective_format);

    if verify
        && !report.findings.is_empty()
        && !cli.quiet
        && matches!(effective_format, OutputFormat::Text)
    {
        verify_findings_live(cli, &scanner, &report);
    }

    if let Some(webhook_url) = webhook {
        dispatch_webhook(cli, &webhook_url, &report);
    }

    if cloud {
        sync_cloud_report(cli, &report);
    }

    if fail_on_secret && !report.findings.is_empty() {
        process::exit(1);
    }
}

fn render_scan_report(cli: &Cli, report: &ScanReport, effective_format: OutputFormat) {
    match effective_format {
        OutputFormat::Text => {
            Reporter::print_terminal_report(report, cli.quiet, cli.no_color);
            if std::env::var_os("GITHUB_ACTIONS").is_some() {
                Reporter::print_github_annotations(report);
            }
        }
        OutputFormat::Json => match Reporter::to_json(report) {
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
        OutputFormat::Sarif => match Reporter::to_sarif(report) {
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
            Reporter::print_github_annotations(report);
        }
        OutputFormat::Gitlab => match Reporter::to_gitlab(report) {
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
}

fn verify_findings_live(cli: &Cli, scanner: &Scanner, report: &ScanReport) {
    if cli.offline {
        println!(
            "{}",
            "ℹ️  Zero-egress offline mode active: Live provider API verification suppressed."
                .yellow()
        );
        return;
    }

    let registry = crate::verifier::VerifierRegistry::new();
    println!(
        "{}",
        "🔍 Live Provider Identity & Blast Radius Verification:"
            .cyan()
            .bold()
    );
    for f in &report.findings {
        let env_tier = match f.context_kind() {
            crate::model::ContextKind::Production => "Production Code",
            crate::model::ContextKind::TestFixture => "Test/Fixture",
        };
        if let Some(verifier) = registry.find_verifier(&f.rule_id) {
            let status = if let Ok(content) = fs::read_to_string(&f.file_path) {
                let lines: Vec<&str> = content.lines().collect();
                if f.line_number > 0 && f.line_number <= lines.len() {
                    let target_line = lines[f.line_number - 1];
                    let mut raw_secret = scanner
                        .extract_raw_secret(target_line, &f.rule_id)
                        .unwrap_or_default();
                    let res = verifier.verify_live(&raw_secret).unwrap_or(
                        crate::verifier::LiveStatus::Unverified("Verification failed".to_string()),
                    );
                    Remediator::zeroize_secret_string(&mut raw_secret);
                    res
                } else {
                    crate::verifier::LiveStatus::Unverified("Line out of range".to_string())
                }
            } else {
                crate::verifier::LiveStatus::Unverified("Historical/unstaged blob".to_string())
            };

            match status {
                crate::verifier::LiveStatus::Active { scopes } => {
                    println!(
                        "   • {}:{} ({} • {}): {} [Scopes: {}]",
                        f.file_path.bold(),
                        f.line_number,
                        verifier.provider_name().cyan(),
                        env_tier,
                        "ACTIVE & LIVE".red().bold(),
                        scopes.join(", ").yellow()
                    );
                }
                crate::verifier::LiveStatus::Revoked => {
                    println!(
                        "   • {}:{} ({} • {}): {}",
                        f.file_path.bold(),
                        f.line_number,
                        verifier.provider_name().cyan(),
                        env_tier,
                        "REVOKED / INACTIVE".dimmed()
                    );
                }
                crate::verifier::LiveStatus::Unverified(reason) => {
                    println!(
                        "   • {}:{} ({} • {}): {} ({})",
                        f.file_path.bold(),
                        f.line_number,
                        verifier.provider_name().cyan(),
                        env_tier,
                        "UNVERIFIED".yellow(),
                        reason.dimmed()
                    );
                }
            }
        } else {
            println!(
                "   • {}:{} ({} • {}): {}",
                f.file_path.bold(),
                f.line_number,
                f.rule_id.cyan(),
                env_tier,
                "Pattern-Verified (High Entropy)".yellow()
            );
        }
    }
    println!();
}

fn dispatch_webhook(cli: &Cli, webhook_url: &str, report: &ScanReport) {
    if cli.offline {
        if !cli.quiet {
            println!(
                "{}",
                "ℹ️  Zero-egress offline mode active: Webhook incident dispatch suppressed."
                    .yellow()
            );
        }
        return;
    }

    match crate::reporter::webhook::WebhookReporter::post_incident_card(webhook_url, report, false)
    {
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

fn sync_cloud_report(cli: &Cli, report: &ScanReport) {
    if cli.offline {
        if !cli.quiet {
            println!(
                "{}",
                "ℹ️  Zero-egress offline mode active: Sentris Pro Cloud sync suppressed.".yellow()
            );
        }
        return;
    }

    match Credentials::load_default() {
        Ok(creds) => {
            let repo_name = GitManager::find_git_root()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "workspace".to_string());
            let branch = GitManager::get_head_branch()
                .ok()
                .flatten()
                .unwrap_or_else(|| "main".to_string());
            let commit = GitManager::get_head_commit().ok().flatten();
            match build_cloud_payload(report, &creds, Some(&repo_name), Some(&branch), commit)
                .and_then(|payload| upload_scan(&payload, &creds, false))
            {
                Ok(res) => {
                    if !cli.quiet {
                        println!(
                            "{} {}",
                            "☁️  Sentris Pro Cloud:".cyan().bold(),
                            res.message.green()
                        );
                        println!("   Dashboard: {}", res.dashboard_url.underline());
                        let multi_repo: Vec<_> = res
                            .blast_radius_insights
                            .iter()
                            .filter(|i| i.affected_repos.len() > 1)
                            .collect();
                        if !multi_repo.is_empty() {
                            println!(
                                "   {}",
                                "⚡ Zero-Knowledge Multi-Repo Blast Radius Insight (0 Bytes Source Ingested):"
                                    .yellow()
                                    .bold()
                            );
                            for insight in multi_repo {
                                let short_fp = if insight.zk_fingerprint.len() > 15 {
                                    crate::model::short(&insight.zk_fingerprint, 15)
                                } else {
                                    &insight.zk_fingerprint
                                };
                                println!(
                                    "      • {}... ({}) reused across {} repos: [{}]",
                                    short_fp.cyan(),
                                    insight.rule_id.red().bold(),
                                    insight.affected_repos.len(),
                                    insight.affected_repos.join(", ").yellow()
                                );
                            }
                        }
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
