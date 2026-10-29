use owo_colors::OwoColorize;
use std::fs;

use super::{die, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::{Cli, OutputFormat};
use crate::cloud::{build_cloud_payload, upload_scan, Credentials, MultiRepoBlastRadiusInsight};
use crate::git::GitManager;
use crate::model::{ContextKind, ScanReport};
use crate::remediator::Remediator;
use crate::reporter::Reporter;
use crate::scanner::Scanner;
use crate::verifier::{LiveStatus, ProviderVerifier, VerifierRegistry};

pub(super) fn render_scan_report(cli: &Cli, report: &ScanReport, format: OutputFormat) {
    match format {
        OutputFormat::Text => {
            Reporter::print_terminal_report(report, cli.quiet, cli.no_color);
            if std::env::var_os("GITHUB_ACTIONS").is_some() {
                Reporter::print_github_annotations(report);
            }
        }
        OutputFormat::Json => print_serialized(Reporter::to_json(report), "JSON"),
        OutputFormat::Sarif => print_serialized(Reporter::to_sarif(report), "SARIF"),
        OutputFormat::Github => Reporter::print_github_annotations(report),
        OutputFormat::Gitlab => print_serialized(Reporter::to_gitlab(report), "GitLab report"),
    }
}

fn print_serialized<E: std::fmt::Display>(out: Result<String, E>, what: &str) {
    match out {
        Ok(text) => println!("{text}"),
        Err(err) => die(&format!("Failed to serialize {what}"), err),
    }
}

pub(super) fn verify_findings_live(cli: &Cli, scanner: &Scanner, report: &ScanReport) {
    if cli.offline {
        println!(
            "{}",
            "ℹ️  Zero-egress offline mode active: Live provider API verification suppressed."
                .yellow()
        );
        return;
    }

    let registry = VerifierRegistry::new();
    println!(
        "{}",
        "🔍 Live Provider Identity & Blast Radius Verification:"
            .cyan()
            .bold()
    );
    for f in &report.findings {
        let env_tier = match f.context_kind() {
            ContextKind::Production => "Production Code",
            ContextKind::TestFixture => "Test/Fixture",
        };
        let place = format!("{}:{}", f.file_path.bold(), f.line_number);
        match registry.find_verifier(&f.rule_id) {
            Some(verifier) => {
                let status = live_status(scanner, f, verifier);
                println!(
                    "   • {place} ({} • {env_tier}): {}",
                    verifier.provider_name().cyan(),
                    describe_status(status)
                );
            }
            None => println!(
                "   • {place} ({} • {env_tier}): {}",
                f.rule_id.cyan(),
                "Pattern-Verified (High Entropy)".yellow()
            ),
        }
    }
    println!();
}

/// Re-extracts the raw secret from disk (it is never stored) and asks the provider about it.
fn live_status(
    scanner: &Scanner,
    f: &crate::model::Finding,
    verifier: &dyn ProviderVerifier,
) -> LiveStatus {
    let Ok(content) = fs::read_to_string(&f.file_path) else {
        return LiveStatus::Unverified("Historical/unstaged blob".to_string());
    };
    let Some(target_line) = f
        .line_number
        .checked_sub(1)
        .and_then(|i| content.lines().nth(i))
    else {
        return LiveStatus::Unverified("Line out of range".to_string());
    };
    let mut raw_secret = scanner
        .extract_raw_secret(target_line, &f.rule_id)
        .unwrap_or_default();
    let res = verifier
        .verify_live(&raw_secret)
        .unwrap_or(LiveStatus::Unverified("Verification failed".to_string()));
    Remediator::zeroize_secret_string(&mut raw_secret);
    res
}

/// Scopes already appear under the capabilities, so the status line stays short.
fn describe_probed(status: &LiveStatus) -> String {
    match status {
        LiveStatus::Active { .. } => "ACTIVE & LIVE".red().bold().to_string(),
        other => describe_status(other.clone()),
    }
}

fn describe_status(status: LiveStatus) -> String {
    match status {
        LiveStatus::Active { scopes } => format!(
            "{} [Scopes: {}]",
            "ACTIVE & LIVE".red().bold(),
            scopes.join(", ").yellow()
        ),
        LiveStatus::Revoked => "REVOKED / INACTIVE".dimmed().to_string(),
        LiveStatus::Unverified(reason) => {
            format!("{} ({})", "UNVERIFIED".yellow(), reason.dimmed())
        }
    }
}

/// Read-only provider probes for `scan --probe`. Each probe is audited before its network call; offline mode makes none.
pub(super) fn probe_findings(cli: &Cli, scanner: &Scanner, report: &mut ScanReport) {
    if cli.offline {
        if !cli.quiet {
            eprintln!("Zero-egress offline mode active: exposure probes suppressed.");
        }
        return;
    }
    crate::exposure::probe_report(
        report,
        |f| {
            let content = fs::read_to_string(&f.file_path).ok()?;
            scanner.resolve_finding_secret(&content, f).ok()
        },
        crate::exposure::probe_for_rule,
        |f, provider| {
            let fingerprint = crate::model::short(&f.fingerprint, 12);
            record_audit_event(
                AuditAction::ExposureProbed {
                    finding_id: fingerprint.to_string(),
                    provider: provider.to_string(),
                },
                serde_json::json!({
                    "rule_id": f.rule_id,
                    "note": format!("probe performed with credential fingerprint {fingerprint}"),
                }),
            );
        },
    );
}

pub(super) fn print_exposures(report: &ScanReport) {
    if report.exposures.is_empty() {
        return;
    }
    println!("{}", "Exposure (read-only provider probes):".cyan().bold());
    for f in &report.findings {
        let Some(e) = report.exposures.get(&f.fingerprint) else {
            continue;
        };
        println!(
            "   • {}:{} {} [{}] {}",
            f.file_path.bold(),
            f.line_number,
            e.provider.cyan(),
            format!("{:?}", e.tier).to_uppercase().red().bold(),
            describe_probed(&e.live)
        );
        for c in &e.capabilities {
            println!("       - {c}");
        }
        if let Some(usd) = e.measured_usd {
            println!("       - provider-reported available balance: ${usd:.2}");
        }
    }
    println!();
}

pub(super) fn dispatch_webhook(cli: &Cli, webhook_url: &str, report: &ScanReport) {
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
        Ok(msg) if !cli.quiet => println!("{}", msg.green()),
        Ok(_) => {}
        Err(err) => eprintln!(
            "{} Failed to dispatch incident webhook: {}",
            "WARNING:".yellow().bold(),
            err
        ),
    }
}

pub(super) fn sync_cloud_report(cli: &Cli, report: &ScanReport) {
    if cli.offline {
        if !cli.quiet {
            println!(
                "{}",
                "ℹ️  Zero-egress offline mode active: Sentris Pro Cloud sync suppressed.".yellow()
            );
        }
        return;
    }

    let Ok(creds) = Credentials::load_default() else {
        if !cli.quiet {
            println!(
                "{}",
                "ℹ️  Not authenticated with Sentris Pro Cloud. Run `sentris auth login --token <TOKEN>` to enable Pro team dashboard sync."
                    .dimmed()
            );
        }
        return;
    };

    let repo_name = GitManager::find_git_root()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "workspace".to_string());
    let branch = GitManager::get_head_branch()
        .ok()
        .flatten()
        .unwrap_or_else(|| "main".to_string());
    let commit = GitManager::get_head_commit().ok().flatten();
    let synced = build_cloud_payload(report, &creds, Some(&repo_name), Some(&branch), commit)
        .and_then(|payload| upload_scan(&payload, &creds, false));
    match synced {
        Ok(res) if !cli.quiet => {
            println!(
                "{} {}",
                "☁️  Sentris Pro Cloud:".cyan().bold(),
                res.message.green()
            );
            println!("   Dashboard: {}", res.dashboard_url.underline());
            print_blast_radius(&res.blast_radius_insights);
        }
        Ok(_) => {}
        Err(err) => eprintln!(
            "{} Failed to sync with Sentris Pro Cloud: {}",
            "WARNING:".yellow().bold(),
            err
        ),
    }
}

pub(super) fn print_blast_radius(insights: &[MultiRepoBlastRadiusInsight]) {
    let multi_repo: Vec<_> = insights
        .iter()
        .filter(|i| i.affected_repos.len() > 1)
        .collect();
    if multi_repo.is_empty() {
        return;
    }
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
