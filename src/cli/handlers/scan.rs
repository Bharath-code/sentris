use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::process;

use super::scan_output::{
    dispatch_webhook, print_exposures, probe_findings, render_scan_report, sync_cloud_report,
    verify_findings_live,
};
use super::{die, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::{Cli, OutputFormat};
use crate::detector::baseline::BaselineFile;
use crate::exposure::{at_or_above, rank_findings, RiskTier};
use crate::git::GitManager;
use crate::model::{ScanReport, Severity};
use crate::scanner::Scanner;

#[allow(clippy::too_many_arguments)]
pub fn handle_scan(
    cli: &Cli,
    path: PathBuf,
    from_report: Option<PathBuf>,
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
    probe: bool,
    fail_on: Option<RiskTier>,
    workstation: bool,
    stdin: bool,
    docker: Option<String>,
    fix: bool,
    ignore_tests: bool,
) {
    let mut scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let mut report = match &from_report {
        Some(file) => import_report(cli, &mut scanner, file),
        None => run_scan(
            &scanner,
            since.as_deref(),
            git_history,
            staged,
            workstation,
            stdin,
            docker.as_deref(),
            &path,
        ),
    };
    let path = from_report.unwrap_or(path);

    if ignore_tests {
        report.findings.retain(|f| {
            !crate::detector::false_positives::FalsePositiveFilter::is_test_fixture_path(
                &f.file_path,
            )
        });
        report.stats.findings_count = report.findings.len();
    }

    if let Some(min_sev) = min_severity {
        report.findings.retain(|f| f.severity >= min_sev);
        report.stats.findings_count = report.findings.len();
    }

    if fix
        && !report.findings.is_empty()
        && docker.is_none()
        && !git_history
        && since.is_none()
        && !stdin
    {
        auto_fix_scan_findings(cli, &scanner, &report, staged);
        report = run_scan(
            &scanner,
            since.as_deref(),
            git_history,
            staged,
            workstation,
            stdin,
            docker.as_deref(),
            &path,
        );
        if ignore_tests {
            report.findings.retain(|f| {
                !crate::detector::false_positives::FalsePositiveFilter::is_test_fixture_path(
                    &f.file_path,
                )
            });
            report.stats.findings_count = report.findings.len();
        }
    }

    let effective_format = if cli.is_agent_mode() && matches!(format, OutputFormat::Text) {
        OutputFormat::Json
    } else {
        format
    };
    let show_notes = !cli.quiet && matches!(effective_format, OutputFormat::Text);
    if let Some(baseline_path) = &baseline {
        apply_baseline(&mut report, baseline_path, show_notes);
    }
    if let Some(record_path) = &record_baseline {
        record_baseline_snapshot(&report, record_path, show_notes);
    }
    record_scan_audit(&report, &path, staged, git_history, fail_on_secret);
    if probe {
        probe_findings(cli, &scanner, &mut report);
        rank_findings(&mut report);
    }

    render_scan_report(cli, &report, effective_format);
    if matches!(effective_format, OutputFormat::Text) {
        print_exposures(&report, cli.no_color);
    }

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
    if let Some(tier) = fail_on.filter(|t| at_or_above(&report, *t)) {
        eprintln!(
            "FAILED: at least one finding is at or above the {} risk tier",
            format!("{tier:?}").to_lowercase()
        );
        process::exit(1);
    }
}

/// Loads findings from a Betterleaks/Gitleaks report and hands their secrets to `scanner` for probing and remediation.
pub(super) fn import_report(cli: &Cli, scanner: &mut Scanner, file: &Path) -> ScanReport {
    let root =
        std::env::current_dir().unwrap_or_else(|err| die("Cannot read working directory", err));
    let imported =
        crate::import::load(file, &root).unwrap_or_else(|err| die("Failed to import report", err));
    if !cli.quiet {
        for note in &imported.skipped {
            eprintln!("{} skipped {note}", "warning:".yellow().bold());
        }
    }
    scanner.use_imported_secrets(imported.secrets);
    imported.report
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    scanner: &Scanner,
    since: Option<&str>,
    git_history: bool,
    staged: bool,
    workstation: bool,
    stdin: bool,
    docker: Option<&str>,
    path: &Path,
) -> ScanReport {
    let (context, result) = if let Some(docker_target) = docker {
        (
            format!("Failed during Docker image/tar scan ({docker_target})"),
            scanner.scan_docker(docker_target),
        )
    } else if stdin {
        (
            "Failed during standard input (--stdin) stream scan".to_string(),
            scanner.scan_reader(std::io::stdin().lock(), "<stdin>"),
        )
    } else if workstation {
        (
            "Failed during workstation AI & MCP config scan".to_string(),
            scanner.scan_workstation(),
        )
    } else if let Some(since_ref) = since {
        (
            format!("Failed during git commit range scan ({since_ref})"),
            scanner.scan_git_since(since_ref),
        )
    } else if git_history {
        (
            "Failed during git history scan".to_string(),
            scanner.scan_git_history(),
        )
    } else if staged {
        (
            "Failed during staged scan".to_string(),
            scanner.scan_staged(),
        )
    } else {
        ("Failed during scan".to_string(), scanner.scan_path(path))
    };
    result.unwrap_or_else(|err| die(&context, err))
}

fn auto_fix_scan_findings(cli: &Cli, scanner: &Scanner, report: &ScanReport, restage: bool) {
    let remediator = crate::remediator::Remediator::new();
    let quiet = cli.quiet || cli.is_agent_mode();
    let mut patched_files = Vec::new();

    for finding in &report.findings {
        if matches!(
            finding.rule_id.as_str(),
            "mcp-unpinned-npx-server" | "unicode-prompt-injection" | "ai-prompt-injection-exfil"
        ) {
            continue;
        }
        let norm = finding.file_path.replace('\\', "/");
        let trimmed = norm.trim_start_matches("./");
        if trimmed == ".env"
            || trimmed.ends_with("/.env")
            || trimmed.starts_with(".sentris/")
            || trimmed.contains("/.sentris/")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&finding.file_path) else {
            continue;
        };
        let Ok(mut raw_secret) = scanner.resolve_finding_secret(&content, finding) else {
            continue;
        };
        let ok = remediator
            .remediate_finding_with_options(
                finding,
                &raw_secret,
                false,
                Some("env"),
                cli.offline,
                false,
                quiet,
            )
            .is_ok();
        crate::remediator::Remediator::zeroize_secret_string(&mut raw_secret);
        if ok {
            patched_files.push(finding.file_path.clone());
        }
    }

    if restage && !patched_files.is_empty() {
        for file in &patched_files {
            let _ = std::process::Command::new("git")
                .args(["add", file])
                .output();
        }
        for aux in [".env.example", ".gitignore"] {
            if Path::new(aux).exists() {
                let _ = std::process::Command::new("git")
                    .args(["add", aux])
                    .output();
            }
        }
    }
}

fn apply_baseline(report: &mut ScanReport, baseline_path: &Path, show_notes: bool) {
    let base = BaselineFile::load_from_path(baseline_path).unwrap_or_else(|err| {
        die(
            &format!("Failed to load baseline from {}", baseline_path.display()),
            err,
        )
    });
    let (unsuppressed, suppressed_count) =
        base.filter_findings(std::mem::take(&mut report.findings));
    report.findings = unsuppressed;
    report.stats.findings_count = report.findings.len();
    if suppressed_count > 0 && show_notes {
        println!(
            "{} {} legacy secret(s) suppressed via baseline ({})",
            "ℹ️ ".cyan(),
            suppressed_count.to_string().bold(),
            baseline_path.display().to_string().dimmed()
        );
    }
}

fn record_baseline_snapshot(report: &ScanReport, record_path: &Path, show_notes: bool) {
    let commit = GitManager::get_head_commit().ok().flatten();
    let base_file = BaselineFile::from_findings(&report.findings, commit.clone());
    if let Err(err) = base_file.save_to_path(record_path) {
        die(
            &format!(
                "Failed to write baseline snapshot to {}",
                record_path.display()
            ),
            err,
        );
    }
    if show_notes {
        println!(
            "{} Recorded {} finding(s) into baseline snapshot at {}",
            "✔".green().bold(),
            base_file.findings.len(),
            record_path.display().to_string().cyan().bold()
        );
    }
    record_audit_event(
        AuditAction::BaselineRecorded {
            entries_count: base_file.findings.len(),
            git_commit: commit,
        },
        serde_json::json!({ "output_file": record_path.to_string_lossy() }),
    );
}

fn record_scan_audit(
    report: &ScanReport,
    path: &Path,
    staged: bool,
    git_history: bool,
    fail_on_secret: bool,
) {
    record_audit_event(
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
}
