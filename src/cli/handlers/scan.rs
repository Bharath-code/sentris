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
use crate::git::GitManager;
use crate::model::{ScanReport, Severity};
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
    probe: bool,
) {
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let mut report = run_scan(&scanner, since.as_deref(), git_history, staged, &path);

    if let Some(min_sev) = min_severity {
        report.findings.retain(|f| f.severity >= min_sev);
        report.stats.findings_count = report.findings.len();
    }

    let show_notes = !cli.quiet && format == OutputFormat::Text;
    if let Some(baseline_path) = &baseline {
        apply_baseline(&mut report, baseline_path, show_notes);
    }
    if let Some(record_path) = &record_baseline {
        record_baseline_snapshot(&report, record_path, show_notes);
    }
    record_scan_audit(&report, &path, staged, git_history, fail_on_secret);
    if probe {
        probe_findings(cli, &scanner, &mut report);
    }

    let effective_format = if cli.is_agent_mode() && matches!(format, OutputFormat::Text) {
        OutputFormat::Json
    } else {
        format
    };
    render_scan_report(cli, &report, effective_format);
    if matches!(effective_format, OutputFormat::Text) {
        print_exposures(&report);
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
}

fn run_scan(
    scanner: &Scanner,
    since: Option<&str>,
    git_history: bool,
    staged: bool,
    path: &Path,
) -> ScanReport {
    let (context, result) = if let Some(since_ref) = since {
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
