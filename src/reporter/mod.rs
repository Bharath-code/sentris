pub mod gitlab;
pub mod sarif;
pub mod webhook;

#[allow(unused_imports)]
pub use webhook::WebhookReporter;

use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;

use crate::model::{ScanReport, Severity};

pub struct Reporter;

impl Reporter {
    /// Renders a beautiful terminal table and summary of findings with quiet and no_color support
    pub fn print_terminal_report(report: &ScanReport, quiet: bool, mut no_color: bool) {
        if std::env::var_os("NO_COLOR").is_some() {
            no_color = true;
        }

        if report.findings.is_empty() {
            if !quiet {
                println!();
                if no_color {
                    println!("Sentris — High-Performance Secret Scanner");
                    println!(
                        "Scanned {} files ({:.2} MB) in {}ms",
                        report.stats.files_scanned,
                        report.stats.bytes_scanned as f64 / 1_048_576.0,
                        report.stats.duration_ms
                    );
                    println!();
                    println!("✔ Zero secrets detected! Repository is clean.");
                    println!();
                } else {
                    println!(
                        "{}",
                        "⚡ Sentris — High-Performance Secret Scanner".bold().cyan()
                    );
                    println!(
                        "{}",
                        format!(
                            "Scanned {} files ({:.2} MB) in {}ms",
                            report.stats.files_scanned,
                            report.stats.bytes_scanned as f64 / 1_048_576.0,
                            report.stats.duration_ms
                        )
                        .dimmed()
                    );
                    println!();
                    println!(
                        "{}",
                        "✔ Zero secrets detected! Repository is clean."
                            .bold()
                            .green()
                    );
                    println!();
                }
            }
            return;
        }

        if !quiet {
            println!();
            if no_color {
                println!("Sentris — High-Performance Secret Scanner");
                println!(
                    "Scanned {} files ({:.2} MB) in {}ms",
                    report.stats.files_scanned,
                    report.stats.bytes_scanned as f64 / 1_048_576.0,
                    report.stats.duration_ms
                );
            } else {
                println!(
                    "{}",
                    "⚡ Sentris — High-Performance Secret Scanner".bold().cyan()
                );
                println!(
                    "{}",
                    format!(
                        "Scanned {} files ({:.2} MB) in {}ms",
                        report.stats.files_scanned,
                        report.stats.bytes_scanned as f64 / 1_048_576.0,
                        report.stats.duration_ms
                    )
                    .dimmed()
                );
            }
            println!();
        }

        let mut table = Table::new();
        if no_color {
            table
                .load_preset(comfy_table::presets::ASCII_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "SEVERITY",
                    "RULE ID",
                    "FILE : LINE",
                    "PREVIEW",
                    "ENTROPY",
                ]);
        } else {
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("SEVERITY").fg(Color::Cyan),
                    Cell::new("RULE ID").fg(Color::Cyan),
                    Cell::new("FILE : LINE").fg(Color::Cyan),
                    Cell::new("PREVIEW").fg(Color::Cyan),
                    Cell::new("ENTROPY").fg(Color::Cyan),
                ]);
        }

        for finding in &report.findings {
            let (sev_str, sev_color) = match finding.severity {
                Severity::Critical => ("CRITICAL", Color::Red),
                Severity::High => ("HIGH", Color::DarkRed),
                Severity::Medium => ("MEDIUM", Color::Yellow),
                Severity::Low => ("LOW", Color::Blue),
            };

            let loc_str = if let Some(h) = &finding.commit_hash {
                let short_hash = &h[..7.min(h.len())];
                format!(
                    "{}:{} ({})",
                    finding.file_path, finding.line_number, short_hash
                )
            } else {
                format!("{}:{}", finding.file_path, finding.line_number)
            };
            let entropy_str = format!("{:.2}", finding.entropy);

            if no_color {
                table.add_row(vec![
                    sev_str,
                    &finding.rule_id,
                    &loc_str,
                    &finding.redacted_match,
                    &entropy_str,
                ]);
            } else {
                table.add_row(vec![
                    Cell::new(sev_str).fg(sev_color),
                    Cell::new(&finding.rule_id),
                    Cell::new(loc_str),
                    Cell::new(&finding.redacted_match).fg(Color::Yellow),
                    Cell::new(entropy_str),
                ]);
            }
        }

        println!("{table}");
        println!();

        // Print severity summary
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for f in &report.findings {
            match f.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
            }
        }

        if no_color {
            println!(
                "{} findings detected: {} critical, {} high, {} medium, {} low",
                report.findings.len(),
                critical_count,
                high_count,
                medium_count,
                low_count,
            );
        } else {
            println!(
                "{} findings detected: {} critical, {} high, {} medium, {} low",
                report.findings.len().to_string().bold().red(),
                critical_count.to_string().red(),
                high_count.to_string().yellow(),
                medium_count.to_string().blue(),
                low_count.to_string().dimmed(),
            );
        }

        if !quiet {
            if no_color {
                println!("Tip: Run 'sentris remediate' to safely rotate live credentials with zero downtime.");
            } else {
                println!(
                    "{}",
                    "Tip: Run 'sentris remediate' to safely rotate live credentials with zero downtime."
                        .italic()
                        .dimmed()
                );
            }
            println!();
        }
    }

    /// Renders the report as JSON string
    pub fn to_json(report: &ScanReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }

    /// Renders the report as SARIF v2.1.0 string
    pub fn to_sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
        let sarif_log = sarif::convert_to_sarif(report);
        serde_json::to_string_pretty(&sarif_log)
    }

    /// Renders the report as GitLab Secret Detection JSON format (schema v15.0.7)
    pub fn to_gitlab(report: &ScanReport) -> Result<String, serde_json::Error> {
        gitlab::to_gitlab(report)
    }

    /// Emits native GitHub Actions workflow error annotations for inline PR diff code-review
    pub fn print_github_annotations(report: &ScanReport) {
        for f in &report.findings {
            println!(
                "::error file={},line={},col={},title=Hardcoded Secret Detected ({rule})::[sentris] {} (Entropy: {:.2})",
                f.file_path,
                f.line_number,
                f.column,
                f.description,
                f.entropy,
                rule = f.rule_id
            );
        }
    }
}
