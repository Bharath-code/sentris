use serde_json::{json, Value};

use super::{WebhookReporter, MAX_DISPLAY, RECOMMENDED_ACTION};
use crate::model::{Finding, ScanReport};

/// Used when a report carries no timestamp, so the embed always has a valid one.
const FALLBACK_TIMESTAMP: &str = "2026-10-07T00:00:00Z";

impl WebhookReporter {
    /// Formats the scan report as a Discord Webhook message payload
    pub fn format_discord_card(report: &ScanReport) -> Value {
        let branding = Self::resolve_branding(report);
        let count = report.findings.len();
        let duration_ms = report.stats.duration_ms;
        let files_scanned = report.stats.files_scanned;

        let content_text = if count == 0 {
            format!(
                "{} **[CLEAN] Sentris Scan Passed** - Zero secrets detected across {} files ({}ms)",
                branding.emoji, files_scanned, duration_ms
            )
        } else {
            format!(
                "{} **[{}] Sentris Incident Alert** - {} secrets detected ({}ms)",
                branding.emoji, branding.level_name, count, duration_ms
            )
        };
        let description = if count == 0 {
            "Repository scan completed successfully. No hardcoded credentials detected.".to_string()
        } else {
            format!("Hardcoded secrets detected during scan execution.\n\n🛡️ **Recommended Action:** {RECOMMENDED_ACTION}")
        };

        let mut fields = vec![field(
            "📊 Scan Summary".to_string(),
            format!(
                "• **Branding:** {} {}\n• **Finding Count:** {}\n• **Scan Duration:** {}ms\n• **Files Scanned:** {}",
                branding.dot_emoji, branding.level_name, count, duration_ms, files_scanned
            ),
        )];
        fields.extend(
            report
                .findings
                .iter()
                .take(MAX_DISPLAY)
                .enumerate()
                .map(|(idx, finding)| Self::discord_finding_field(idx, finding)),
        );
        if count > MAX_DISPLAY {
            fields.push(field(
                "⚠️ Additional Findings".to_string(),
                format!(
                    "...and {} additional findings omitted. Run `sentris scan` locally.",
                    count - MAX_DISPLAY
                ),
            ));
        }
        fields.push(field(
            "🛡️ Recommended Action".to_string(),
            RECOMMENDED_ACTION.to_string(),
        ));

        let timestamp = if report.timestamp.is_empty() {
            FALLBACK_TIMESTAMP
        } else {
            &report.timestamp
        };
        json!({
            "content": content_text,
            "embeds": [{
                "title": Self::card_title(&branding, count),
                "description": description,
                "color": branding.discord_color,
                "fields": fields,
                "footer": { "text": "Sentris Security Scanner • Secret Remediation" },
                "timestamp": timestamp
            }]
        })
    }

    fn discord_finding_field(idx: usize, finding: &Finding) -> Value {
        let (badge, sev_name) = Self::severity_badge(finding.severity);
        field(
            format!(
                "{} Finding #{}: {} ({})",
                badge,
                idx + 1,
                finding.rule_id,
                sev_name
            ),
            format!(
                "• **Rule ID:** `{}`\n• **File Path:** `{}:{}`\n• **Entropy Score:** `{:.2}`\n• **Masked Preview:** `{}`",
                finding.rule_id,
                finding.file_path,
                finding.line_number,
                finding.entropy,
                finding.redacted_match
            ),
        )
    }
}

fn field(name: String, value: String) -> Value {
    json!({ "name": name, "value": value, "inline": false })
}
