use serde_json::{json, Value};

use super::{WebhookReporter, MAX_DISPLAY, RECOMMENDED_ACTION};
use crate::model::{Finding, ScanReport};

impl WebhookReporter {
    /// Formats the scan report as a Slack Block Kit message payload
    pub fn format_slack_card(report: &ScanReport) -> Value {
        let branding = Self::resolve_branding(report);
        let count = report.findings.len();
        let duration_ms = report.stats.duration_ms;
        let files_scanned = report.stats.files_scanned;

        let fallback_text = if count == 0 {
            format!(
                "{} [CLEAN] Sentris Scan Passed: 0 secrets detected ({} files in {}ms)",
                branding.emoji, files_scanned, duration_ms
            )
        } else {
            format!(
                "{} [{}] Sentris Incident Alert: {} secrets detected ({}ms)",
                branding.emoji, branding.level_name, count, duration_ms
            )
        };

        let mut blocks = vec![
            json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": Self::card_title(&branding, count),
                    "emoji": true
                }
            }),
            json!({
                "type": "section",
                "fields": [
                    mrkdwn(format!("*Branding:*\n{} {}", branding.dot_emoji, branding.level_name)),
                    mrkdwn(format!("*Finding Count:*\n`{count} detected`")),
                    mrkdwn(format!("*Scan Duration:*\n`{duration_ms}ms`")),
                    mrkdwn(format!("*Files Scanned:*\n`{files_scanned}`")),
                ]
            }),
            json!({ "type": "divider" }),
        ];
        blocks.extend(Self::slack_finding_blocks(report));
        blocks.push(json!({ "type": "divider" }));
        blocks.push(json!({
            "type": "section",
            "text": mrkdwn(format!("👉 *Recommended Action:*\n{RECOMMENDED_ACTION}"))
        }));

        json!({
            "text": fallback_text,
            "blocks": blocks,
            "attachments": [{ "color": branding.slack_color }]
        })
    }

    fn slack_finding_blocks(report: &ScanReport) -> Vec<Value> {
        let count = report.findings.len();
        if count == 0 {
            return vec![json!({
                "type": "section",
                "text": mrkdwn("✔ *Repository is clean.* Zero hardcoded secrets detected.".to_string())
            })];
        }
        let mut blocks: Vec<Value> = report
            .findings
            .iter()
            .take(MAX_DISPLAY)
            .enumerate()
            .map(|(idx, finding)| {
                json!({ "type": "section", "text": mrkdwn(Self::slack_finding_text(idx, finding)) })
            })
            .collect();
        if count > MAX_DISPLAY {
            blocks.push(json!({
                "type": "context",
                "elements": [mrkdwn(format!(
                    "⚠️ _...and {} additional findings omitted. Run `sentris scan` locally to review all findings._",
                    count - MAX_DISPLAY
                ))]
            }));
        }
        blocks
    }

    fn slack_finding_text(idx: usize, finding: &Finding) -> String {
        let (badge, sev_name) = Self::severity_badge(finding.severity);
        format!(
            "*Finding #{}: `{}`* ({} {})\n• *File Path:* `{}:{}`\n• *Entropy Score:* `{:.2}`\n• *Masked Preview:* `{}`",
            idx + 1,
            finding.rule_id,
            badge,
            sev_name,
            finding.file_path,
            finding.line_number,
            finding.entropy,
            finding.redacted_match
        )
    }
}

fn mrkdwn(text: String) -> Value {
    json!({ "type": "mrkdwn", "text": text })
}
