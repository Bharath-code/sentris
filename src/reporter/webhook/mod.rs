#[cfg(test)]
mod tests;

use serde_json::{json, Value};

use crate::error::SentrisError;
use crate::model::{ScanReport, Severity};

pub struct WebhookReporter;

struct Branding {
    level_name: &'static str,
    emoji: &'static str,
    dot_emoji: &'static str,
    slack_color: &'static str,
    discord_color: u32,
}

impl WebhookReporter {
    /// Determines the alert branding based on the highest severity in the scan report
    fn resolve_branding(report: &ScanReport) -> Branding {
        let max_severity = report.findings.iter().map(|f| f.severity).max();
        match max_severity {
            Some(Severity::Critical) => Branding {
                level_name: "Critical Red",
                emoji: "🚨",
                dot_emoji: "🔴",
                slack_color: "#E01E5A",
                discord_color: 15158332, // 0xE74C3C
            },
            Some(Severity::High) => Branding {
                level_name: "High Orange",
                emoji: "⚠️",
                dot_emoji: "🟠",
                slack_color: "#EC6C00",
                discord_color: 15105570, // 0xE67E22
            },
            Some(Severity::Medium) => Branding {
                level_name: "Medium Yellow",
                emoji: "⚠️",
                dot_emoji: "🟡",
                slack_color: "#ECB22E",
                discord_color: 15844367, // 0xF1C40F
            },
            Some(Severity::Low) => Branding {
                level_name: "Low Blue",
                emoji: "ℹ️",
                dot_emoji: "🔵",
                slack_color: "#3498DB",
                discord_color: 3447003, // 0x3498DB
            },
            None => Branding {
                level_name: "Clean Green",
                emoji: "✅",
                dot_emoji: "🟢",
                slack_color: "#2EB886",
                discord_color: 3066993, // 0x2ECC71
            },
        }
    }

    /// Returns the emoji and label for a single finding severity
    fn severity_badge(severity: Severity) -> (&'static str, &'static str) {
        match severity {
            Severity::Critical => ("🔴", "Critical Red"),
            Severity::High => ("🟠", "High Orange"),
            Severity::Medium => ("🟡", "Medium Yellow"),
            Severity::Low => ("🔵", "Low Blue"),
        }
    }

    /// Formats the scan report as a Slack Block Kit message payload
    pub fn format_slack_card(report: &ScanReport) -> Value {
        let branding = Self::resolve_branding(report);
        let finding_count = report.findings.len();
        let duration_ms = report.stats.duration_ms;
        let files_scanned = report.stats.files_scanned;

        let fallback_text = if finding_count == 0 {
            format!(
                "{} [CLEAN] Sentris Scan Passed: 0 secrets detected ({} files in {}ms)",
                branding.emoji, files_scanned, duration_ms
            )
        } else {
            format!(
                "{} [{}] Sentris Incident Alert: {} secrets detected ({}ms)",
                branding.emoji, branding.level_name, finding_count, duration_ms
            )
        };

        let mut blocks = Vec::new();

        // 1. Header block
        let header_title = if finding_count == 0 {
            format!(
                "{} Sentris Scan Clean: Zero Secrets Detected",
                branding.emoji
            )
        } else {
            format!(
                "{} Sentris Incident Alert: Secrets Detected",
                branding.emoji
            )
        };

        blocks.push(json!({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_title,
                "emoji": true
            }
        }));

        // 2. Summary stats section
        let summary_fields = json!([
            {
                "type": "mrkdwn",
                "text": format!("*Branding:*\n{} {}", branding.dot_emoji, branding.level_name)
            },
            {
                "type": "mrkdwn",
                "text": format!("*Finding Count:*\n`{} detected`", finding_count)
            },
            {
                "type": "mrkdwn",
                "text": format!("*Scan Duration:*\n`{}ms`", duration_ms)
            },
            {
                "type": "mrkdwn",
                "text": format!("*Files Scanned:*\n`{}`", files_scanned)
            }
        ]);

        blocks.push(json!({
            "type": "section",
            "fields": summary_fields
        }));

        // 3. Divider
        blocks.push(json!({
            "type": "divider"
        }));

        // 4. Finding details
        if finding_count == 0 {
            blocks.push(json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "✔ *Repository is clean.* Zero hardcoded secrets detected."
                }
            }));
        } else {
            let max_display = 10;
            for (idx, finding) in report.findings.iter().take(max_display).enumerate() {
                let (badge, sev_name) = Self::severity_badge(finding.severity);
                let finding_text = format!(
                    "*Finding #{}: `{}`* ({} {})\n• *File Path:* `{}:{}`\n• *Entropy Score:* `{:.2}`\n• *Masked Preview:* `{}`",
                    idx + 1,
                    finding.rule_id,
                    badge,
                    sev_name,
                    finding.file_path,
                    finding.line_number,
                    finding.entropy,
                    finding.redacted_match
                );
                blocks.push(json!({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": finding_text
                    }
                }));
            }

            if finding_count > max_display {
                let remaining = finding_count - max_display;
                blocks.push(json!({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": format!("⚠️ _...and {} additional findings omitted. Run `sentris scan` locally to review all findings._", remaining)
                        }
                    ]
                }));
            }
        }

        // 5. Divider
        blocks.push(json!({
            "type": "divider"
        }));

        // 6. Recommended action section
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "👉 *Recommended Action:*\nRun 'sentris remediate' to rotate safely with zero downtime"
            }
        }));

        json!({
            "text": fallback_text,
            "blocks": blocks,
            "attachments": [
                {
                    "color": branding.slack_color
                }
            ]
        })
    }

    /// Formats the scan report as a Discord Webhook message payload
    pub fn format_discord_card(report: &ScanReport) -> Value {
        let branding = Self::resolve_branding(report);
        let finding_count = report.findings.len();
        let duration_ms = report.stats.duration_ms;
        let files_scanned = report.stats.files_scanned;

        let content_text = if finding_count == 0 {
            format!(
                "{} **[CLEAN] Sentris Scan Passed** - Zero secrets detected across {} files ({}ms)",
                branding.emoji, files_scanned, duration_ms
            )
        } else {
            format!(
                "{} **[{}] Sentris Incident Alert** - {} secrets detected ({}ms)",
                branding.emoji, branding.level_name, finding_count, duration_ms
            )
        };

        let embed_title = if finding_count == 0 {
            format!(
                "{} Sentris Scan Clean: Zero Secrets Detected",
                branding.emoji
            )
        } else {
            format!(
                "{} Sentris Incident Alert: Secrets Detected",
                branding.emoji
            )
        };

        let embed_description = if finding_count == 0 {
            "Repository scan completed successfully. No hardcoded credentials detected.".to_string()
        } else {
            "Hardcoded secrets detected during scan execution.\n\n🛡️ **Recommended Action:** Run 'sentris remediate' to rotate safely with zero downtime".to_string()
        };

        let mut fields = Vec::new();

        // Summary field
        let summary_val = format!(
            "• **Branding:** {} {}\n• **Finding Count:** {}\n• **Scan Duration:** {}ms\n• **Files Scanned:** {}",
            branding.dot_emoji,
            branding.level_name,
            finding_count,
            duration_ms,
            files_scanned
        );
        fields.push(json!({
            "name": "📊 Scan Summary",
            "value": summary_val,
            "inline": false
        }));

        // Findings fields
        let max_display = 10;
        for (idx, finding) in report.findings.iter().take(max_display).enumerate() {
            let (badge, sev_name) = Self::severity_badge(finding.severity);
            let field_name = format!(
                "{} Finding #{}: {} ({})",
                badge,
                idx + 1,
                finding.rule_id,
                sev_name
            );
            let field_val = format!(
                "• **Rule ID:** `{}`\n• **File Path:** `{}:{}`\n• **Entropy Score:** `{:.2}`\n• **Masked Preview:** `{}`",
                finding.rule_id,
                finding.file_path,
                finding.line_number,
                finding.entropy,
                finding.redacted_match
            );
            fields.push(json!({
                "name": field_name,
                "value": field_val,
                "inline": false
            }));
        }

        if finding_count > max_display {
            let remaining = finding_count - max_display;
            fields.push(json!({
                "name": "⚠️ Additional Findings",
                "value": format!("...and {} additional findings omitted. Run `sentris scan` locally.", remaining),
                "inline": false
            }));
        }

        // Recommended action field
        fields.push(json!({
            "name": "🛡️ Recommended Action",
            "value": "Run 'sentris remediate' to rotate safely with zero downtime",
            "inline": false
        }));

        let embed = json!({
            "title": embed_title,
            "description": embed_description,
            "color": branding.discord_color,
            "fields": fields,
            "footer": {
                "text": "Sentris Security Scanner • Zero-Downtime Secret Remediation"
            },
            "timestamp": if report.timestamp.is_empty() {
                "2026-10-07T00:00:00Z".to_string()
            } else {
                report.timestamp.clone()
            }
        });

        json!({
            "content": content_text,
            "embeds": [embed]
        })
    }

    /// Dispatches an incident alert card to Slack or Discord webhook
    pub fn post_incident_card(
        webhook_url: &str,
        report: &ScanReport,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        let trimmed_url = webhook_url.trim();
        if trimmed_url.is_empty() {
            return Err(SentrisError::Webhook(
                "Webhook URL cannot be empty".to_string(),
            ));
        }

        let is_discord =
            trimmed_url.contains("discord.com") || trimmed_url.contains("discordapp.com");
        let provider = if is_discord { "Discord" } else { "Slack" };

        let payload = if is_discord {
            Self::format_discord_card(report)
        } else {
            Self::format_slack_card(report)
        };

        if dry_run {
            return Ok(format!(
                "[DRY RUN] Webhook alert card simulated successfully for {} ({}) - {} findings",
                provider,
                trimmed_url,
                report.findings.len()
            ));
        }

        let response = ureq::post(trimmed_url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(10))
            .send_json(&payload);

        match response {
            Ok(res) => {
                let status = res.status();
                if (200..=299).contains(&status) {
                    Ok(format!(
                        "Successfully posted incident card to {} ({}) with HTTP {}",
                        provider, trimmed_url, status
                    ))
                } else {
                    let body = res.into_string().unwrap_or_default();
                    Err(SentrisError::Webhook(format!(
                        "Webhook endpoint responded with HTTP {}: {}",
                        status, body
                    )))
                }
            }
            Err(ureq::Error::Status(status, res)) => {
                let body = res.into_string().unwrap_or_default();
                Err(SentrisError::Webhook(format!(
                    "Webhook endpoint responded with HTTP {}: {}",
                    status, body
                )))
            }
            Err(ureq::Error::Transport(err)) => Err(SentrisError::Webhook(format!(
                "Network transport error (offline or unreachable host): {}",
                err
            ))),
        }
    }
}
