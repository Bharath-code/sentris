use serde_json::{json, Value};

use crate::error::SentrisError;
use crate::model::{ScanReport, Severity};

#[allow(dead_code)]
pub struct WebhookReporter;

#[allow(dead_code)]
struct Branding {
    level_name: &'static str,
    emoji: &'static str,
    dot_emoji: &'static str,
    slack_color: &'static str,
    discord_color: u32,
}

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, ScanStats};

    fn create_test_finding(
        rule_id: &str,
        severity: Severity,
        file: &str,
        line: usize,
        preview: &str,
        entropy: f64,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: format!("Identifies {}", rule_id),
            severity,
            file_path: file.to_string(),
            line_number: line,
            column: 15,
            redacted_match: preview.to_string(),
            entropy,
            fingerprint: "test-fingerprint-123".to_string(),
            commit_hash: None,
        }
    }

    fn create_test_report(findings: Vec<Finding>, duration_ms: u128) -> ScanReport {
        let count = findings.len();
        ScanReport {
            timestamp: "2026-10-07T18:54:21Z".to_string(),
            version: "0.1.0".to_string(),
            stats: ScanStats {
                files_scanned: 15,
                files_ignored: 2,
                bytes_scanned: 10240,
                findings_count: count,
                duration_ms,
            },
            findings,
        }
    }

    #[test]
    fn test_format_slack_card_critical() {
        let findings = vec![create_test_finding(
            "aws-access-key-id",
            Severity::Critical,
            "src/config/aws.rs",
            42,
            "AKIA...7EXA",
            3.84,
        )];
        let report = create_test_report(findings, 45);

        let card = WebhookReporter::format_slack_card(&report);

        // Verify fallback text
        let text = card["text"].as_str().expect("text should be string");
        assert!(text.contains("🚨"));
        assert!(text.contains("Critical Red"));
        assert!(text.contains("1 secrets detected"));
        assert!(text.contains("45ms"));

        // Verify attachments color branding
        let color = card["attachments"][0]["color"].as_str().unwrap();
        assert_eq!(color, "#E01E5A");

        // Verify Block Kit blocks structure
        let blocks = card["blocks"].as_array().expect("blocks should be array");
        assert!(blocks.len() >= 5);

        // Header
        let header_text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(header_text.contains("🚨 Sentris Incident Alert: Secrets Detected"));

        // Summary fields
        let summary_fields = blocks[1]["fields"].as_array().unwrap();
        let branding_field = summary_fields[0]["text"].as_str().unwrap();
        assert!(branding_field.contains("🔴 Critical Red"));

        let count_field = summary_fields[1]["text"].as_str().unwrap();
        assert!(count_field.contains("1 detected"));

        let duration_field = summary_fields[2]["text"].as_str().unwrap();
        assert!(duration_field.contains("45ms"));

        // Finding detail block
        let finding_block_text = blocks[3]["text"]["text"].as_str().unwrap();
        assert!(finding_block_text.contains("aws-access-key-id"));
        assert!(finding_block_text.contains("src/config/aws.rs:42"));
        assert!(finding_block_text.contains("3.84"));
        assert!(finding_block_text.contains("AKIA...7EXA"));

        // Recommended action
        let action_block_text = blocks.last().unwrap()["text"]["text"].as_str().unwrap();
        assert!(action_block_text
            .contains("Run 'sentris remediate' to rotate safely with zero downtime"));
    }

    #[test]
    fn test_format_slack_card_high_orange() {
        let findings = vec![create_test_finding(
            "slack-webhook-url",
            Severity::High,
            "deploy/notify.sh",
            12,
            "https://hooks.slack.com/services/...xyz",
            2.95,
        )];
        let report = create_test_report(findings, 28);

        let card = WebhookReporter::format_slack_card(&report);

        let color = card["attachments"][0]["color"].as_str().unwrap();
        assert_eq!(color, "#EC6C00");

        let text = card["text"].as_str().unwrap();
        assert!(text.contains("High Orange"));
        assert!(text.contains("⚠️"));

        let blocks = card["blocks"].as_array().unwrap();
        let summary = blocks[1]["fields"][0]["text"].as_str().unwrap();
        assert!(summary.contains("🟠 High Orange"));

        let finding_text = blocks[3]["text"]["text"].as_str().unwrap();
        assert!(finding_text.contains("slack-webhook-url"));
        assert!(finding_text.contains("deploy/notify.sh:12"));
        assert!(finding_text.contains("2.95"));
    }

    #[test]
    fn test_format_discord_card_critical() {
        let findings = vec![create_test_finding(
            "stripe-secret-key",
            Severity::Critical,
            "backend/payments.rs",
            88,
            "sk_live_...999",
            4.15,
        )];
        let report = create_test_report(findings, 62);

        let card = WebhookReporter::format_discord_card(&report);

        let content = card["content"].as_str().unwrap();
        assert!(content.contains("🚨"));
        assert!(content.contains("Critical Red"));
        assert!(content.contains("1 secrets detected"));

        let embeds = card["embeds"].as_array().expect("embeds must be array");
        assert_eq!(embeds.len(), 1);

        let embed = &embeds[0];
        assert_eq!(embed["color"].as_u64().unwrap(), 15158332);

        let desc = embed["description"].as_str().unwrap();
        assert!(desc.contains("Run 'sentris remediate' to rotate safely with zero downtime"));

        let fields = embed["fields"].as_array().unwrap();
        // Check Scan Summary field
        assert_eq!(fields[0]["name"].as_str().unwrap(), "📊 Scan Summary");
        let summary_val = fields[0]["value"].as_str().unwrap();
        assert!(summary_val.contains("🔴 Critical Red"));
        assert!(summary_val.contains("Finding Count:** 1"));
        assert!(summary_val.contains("Scan Duration:** 62ms"));

        // Check Finding field
        let finding_field = &fields[1];
        assert!(finding_field["name"]
            .as_str()
            .unwrap()
            .contains("stripe-secret-key"));
        let val = finding_field["value"].as_str().unwrap();
        assert!(val.contains("backend/payments.rs:88"));
        assert!(val.contains("4.15"));
        assert!(val.contains("sk_live_...999"));

        // Check Recommended Action field
        let action_field = fields.last().unwrap();
        assert_eq!(
            action_field["name"].as_str().unwrap(),
            "🛡️ Recommended Action"
        );
        assert_eq!(
            action_field["value"].as_str().unwrap(),
            "Run 'sentris remediate' to rotate safely with zero downtime"
        );
    }

    #[test]
    fn test_format_discord_card_high_orange() {
        let findings = vec![create_test_finding(
            "discord-webhook-url",
            Severity::High,
            "scripts/alert.js",
            5,
            "https://discord.com/api/webhooks/...abc",
            3.10,
        )];
        let report = create_test_report(findings, 19);

        let card = WebhookReporter::format_discord_card(&report);

        let embed = &card["embeds"][0];
        assert_eq!(embed["color"].as_u64().unwrap(), 15105570);

        let summary = embed["fields"][0]["value"].as_str().unwrap();
        assert!(summary.contains("🟠 High Orange"));
        assert!(summary.contains("Scan Duration:** 19ms"));
    }

    #[test]
    fn test_format_cards_clean_repository() {
        let report = create_test_report(Vec::new(), 10);

        // Slack clean
        let slack = WebhookReporter::format_slack_card(&report);
        assert_eq!(
            slack["attachments"][0]["color"].as_str().unwrap(),
            "#2EB886"
        );
        let slack_text = slack["text"].as_str().unwrap();
        assert!(slack_text.contains("CLEAN"));
        assert!(slack_text.contains("0 secrets detected"));

        // Discord clean
        let discord = WebhookReporter::format_discord_card(&report);
        let embed = &discord["embeds"][0];
        assert_eq!(embed["color"].as_u64().unwrap(), 3066993);
        let discord_content = discord["content"].as_str().unwrap();
        assert!(discord_content.contains("CLEAN"));
    }

    #[test]
    fn test_post_incident_card_dry_run() {
        let findings = vec![create_test_finding(
            "aws-access-key-id",
            Severity::Critical,
            "test.rs",
            1,
            "AKIA...7EXA",
            3.8,
        )];
        let report = create_test_report(findings, 50);

        // Slack dry run
        let slack_res = WebhookReporter::post_incident_card(
            "https://hooks.slack.com/services/T000/B000/XXXX",
            &report,
            true,
        );
        assert!(slack_res.is_ok());
        let msg = slack_res.unwrap();
        assert!(msg.contains("[DRY RUN]"));
        assert!(msg.contains("Slack"));
        assert!(msg.contains("1 findings"));

        // Discord dry run
        let discord_res = WebhookReporter::post_incident_card(
            "https://discord.com/api/webhooks/12345/abcdef",
            &report,
            true,
        );
        assert!(discord_res.is_ok());
        let msg = discord_res.unwrap();
        assert!(msg.contains("[DRY RUN]"));
        assert!(msg.contains("Discord"));
        assert!(msg.contains("1 findings"));
    }

    #[test]
    fn test_post_incident_card_empty_url() {
        let report = create_test_report(Vec::new(), 10);
        let res = WebhookReporter::post_incident_card("", &report, false);
        assert!(res.is_err());
        match res.unwrap_err() {
            SentrisError::Webhook(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected SentrisError::Webhook"),
        }
    }

    #[test]
    fn test_post_incident_card_offline_transport_error() {
        let findings = vec![create_test_finding(
            "aws-access-key-id",
            Severity::Critical,
            "test.rs",
            1,
            "AKIA...7EXA",
            3.8,
        )];
        let report = create_test_report(findings, 50);

        // Attempting to post to a closed loopback port should gracefully return transport error
        let res = WebhookReporter::post_incident_card("http://127.0.0.1:9/webhook", &report, false);
        assert!(res.is_err());
        match res.unwrap_err() {
            SentrisError::Webhook(msg) => {
                assert!(
                    msg.contains("transport") || msg.contains("offline") || msg.contains("failed")
                );
            }
            _ => panic!("Expected SentrisError::Webhook"),
        }
    }
}
