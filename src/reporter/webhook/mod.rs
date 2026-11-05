#[cfg(test)]
mod tests;

mod discord;
mod slack;

use crate::error::SentrisError;
use crate::model::{ScanReport, Severity};

pub struct WebhookReporter;

/// Findings listed individually in a card; the rest are summarised as "N omitted".
const MAX_DISPLAY: usize = 10;
const RECOMMENDED_ACTION: &str =
    "Run 'sentris remediate' to move the secret out of source (then revoke the old key)";

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

    /// Card title shared by both providers.
    fn card_title(branding: &Branding, finding_count: usize) -> String {
        if finding_count == 0 {
            format!(
                "{} Sentris Scan Clean: Zero Secrets Detected",
                branding.emoji
            )
        } else {
            format!(
                "{} Sentris Incident Alert: Secrets Detected",
                branding.emoji
            )
        }
    }

    /// Dispatches an incident alert card to Slack or Discord webhook
    pub fn post_incident_card(
        webhook_url: &str,
        report: &ScanReport,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        let trimmed_url = webhook_url.trim();
        let target = Target::parse(trimmed_url)?;
        let payload = if target.is_discord {
            Self::format_discord_card(report)
        } else {
            Self::format_slack_card(report)
        };

        if dry_run {
            return Ok(format!(
                "[DRY RUN] Webhook alert card simulated successfully for {} ({}) - {} findings",
                target.provider(),
                target.shown,
                report.findings.len()
            ));
        }
        target.post(trimmed_url, &payload)
    }

    /// Dispatches a Secret Rot & Configuration Drift alert card to Slack or Discord webhook.
    pub fn post_drift_rot_card(
        webhook_url: &str,
        report: &crate::drift::DriftReport,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        let trimmed_url = webhook_url.trim();
        let target = Target::parse(trimmed_url)?;
        let status_label = if report.has_rot {
            "🚨 Secret Rot Detected"
        } else if report.has_drift {
            "⚠️ Configuration Drift Detected"
        } else {
            "✅ Zero Secret Rot & 100% Healthy"
        };
        let summary_text = format!(
            "{status_label} | Vault Coverage: {:.1}% | Rot Score: {:.1}% | Leaked: {} | Stale (>max age): {} | Dead/Revoked: {} | Orphaned (.env): {} | Missing (.env): {}",
            report.vault_coverage_pct,
            report.rot_score_pct,
            report.hardcoded_leaks_count,
            report.stale_keys.len(),
            report.dead_or_revoked_keys.len(),
            report.shadow_env_vars.len(),
            report.missing_from_env.len(),
        );
        let payload = if target.is_discord {
            serde_json::json!({
                "content": summary_text,
            })
        } else {
            serde_json::json!({
                "text": summary_text,
            })
        };
        if dry_run {
            return Ok(format!(
                "[DRY RUN] Secret Rot webhook alert card simulated for {} ({})",
                target.provider(),
                target.shown
            ));
        }
        target.post(trimmed_url, &payload)
    }
}

/// Where a card is going, with a form of the URL that is safe to print.
struct Target {
    is_discord: bool,
    shown: String,
}

impl Target {
    fn parse(url: &str) -> Result<Self, SentrisError> {
        if url.is_empty() {
            return Err(SentrisError::Webhook(
                "Webhook URL cannot be empty".to_string(),
            ));
        }
        let rest = url.strip_prefix("https://").ok_or_else(|| {
            SentrisError::Webhook("Webhook URL must start with https://".to_string())
        })?;
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let is_discord = ["discord.com", "discordapp.com"]
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")));
        Ok(Self {
            is_discord,
            // The URL path is the credential, so messages only ever show the host
            shown: format!("https://{host}/…"),
        })
    }

    fn provider(&self) -> &'static str {
        if self.is_discord {
            "Discord"
        } else {
            "Slack"
        }
    }

    fn post(&self, url: &str, payload: &serde_json::Value) -> Result<String, SentrisError> {
        let shown = &self.shown;
        let response = ureq::post(url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(10))
            .send_json(payload);
        match response {
            Ok(res) if (200..=299).contains(&res.status()) => Ok(format!(
                "Successfully posted incident card to {} ({shown}) with HTTP {}",
                self.provider(),
                res.status()
            )),
            Ok(res) => Err(SentrisError::Webhook(format!(
                "Webhook endpoint {shown} responded with HTTP {}",
                res.status()
            ))),
            Err(ureq::Error::Status(status, _)) => Err(SentrisError::Webhook(format!(
                "Webhook endpoint {shown} responded with HTTP {status}"
            ))),
            Err(ureq::Error::Transport(err)) => Err(SentrisError::Webhook(format!(
                "Network transport error reaching {shown} (offline or unreachable host): {}",
                err.kind()
            ))),
        }
    }
}
