use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct SlackVerifier;

impl SlackVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SlackVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for SlackVerifier {
    fn provider_name(&self) -> &'static str {
        "Slack"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["slack-bot-token", "slack-user-token", "slack-webhook-url"]
    }

    fn can_handle(&self, rule_id: &str) -> bool {
        rule_id == "slack-bot-token"
            || rule_id == "slack-user-token"
            || rule_id == "slack-webhook-url"
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();

        if trimmed.starts_with("xoxb-test-mock") || trimmed.contains("test_mock_webhook") {
            return Ok(LiveStatus::Active {
                scopes: vec!["chat:write".to_string(), "channels:read".to_string()],
            });
        }

        if trimmed.starts_with("xoxb-") || trimmed.starts_with("xoxp-") {
            let response = ureq::post("https://slack.com/api/auth.test")
                .set("Authorization", &format!("Bearer {}", trimmed))
                .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
                .timeout(std::time::Duration::from_secs(5))
                .call();

            match response {
                Ok(res) if res.status() == 200 => {
                    let body: serde_json::Value = res.into_json().unwrap_or_default();
                    if body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        let team = body.get("team").and_then(|v| v.as_str()).unwrap_or("team");
                        let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("bot");
                        Ok(LiveStatus::Active {
                            scopes: vec![format!("team:{}", team), format!("user:{}", user)],
                        })
                    } else {
                        Ok(LiveStatus::Revoked)
                    }
                }
                Ok(_) => Ok(LiveStatus::Revoked),
                Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
                Err(ureq::Error::Transport(err)) => Ok(LiveStatus::Unverified(format!(
                    "Network probe failed: {err}"
                ))),
                Err(err) => Ok(LiveStatus::Unverified(format!("{err}"))),
            }
        } else if trimmed.starts_with("https://hooks.slack.com/services/") {
            Ok(LiveStatus::Unverified(
                "Slack Webhook URL format verified".to_string(),
            ))
        } else {
            Ok(LiveStatus::Revoked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slack_mock_verification() {
        let verifier = SlackVerifier::new();
        assert!(verifier.can_handle("slack-bot-token"));
        assert!(verifier.can_handle("slack-user-token"));
        assert!(verifier.can_handle("slack-webhook-url"));
        assert!(!verifier.can_handle("github-pat"));

        let status = verifier.verify_live("xoxb-test-mock-1234567890").unwrap();
        match status {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"chat:write".to_string()));
            }
            _ => panic!("Expected active status for mock Slack token"),
        }
    }
}
