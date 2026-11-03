use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct SendgridVerifier;

impl SendgridVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SendgridVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for SendgridVerifier {
    fn provider_name(&self) -> &'static str {
        "SendGrid"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["sendgrid-api-key"]
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();
        if super::mock_tokens_enabled() && trimmed.starts_with("SG.test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec!["mail.send".to_string()],
            });
        }

        let response = ureq::get("https://api.sendgrid.com/v3/scopes")
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let scopes = res
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| {
                        v["scopes"].as_array().map(|arr| {
                            arr.iter()
                                .take(10)
                                .filter_map(|s| s.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                    })
                    .unwrap_or_else(|| vec!["authenticated".to_string()]);
                Ok(LiveStatus::Active { scopes })
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "SendGrid API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401 | 403, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "SendGrid API returned status {code}"
            ))),
            Err(ureq::Error::Transport(err)) => Ok(LiveStatus::Unverified(format!(
                "Network probe failed: {err}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sendgrid_mock_verification() {
        let v = SendgridVerifier::new();
        assert!(v.can_handle("sendgrid-api-key"));
        let status = v.verify_live("SG.test_mock_1234567890abcdef").unwrap();
        assert!(matches!(status, LiveStatus::Active { .. }));
    }
}
