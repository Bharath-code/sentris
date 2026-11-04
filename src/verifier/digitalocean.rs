use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct DigitalOceanVerifier;

impl DigitalOceanVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DigitalOceanVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for DigitalOceanVerifier {
    fn provider_name(&self) -> &'static str {
        "DigitalOcean"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["digitalocean-access-token"]
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();
        if let Some(reason) = super::detect_canary_token(trimmed, None) {
            return Ok(LiveStatus::Unverified(reason));
        }
        if super::mock_tokens_enabled() && trimmed.starts_with("dop_v1_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec!["account:read".to_string(), "droplet:write".to_string()],
            });
        }

        let response = ureq::get("https://api.digitalocean.com/v2/account")
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let status = res
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| v["account"]["status"].as_str().map(ToOwned::to_owned))
                    .unwrap_or_else(|| "active".to_string());
                Ok(LiveStatus::Active {
                    scopes: vec![format!("account:{status}")],
                })
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "DigitalOcean API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401 | 403, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "DigitalOcean API returned status {code}"
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
    fn test_digitalocean_mock_verification() {
        let v = DigitalOceanVerifier::new();
        assert!(v.can_handle("digitalocean-access-token"));
        let status = v
            .verify_live("dop_v1_mock_0123456789abcdef0123456789abcdef0123456789abcdef0123")
            .unwrap();
        assert!(matches!(status, LiveStatus::Active { .. }));
    }
}
