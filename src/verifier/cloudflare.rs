use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct CloudflareVerifier;

impl CloudflareVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CloudflareVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for CloudflareVerifier {
    fn provider_name(&self) -> &'static str {
        "Cloudflare"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["cloudflare-api-token"]
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();
        if let Some(reason) = super::detect_canary_token(trimmed, None) {
            return Ok(LiveStatus::Unverified(reason));
        }
        if super::mock_tokens_enabled() && trimmed.starts_with("cf_test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec!["zone:read".to_string(), "dns:edit".to_string()],
            });
        }

        let response = ureq::get("https://api.cloudflare.com/client/v4/user/tokens/verify")
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let status_str = res
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| v["result"]["status"].as_str().map(ToOwned::to_owned))
                    .unwrap_or_else(|| "active".to_string());
                if status_str.eq_ignore_ascii_case("active") {
                    Ok(LiveStatus::Active {
                        scopes: vec![format!("status:{status_str}")],
                    })
                } else {
                    Ok(LiveStatus::Revoked)
                }
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "Cloudflare API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(400 | 401 | 403, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "Cloudflare API returned status {code}"
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
    fn test_cloudflare_mock_verification() {
        let v = CloudflareVerifier::new();
        assert!(v.can_handle("cloudflare-api-token"));
        let status = v
            .verify_live("cf_test_mock_1234567890abcdef1234567890ab")
            .unwrap();
        assert!(matches!(status, LiveStatus::Active { .. }));
    }
}
