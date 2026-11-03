use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct HuggingFaceVerifier;

impl HuggingFaceVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HuggingFaceVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for HuggingFaceVerifier {
    fn provider_name(&self) -> &'static str {
        "HuggingFace"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["huggingface-token"]
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();
        if super::mock_tokens_enabled() && trimmed.starts_with("hf_test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec!["write".to_string(), "orgs:read".to_string()],
            });
        }

        let response = ureq::get("https://huggingface.co/api/whoami-v2")
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let role = res
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| {
                        v["auth"]["accessToken"]["role"]
                            .as_str()
                            .map(ToOwned::to_owned)
                    })
                    .unwrap_or_else(|| "read".to_string());
                Ok(LiveStatus::Active { scopes: vec![role] })
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "HuggingFace API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "HuggingFace API returned status {code}"
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
    fn test_huggingface_mock_verification() {
        let v = HuggingFaceVerifier::new();
        assert!(v.can_handle("huggingface-token"));
        let status = v.verify_live("hf_test_mock_1234567890abcdef").unwrap();
        assert!(matches!(status, LiveStatus::Active { .. }));
    }
}
