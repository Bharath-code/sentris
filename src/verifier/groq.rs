use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct GroqVerifier;

impl GroqVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GroqVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for GroqVerifier {
    fn provider_name(&self) -> &'static str {
        "Groq"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["groq-api-key"]
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();
        if super::mock_tokens_enabled() && trimmed.starts_with("gsk_test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec!["models:read".to_string(), "chat:completions".to_string()],
            });
        }

        let response = ureq::get("https://api.groq.com/openai/v1/models")
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => Ok(LiveStatus::Active {
                scopes: vec!["models:read".to_string(), "chat:completions".to_string()],
            }),
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "Groq API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "Groq API returned status {code}"
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
    fn test_groq_mock_verification() {
        let v = GroqVerifier::new();
        assert!(v.can_handle("groq-api-key"));
        let status = v.verify_live("gsk_test_mock_1234567890abcdef").unwrap();
        assert!(matches!(status, LiveStatus::Active { .. }));
    }
}
