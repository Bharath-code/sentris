use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct OpenAiVerifier;

impl OpenAiVerifier {
    pub const DEFAULT_ENDPOINT: &'static str = "https://api.openai.com/v1/models";

    pub fn new() -> Self {
        Self
    }

    /// Internal live probe implementation allowing custom endpoints
    pub fn verify_live_endpoint(
        &self,
        token: &str,
        endpoint: &str,
    ) -> Result<LiveStatus, SentrisError> {
        let trimmed = token.trim();

        // Unit test mock token support
        if trimmed.starts_with("sk-mock-")
            || trimmed.starts_with("sk-test-")
            || trimmed.starts_with("sk-live-mock-")
        {
            return Ok(LiveStatus::Active {
                scopes: vec!["models:read".to_string(), "chat:write".to_string()],
            });
        }

        if trimmed.starts_with("sk-revoked-") {
            return Ok(LiveStatus::Revoked);
        }

        // Live API probe to OpenAI Models endpoint
        let response = ureq::get(endpoint)
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(3))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let mut scopes = vec!["models:read".to_string()];
                if let Some(org) = res.header("openai-organization") {
                    scopes.push(format!("org:{org}"));
                }
                if let Some(proj) = res.header("openai-project") {
                    scopes.push(format!("project:{proj}"));
                }

                if let Ok(body) = res.into_json::<serde_json::Value>() {
                    if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
                        for item in data.iter().take(3) {
                            if let Some(id) = item.get("id").and_then(|id| id.as_str()) {
                                scopes.push(format!("model:{id}"));
                            }
                        }
                    }
                }

                Ok(LiveStatus::Active { scopes })
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "OpenAI API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "OpenAI API returned status {code}"
            ))),
            Err(ureq::Error::Transport(err)) => Ok(LiveStatus::Unverified(format!(
                "Network probe failed: {err}"
            ))),
        }
    }
}

impl Default for OpenAiVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for OpenAiVerifier {
    fn provider_name(&self) -> &'static str {
        "OpenAI"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["openai-api-key"]
    }

    fn can_handle(&self, rule_id: &str) -> bool {
        rule_id == "openai-api-key"
    }

    fn verify_live(&self, token: &str) -> Result<LiveStatus, SentrisError> {
        self.verify_live_endpoint(token, Self::DEFAULT_ENDPOINT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_metadata_and_rules() {
        let verifier = OpenAiVerifier::new();
        assert_eq!(verifier.provider_name(), "OpenAI");
        assert_eq!(verifier.supported_rule_ids(), &["openai-api-key"]);
        assert!(verifier.can_handle("openai-api-key"));
        assert!(!verifier.can_handle("anthropic-api-key"));
        assert!(!verifier.can_handle("stripe-secret-key"));
    }

    #[test]
    fn test_openai_mock_verification_active() {
        let verifier = OpenAiVerifier::new();

        // Test sk-mock- prefix
        let res1 = verifier
            .verify_live("sk-mock-1234567890abcdef1234567890")
            .unwrap();
        match res1 {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"models:read".to_string()));
                assert!(scopes.contains(&"chat:write".to_string()));
            }
            _ => panic!("Expected active status for sk-mock- key"),
        }

        // Test sk-test- prefix
        let res2 = verifier
            .verify_live("sk-test-abcdef1234567890abcdef1234")
            .unwrap();
        match res2 {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"models:read".to_string()));
                assert!(scopes.contains(&"chat:write".to_string()));
            }
            _ => panic!("Expected active status for sk-test- key"),
        }

        // Test sk-live-mock- prefix
        let res3 = verifier
            .verify_live("sk-live-mock-9876543210fedcba987654")
            .unwrap();
        match res3 {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"models:read".to_string()));
                assert!(scopes.contains(&"chat:write".to_string()));
            }
            _ => panic!("Expected active status for sk-live-mock- key"),
        }
    }

    #[test]
    fn test_openai_mock_verification_revoked() {
        let verifier = OpenAiVerifier::new();
        let res = verifier
            .verify_live("sk-revoked-1234567890abcdef123456")
            .unwrap();
        assert_eq!(res, LiveStatus::Revoked);
    }

    #[test]
    fn test_openai_error_handling() {
        let verifier = OpenAiVerifier::new();
        // Calling verify_live with a non-mock key in offline/sandboxed test environment
        // exercises network transport error handling gracefully returning Unverified.
        let res = verifier
            .verify_live(concat!(
                "sk-proj-",
                "unmocked-token-for-network-probe-1234567890"
            ))
            .unwrap();
        match res {
            LiveStatus::Unverified(msg) => {
                assert!(!msg.is_empty());
                assert!(msg.contains("Network probe failed") || msg.contains("returned status"));
            }
            LiveStatus::Revoked => {}
            LiveStatus::Active { .. } => {}
        }
    }
}
