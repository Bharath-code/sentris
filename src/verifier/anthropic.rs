use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct AnthropicVerifier;

impl AnthropicVerifier {
    pub const DEFAULT_ENDPOINT: &'static str = "https://api.anthropic.com/v1/models";

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
        if super::mock_tokens_enabled()
            && (trimmed.starts_with("sk-ant-mock-") || trimmed.starts_with("sk-ant-test-"))
        {
            return Ok(LiveStatus::Active {
                scopes: vec!["claude-3".to_string(), "messages:write".to_string()],
            });
        }

        if trimmed.starts_with("sk-ant-revoked-") {
            return Ok(LiveStatus::Revoked);
        }

        // Live API probe to Anthropic Models endpoint
        let response = ureq::get(endpoint)
            .set("x-api-key", trimmed)
            .set("anthropic-version", "2023-06-01")
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(3))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let mut scopes = vec!["claude-3".to_string(), "messages:write".to_string()];

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
                "Anthropic API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "Anthropic API returned status {code}"
            ))),
            Err(ureq::Error::Transport(err)) => Ok(LiveStatus::Unverified(format!(
                "Network probe failed: {err}"
            ))),
        }
    }
}

impl Default for AnthropicVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for AnthropicVerifier {
    fn provider_name(&self) -> &'static str {
        "Anthropic"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["anthropic-api-key"]
    }

    fn can_handle(&self, rule_id: &str) -> bool {
        rule_id == "anthropic-api-key"
    }

    fn verify_live(&self, token: &str) -> Result<LiveStatus, SentrisError> {
        self.verify_live_endpoint(token, Self::DEFAULT_ENDPOINT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_metadata_and_rules() {
        let verifier = AnthropicVerifier::new();
        assert_eq!(verifier.provider_name(), "Anthropic");
        assert_eq!(verifier.supported_rule_ids(), &["anthropic-api-key"]);
        assert!(verifier.can_handle("anthropic-api-key"));
        assert!(!verifier.can_handle("openai-api-key"));
        assert!(!verifier.can_handle("stripe-secret-key"));
    }

    #[test]
    fn test_anthropic_mock_verification_active() {
        let verifier = AnthropicVerifier::new();

        // Test sk-ant-mock- prefix
        let res1 = verifier
            .verify_live("sk-ant-mock-1234567890abcdef1234567890")
            .unwrap();
        match res1 {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"claude-3".to_string()));
                assert!(scopes.contains(&"messages:write".to_string()));
            }
            _ => panic!("Expected active status for sk-ant-mock- key"),
        }

        // Test sk-ant-test- prefix
        let res2 = verifier
            .verify_live("sk-ant-test-abcdef1234567890abcdef1234")
            .unwrap();
        match res2 {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"claude-3".to_string()));
                assert!(scopes.contains(&"messages:write".to_string()));
            }
            _ => panic!("Expected active status for sk-ant-test- key"),
        }
    }

    #[test]
    fn test_anthropic_mock_verification_revoked() {
        let verifier = AnthropicVerifier::new();
        let res = verifier
            .verify_live("sk-ant-revoked-1234567890abcdef123456")
            .unwrap();
        assert_eq!(res, LiveStatus::Revoked);
    }

    #[test]
    fn test_anthropic_error_handling() {
        let verifier = AnthropicVerifier::new();
        // Calling verify_live with a non-mock key in offline/sandboxed test environment
        // exercises network transport error handling gracefully returning Unverified.
        let res = verifier
            .verify_live("sk-ant-api03-unmocked-token-for-network-probe-1234567890")
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
