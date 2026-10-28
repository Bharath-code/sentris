pub mod anthropic;
pub mod aws;
pub mod github;
pub mod openai;
pub mod slack;
pub mod stripe;

use crate::error::SentrisError;
use serde::{Deserialize, Serialize};

use self::anthropic::AnthropicVerifier;
use self::aws::AwsVerifier;
use self::github::GithubVerifier;
use self::openai::OpenAiVerifier;
use self::slack::SlackVerifier;
use self::stripe::StripeVerifier;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveStatus {
    /// Credential was verified live and active via provider API
    Active { scopes: Vec<String> },
    /// Credential was rejected (revoked, expired, or invalid)
    Revoked,
    /// Credential format is syntactically valid but unverified
    Unverified(String),
}

pub trait ProviderVerifier: Send + Sync {
    /// Returns the provider name (e.g. "Stripe", "AWS", "GitHub", "Slack", "OpenAI", "Anthropic")
    fn provider_name(&self) -> &'static str;

    /// Supported rule IDs for this provider
    fn supported_rule_ids(&self) -> &[&'static str] {
        &[]
    }

    /// Checks if this verifier handles the given rule ID
    fn can_handle(&self, rule_id: &str) -> bool {
        self.supported_rule_ids().contains(&rule_id)
    }

    /// Checks live status via provider API
    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError>;

    /// Provider-side rotation is not implemented for any provider yet; callers must treat the leaked key as still valid
    fn rotate(&self, _old_secret: &str, _dry_run: bool) -> Result<String, SentrisError> {
        Err(SentrisError::NotImplemented(format!(
            "{} key rotation",
            self.provider_name()
        )))
    }
}

pub struct VerifierRegistry {
    verifiers: Vec<Box<dyn ProviderVerifier>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            verifiers: vec![
                Box::new(StripeVerifier::new()),
                Box::new(GithubVerifier::new()),
                Box::new(AwsVerifier::new()),
                Box::new(SlackVerifier::new()),
                Box::new(OpenAiVerifier::new()),
                Box::new(AnthropicVerifier::new()),
            ],
        }
    }

    pub fn find_verifier(&self, rule_id: &str) -> Option<&dyn ProviderVerifier> {
        self.verifiers
            .iter()
            .find(|v| v.can_handle(rule_id))
            .map(|b| b.as_ref())
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_lookup() {
        let registry = VerifierRegistry::new();
        assert_eq!(
            registry
                .find_verifier("stripe-secret-key")
                .unwrap()
                .provider_name(),
            "Stripe"
        );
        assert_eq!(
            registry
                .find_verifier("github-pat")
                .unwrap()
                .provider_name(),
            "GitHub"
        );
        assert_eq!(
            registry
                .find_verifier("aws-access-key-id")
                .unwrap()
                .provider_name(),
            "AWS"
        );
        assert_eq!(
            registry
                .find_verifier("slack-webhook-url")
                .unwrap()
                .provider_name(),
            "Slack"
        );
        assert_eq!(
            registry
                .find_verifier("openai-api-key")
                .unwrap()
                .provider_name(),
            "OpenAI"
        );
        assert_eq!(
            registry
                .find_verifier("anthropic-api-key")
                .unwrap()
                .provider_name(),
            "Anthropic"
        );
        assert!(registry.find_verifier("unknown-rule").is_none());
    }
}
