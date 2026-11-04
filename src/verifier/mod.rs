pub mod anthropic;
pub mod aws;
pub mod cloudflare;
pub mod digitalocean;
pub mod github;
pub mod gitlab;
pub mod groq;
pub mod huggingface;
pub mod openai;
pub mod sendgrid;
pub mod slack;
pub mod stripe;

use crate::error::SentrisError;
use serde::{Deserialize, Serialize};

use self::anthropic::AnthropicVerifier;
use self::aws::AwsVerifier;
use self::cloudflare::CloudflareVerifier;
use self::digitalocean::DigitalOceanVerifier;
use self::github::GithubVerifier;
use self::gitlab::GitlabVerifier;
use self::groq::GroqVerifier;
use self::huggingface::HuggingFaceVerifier;
use self::openai::OpenAiVerifier;
use self::sendgrid::SendgridVerifier;
use self::slack::SlackVerifier;
use self::stripe::StripeVerifier;

/// Detects Thinkst Canary, GitGuardian Honeytoken, or custom canary tripwire markers before any
/// outbound network call is made, preventing false-positive intrusion alarms during `scan --verify`.
pub fn detect_canary_token(secret: &str, context_line: Option<&str>) -> Option<String> {
    const CANARY_MARKERS: &[&str] = &[
        "canarytokens.com",
        "canarytokens.org",
        "canarytokens",
        "thinkst",
        "ggcanary",
        "honeytoken",
        "sentris-canary",
        "canary_tripwire",
    ];
    let sec_lower = secret.to_ascii_lowercase();
    for &marker in CANARY_MARKERS {
        if sec_lower.contains(marker) {
            return Some(format!(
                "Canary/Honeytoken tripwire detected ({marker}) — network verification skipped"
            ));
        }
    }
    if let Some(line) = context_line {
        let line_lower = line.to_ascii_lowercase();
        for &marker in CANARY_MARKERS {
            if line_lower.contains(marker) {
                return Some(format!(
                    "Canary/Honeytoken tripwire detected ({marker}) — network verification skipped"
                ));
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveStatus {
    /// Credential was verified live and active via provider API
    Active { scopes: Vec<String> },
    /// Credential was rejected (revoked, expired, or invalid)
    Revoked,
    /// Credential format is syntactically valid but unverified
    Unverified(String),
}

/// Canned "Active" answers for fake tokens exist for tests only; in a real build a planted token must not read as verified.
pub(crate) fn mock_tokens_enabled() -> bool {
    cfg!(test)
        || std::env::var("SENTRIS_VERIFIER_MOCK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
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
                Box::new(HuggingFaceVerifier::new()),
                Box::new(GitlabVerifier::new()),
                Box::new(GroqVerifier::new()),
                Box::new(SendgridVerifier::new()),
                Box::new(CloudflareVerifier::new()),
                Box::new(DigitalOceanVerifier::new()),
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
        assert_eq!(
            registry
                .find_verifier("cloudflare-api-token")
                .unwrap()
                .provider_name(),
            "Cloudflare"
        );
        assert_eq!(
            registry
                .find_verifier("digitalocean-access-token")
                .unwrap()
                .provider_name(),
            "DigitalOcean"
        );
        assert!(registry.find_verifier("unknown-rule").is_none());
    }

    #[test]
    fn test_canary_honeytoken_detection_skips_network() {
        assert!(detect_canary_token(
            "AKIA1234567890ABCDEF",
            Some("AWS_KEY = \"AKIA1234567890ABCDEF\" # thinkst canary_tripwire")
        )
        .is_some());
        assert!(
            detect_canary_token("https://canarytokens.com/stuff/abc123/submit.aspx", None)
                .is_some()
        );
        assert!(detect_canary_token(
            "sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz123456",
            Some("const key = \"sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz123456\";")
        )
        .is_none());
    }
}
