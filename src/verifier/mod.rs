pub mod stripe;

use crate::error::SentrisError;
use serde::{Deserialize, Serialize};

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
    /// Returns the provider name (e.g. "Stripe", "AWS", "GitHub")
    #[allow(dead_code)]
    fn provider_name(&self) -> &'static str;

    /// Checks if this verifier handles the given rule ID
    fn can_handle(&self, rule_id: &str) -> bool;

    /// Checks live status via provider API
    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError>;

    /// Rotates the credential, provisioning a new replacement key
    fn rotate(&self, old_secret: &str, dry_run: bool) -> Result<String, SentrisError>;
}
