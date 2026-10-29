pub mod aws;
pub mod flow;
pub mod ledger;

pub mod timefmt;

pub use ledger::RotationLedger;

use crate::error::SentrisError;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationState {
    Planned,
    Minted,
    Stored,
    OldDeactivated,
    OldDeleted,
    RolledBack,
}

impl RotationState {
    pub fn can_advance_to(self, next: Self) -> bool {
        use RotationState::*;
        matches!(
            (self, next),
            (Planned, Minted)
                | (Planned, RolledBack)
                | (Minted, Stored)
                | (Minted, RolledBack)
                | (Stored, OldDeactivated)
                | (Stored, RolledBack)
                | (OldDeactivated, OldDeleted)
                | (OldDeactivated, RolledBack)
        )
    }
}

/// What a rotator learned about the leaked key before touching anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationPlan {
    pub provider: String,
    pub rule_id: String,
    pub principal: String,
    pub old_key_id: String,
    pub old_fingerprint: String,
}

/// When and where the provider last saw a key in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastUse {
    pub at: u64,
    pub service: String,
    pub region: String,
}

/// Fresh credential returned by a provider. `secret` exists only in memory; it is never serialized or printed.
pub struct MintedCredential {
    pub key_id: String,
    pub secret: String,
}

impl fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedCredential")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Persisted state of one rotation. Holds key ids and a fingerprint, never a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    pub id: String,
    pub provider: String,
    pub rule_id: String,
    pub principal: String,
    pub old_key_id: String,
    pub old_fingerprint: String,
    pub new_key_id: Option<String>,
    pub backend: String,
    pub state: RotationState,
    pub created_at: u64,
    pub grace_until: u64,
}

impl RotationRecord {
    pub fn plan(&self) -> RotationPlan {
        RotationPlan {
            provider: self.provider.clone(),
            rule_id: self.rule_id.clone(),
            principal: self.principal.clone(),
            old_key_id: self.old_key_id.clone(),
            old_fingerprint: self.old_fingerprint.clone(),
        }
    }

    pub fn new(id: &str, backend: &str, plan: &RotationPlan, now: u64, grace_secs: u64) -> Self {
        Self {
            id: id.to_string(),
            provider: plan.provider.clone(),
            rule_id: plan.rule_id.clone(),
            principal: plan.principal.clone(),
            old_key_id: plan.old_key_id.clone(),
            old_fingerprint: plan.old_fingerprint.clone(),
            new_key_id: None,
            backend: backend.to_string(),
            state: RotationState::Planned,
            created_at: now,
            grace_until: now + grace_secs,
        }
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Rotator for a detection rule, or `None` when the provider cannot be rotated.
pub fn rotator_for_rule(rule_id: &str) -> Option<Box<dyn Rotator>> {
    match rule_id {
        "aws-access-key-id" => Some(Box::new(aws::AwsRotator::new())),
        _ => None,
    }
}

pub fn new_rotation_id() -> Result<String, SentrisError> {
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).map_err(|e| SentrisError::Config(e.to_string()))?;
    Ok(format!("rot_{}", hex::encode(rnd)))
}

/// Provider-side key lifecycle. Implementations must never put a secret in argv, logs or error text.
pub trait Rotator: Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn plan(&self, old_secret: &str) -> Result<RotationPlan, SentrisError>;
    fn mint(&self, plan: &RotationPlan) -> Result<MintedCredential, SentrisError>;
    fn deactivate_old(&self, plan: &RotationPlan) -> Result<(), SentrisError>;
    fn reactivate_old(&self, plan: &RotationPlan) -> Result<(), SentrisError>;
    fn discard_new(&self, plan: &RotationPlan, new_key_id: &str) -> Result<(), SentrisError>;
    fn delete_old(&self, plan: &RotationPlan) -> Result<(), SentrisError>;
    /// Last observed use of the old key; `finish` refuses to deactivate a key that is still in use.
    fn last_used(&self, plan: &RotationPlan) -> Result<Option<LastUse>, SentrisError>;
    /// Env var entries to store for a new credential; the first entry replaces the literal in code. Stored in reverse so a failure leaves only junk, never a dangling primary.
    fn env_values(&self, base_var: &str, minted: &MintedCredential) -> Vec<(String, String)> {
        vec![(base_var.to_string(), minted.secret.clone())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_ids_are_unique_and_prefixed() {
        let (a, b) = (new_rotation_id().unwrap(), new_rotation_id().unwrap());
        assert!(a.starts_with("rot_") && a.len() == 20);
        assert_ne!(a, b);
    }
}
