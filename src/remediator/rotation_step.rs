use crate::error::SentrisError;
use crate::model::Finding;
use crate::remediator::backend::SecretStoreBackend;
use crate::rotator::flow::{provision, ProvisionRequest, DEFAULT_GRACE_SECS};
use crate::rotator::{unix_now, RotationLedger, Rotator};
use owo_colors::OwoColorize;

/// Rotation half of `remediate --rotate`: mints a replacement key and stores it, leaving the old key active.
pub(super) struct RotationStep<'a> {
    pub rotator: Box<dyn Rotator>,
    pub finding: &'a Finding,
    pub backend: &'a dyn SecretStoreBackend,
    pub backend_label: &'a str,
    pub env_var: &'a str,
    pub quiet: bool,
}

impl RotationStep<'_> {
    pub(super) fn guard(&self, dry_run: bool, offline: bool) -> Result<(), SentrisError> {
        if offline {
            return Err(SentrisError::Refused(
                "--rotate calls the provider API; drop --offline".to_string(),
            ));
        }
        if self.backend.is_mock() && !dry_run {
            return Err(SentrisError::Refused(
                "--rotate would create a real key but SENTRIS_MOCK_BACKEND stores nothing; unset it or use a real backend".to_string(),
            ));
        }
        Ok(())
    }

    /// Dry run: read-only provider calls only.
    pub(super) fn preview(&self, raw_secret: &str) -> Result<(), SentrisError> {
        let plan = self.rotator.plan(raw_secret)?;
        if !self.quiet {
            println!(
                "{} (would create a second {} key for '{}'; {} stays active until `sentris rotate finish`)",
                "PLANNED".yellow(),
                self.rotator.provider_name(),
                plan.principal,
                plan.old_key_id
            );
        }
        Ok(())
    }

    pub(super) fn run(&self, raw_secret: &str) -> Result<String, SentrisError> {
        let out = provision(
            self.rotator.as_ref(),
            self.backend,
            &RotationLedger::path(),
            &ProvisionRequest {
                old_secret: raw_secret,
                fingerprint: &self.finding.fingerprint,
                base_var: self.env_var,
                backend_label: self.backend_label,
                now: unix_now(),
                grace_secs: DEFAULT_GRACE_SECS,
            },
        )?;
        if !self.quiet {
            let how = if out.resumed { "RESUMED" } else { "ROTATED" };
            println!(
                "{} (rotation {} • new key stored, old key still active)",
                how.green(),
                out.id.cyan()
            );
        }
        Ok(out.id)
    }
}
