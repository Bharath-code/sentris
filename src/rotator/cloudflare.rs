//! Cloudflare API Token Rotator (`cloudflare-api-token`).
//! Uses Cloudflare's `/client/v4/user/tokens/verify` and `/client/v4/user/tokens/{id}/value`
//! endpoints (or `SENTRIS_CLOUDFLARE_API_URL` for local test servers) to verify and roll leaked
//! Cloudflare Bearer tokens without exposing secret values in command-line arguments or logs.

use std::time::Duration;

use crate::error::SentrisError;
use crate::remediator::Remediator;
use crate::rotator::{LastUse, MintedCredential, RotationPlan, Rotator};

const DEFAULT_CF_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareRotator {
    base_url: String,
}

impl Default for CloudflareRotator {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflareRotator {
    pub fn new() -> Self {
        let base_url = std::env::var("SENTRIS_CLOUDFLARE_API_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CF_BASE_URL.to_string());
        Self { base_url }
    }

    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    fn auth_token_for_management() -> Option<String> {
        std::env::var("SENTRIS_CLOUDFLARE_ADMIN_TOKEN")
            .ok()
            .or_else(|| std::env::var("CLOUDFLARE_API_TOKEN").ok())
            .filter(|t| !t.trim().is_empty())
    }
}

impl Rotator for CloudflareRotator {
    fn provider_name(&self) -> &'static str {
        "Cloudflare"
    }

    fn plan(&self, old_secret: &str) -> Result<RotationPlan, SentrisError> {
        let url = format!("{}/user/tokens/verify", self.base_url.trim_end_matches('/'));
        let resp = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", old_secret.trim()))
            .set("User-Agent", "sentris-security-scanner")
            .timeout(Duration::from_secs(5))
            .call();

        let body: serde_json::Value = match resp {
            Ok(r) => r
                .into_json()
                .map_err(|e| SentrisError::Scan(format!("Invalid Cloudflare JSON: {e}")))?,
            Err(ureq::Error::Status(code, _)) => {
                return Err(SentrisError::Scan(format!(
                    "Cloudflare token verification failed with HTTP {code}"
                )))
            }
            Err(e) => {
                return Err(SentrisError::Scan(format!(
                    "Cloudflare API unreachable during rotation plan: {e}"
                )))
            }
        };

        let token_id = body["result"]["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SentrisError::Scan("Cloudflare verify response missing result.id".to_string())
            })?
            .to_string();

        let short_id = if token_id.len() >= 8 {
            &token_id[..8]
        } else {
            &token_id
        };

        Ok(RotationPlan {
            provider: "Cloudflare".to_string(),
            rule_id: "cloudflare-api-token".to_string(),
            principal: format!("cf-token:{short_id}"),
            old_key_id: token_id,
            old_fingerprint: String::new(),
        })
    }

    fn mint(&self, plan: &RotationPlan) -> Result<MintedCredential, SentrisError> {
        let mut bearer = Self::auth_token_for_management().unwrap_or_default();
        let url = format!(
            "{}/user/tokens/{}/value",
            self.base_url.trim_end_matches('/'),
            plan.old_key_id
        );
        let req = ureq::put(&url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "sentris-security-scanner")
            .timeout(Duration::from_secs(5));
        let req = if bearer.is_empty() {
            req
        } else {
            req.set("Authorization", &format!("Bearer {bearer}"))
        };
        Remediator::zeroize_secret_string(&mut bearer);

        let resp = req.send_string("{}");
        let body: serde_json::Value = match resp {
            Ok(r) => r
                .into_json()
                .map_err(|e| SentrisError::Scan(format!("Invalid Cloudflare roll JSON: {e}")))?,
            Err(ureq::Error::Status(code, _)) => {
                return Err(SentrisError::Scan(format!(
                    "Cloudflare token roll PUT /user/tokens/{}/value returned HTTP {code}",
                    plan.old_key_id
                )))
            }
            Err(e) => {
                return Err(SentrisError::Scan(format!(
                    "Cloudflare token roll failed: {e}"
                )))
            }
        };

        let new_secret = body["result"]
            .as_str()
            .or_else(|| body["result"]["value"].as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SentrisError::Scan("Cloudflare token roll did not return a new token value".into())
            })?
            .to_string();

        Ok(MintedCredential {
            key_id: format!("{}:rolled", plan.old_key_id),
            secret: new_secret,
        })
    }

    fn deactivate_old(&self, _plan: &RotationPlan) -> Result<(), SentrisError> {
        // Cloudflare `/user/tokens/{id}/value` rolls the secret value atomically in-place.
        Ok(())
    }

    fn reactivate_old(&self, _plan: &RotationPlan) -> Result<(), SentrisError> {
        Ok(())
    }

    fn discard_new(&self, _plan: &RotationPlan, _new_key_id: &str) -> Result<(), SentrisError> {
        Ok(())
    }

    fn delete_old(&self, _plan: &RotationPlan) -> Result<(), SentrisError> {
        Ok(())
    }

    fn last_used(&self, _plan: &RotationPlan) -> Result<Option<LastUse>, SentrisError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::rotator::rotator_for_rule;

    #[test]
    fn cloudflare_rule_resolves_to_cloudflare_rotator() {
        let rot = rotator_for_rule("cloudflare-api-token").expect("cloudflare rotator");
        assert_eq!(rot.provider_name(), "Cloudflare");
    }
}
