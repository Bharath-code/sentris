use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct GitlabVerifier;

impl GitlabVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GitlabVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for GitlabVerifier {
    fn provider_name(&self) -> &'static str {
        "GitLab"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["gitlab-pat"]
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();
        if super::mock_tokens_enabled() && trimmed.starts_with("glpat-test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec!["api".to_string(), "write_repository".to_string()],
            });
        }

        let response = ureq::get("https://gitlab.com/api/v4/personal_access_tokens/self")
            .set("Authorization", &format!("Bearer {trimmed}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                let body: serde_json::Value = res.into_json().unwrap_or_default();
                if body["revoked"].as_bool() == Some(true)
                    || body["active"].as_bool() == Some(false)
                {
                    return Ok(LiveStatus::Revoked);
                }
                let scopes = body["scopes"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                            .collect()
                    })
                    .unwrap_or_else(|| vec!["read_api".to_string()]);
                Ok(LiveStatus::Active { scopes })
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "GitLab API returned status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "GitLab API returned status {code}"
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
    fn test_gitlab_mock_verification() {
        let v = GitlabVerifier::new();
        assert!(v.can_handle("gitlab-pat"));
        let status = v
            .verify_live(concat!("glpat-", "test_mock_1234567890abcdef"))
            .unwrap();
        assert!(matches!(status, LiveStatus::Active { .. }));
    }
}
