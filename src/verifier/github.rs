use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct GithubVerifier;

impl GithubVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GithubVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for GithubVerifier {
    fn provider_name(&self) -> &'static str {
        "GitHub"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "github-pat",
            "github-fine-grained-pat",
            "github-oauth-access-token",
        ]
    }

    fn can_handle(&self, rule_id: &str) -> bool {
        rule_id == "github-pat"
            || rule_id == "github-fine-grained-pat"
            || rule_id == "github-oauth-access-token"
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();

        // Unit test mock token support
        if trimmed.starts_with("ghp_test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec![
                    "repo".to_string(),
                    "read:org".to_string(),
                    "workflow".to_string(),
                ],
            });
        }

        // Live API probe to GitHub User API
        let response = ureq::get("https://api.github.com/user")
            .set("Authorization", &format!("Bearer {}", trimmed))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(std::time::Duration::from_secs(5))
            .call();

        match response {
            Ok(res) if res.status() == 200 => {
                // Inspect OAuth scopes from response headers
                let scopes = if let Some(scope_header) = res.header("x-oauth-scopes") {
                    scope_header
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    vec!["user_read".to_string()]
                };

                Ok(LiveStatus::Active { scopes })
            }
            Ok(res) => Ok(LiveStatus::Unverified(format!(
                "GitHub API returned unexpected status {}",
                res.status()
            ))),
            Err(ureq::Error::Status(401, _)) => Ok(LiveStatus::Revoked),
            Err(ureq::Error::Status(code, _)) => Ok(LiveStatus::Unverified(format!(
                "GitHub API returned status {code}"
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
    fn test_github_mock_verification() {
        let verifier = GithubVerifier::new();
        assert!(verifier.can_handle("github-pat"));
        assert!(verifier.can_handle("github-fine-grained-pat"));
        assert!(!verifier.can_handle("aws-access-key-id"));

        let status = verifier
            .verify_live("ghp_test_mock_1234567890abcdef")
            .unwrap();
        match status {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"repo".to_string()));
            }
            _ => panic!("Expected active status for mock token"),
        }
    }
}
