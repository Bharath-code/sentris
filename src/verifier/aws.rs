use super::{LiveStatus, ProviderVerifier};
use crate::error::SentrisError;

pub struct AwsVerifier;

impl AwsVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AwsVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderVerifier for AwsVerifier {
    fn provider_name(&self) -> &'static str {
        "AWS"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["aws-access-key-id", "aws-secret-access-key"]
    }

    fn can_handle(&self, rule_id: &str) -> bool {
        rule_id == "aws-access-key-id" || rule_id == "aws-secret-access-key"
    }

    fn verify_live(&self, secret: &str) -> Result<LiveStatus, SentrisError> {
        let trimmed = secret.trim();

        if super::mock_tokens_enabled() && trimmed.starts_with("AKIA_test_mock_") {
            return Ok(LiveStatus::Active {
                scopes: vec![
                    "sts:GetCallerIdentity".to_string(),
                    "s3:ListAllMyBuckets".to_string(),
                ],
            });
        }

        // AWS requires paired Secret Access Key + Signature Version 4 to query STS
        // For standalone Access Key IDs, verify standard 20-character AKIA format
        if trimmed.starts_with("AKIA") && trimmed.len() == 20 {
            Ok(LiveStatus::Unverified(
                "AWS Access Key requires paired Secret Access Key for active STS signature probe"
                    .to_string(),
            ))
        } else {
            Ok(LiveStatus::Unverified(
                "Not an AKIA access key id; cannot be verified without a signed STS call"
                    .to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_mock_verification() {
        let verifier = AwsVerifier::new();
        assert!(verifier.can_handle("aws-access-key-id"));
        assert!(verifier.can_handle("aws-secret-access-key"));
        assert!(!verifier.can_handle("stripe-secret-key"));

        let status = verifier.verify_live("AKIA_test_mock_1234567890").unwrap();
        match status {
            LiveStatus::Active { scopes } => {
                assert!(scopes.contains(&"sts:GetCallerIdentity".to_string()));
            }
            _ => panic!("Expected active status for mock AWS key"),
        }
    }
}
