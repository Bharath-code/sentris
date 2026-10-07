pub mod entropy;
pub mod false_positives;
pub mod patterns;

use crate::error::SentrisError;
use crate::model::{Finding, Severity};
use regex::Regex;
use sha2::{Digest, Sha256};

#[allow(dead_code)]
pub struct CompiledRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub regex: Regex,
    pub min_entropy: f64,
}

pub struct DetectorEngine {
    rules: Vec<CompiledRule>,
}

impl DetectorEngine {
    pub fn with_config(config: Option<&crate::config::Config>) -> Result<Self, SentrisError> {
        let raw_rules = patterns::get_rules();
        let custom_count = config.map(|c| c.rules.len()).unwrap_or(0);
        let mut compiled = Vec::with_capacity(raw_rules.len() + custom_count);

        for rule in raw_rules {
            let re = Regex::new(rule.pattern)?;
            compiled.push(CompiledRule {
                rule_id: rule.rule_id.to_string(),
                name: rule.name.to_string(),
                description: rule.description.to_string(),
                severity: rule.severity,
                regex: re,
                min_entropy: rule.min_entropy,
            });
        }

        if let Some(cfg) = config {
            for custom in &cfg.rules {
                let re = Regex::new(&custom.pattern)?;
                compiled.push(CompiledRule {
                    rule_id: custom.rule_id.clone(),
                    name: custom.name.clone(),
                    description: custom.description.clone(),
                    severity: custom.severity,
                    regex: re,
                    min_entropy: custom.min_entropy,
                });
            }
        }

        Ok(Self { rules: compiled })
    }

    #[allow(dead_code)]
    pub fn new() -> Result<Self, SentrisError> {
        Self::with_config(None)
    }

    /// Scans a single line of text with custom line number and optional commit hash
    pub fn scan_single_line(
        &self,
        line: &str,
        file_path: &str,
        line_number: usize,
        commit_hash: Option<String>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for inline suppression comments (supports multi-tool ecosystem standards)
        if line.contains("sentris-ignore")
            || line.contains("rustscan-ignore")
            || line.contains("gitleaks:allow")
            || line.contains("nosec")
            || line.contains("trufflehog:ignore")
            || line.contains("secretlint-disable")
        {
            return findings;
        }

        for rule in &self.rules {
            for mat in rule.regex.find_iter(line) {
                let matched_str = mat.as_str();

                // Check Shannon entropy threshold
                let entropy = entropy::calculate_shannon_entropy(matched_str);
                if entropy < rule.min_entropy {
                    continue;
                }

                // Check world-class false positive suppression filter
                if false_positives::FalsePositiveFilter::is_false_positive(
                    matched_str,
                    &rule.rule_id,
                    line,
                ) {
                    continue;
                }

                // Compute SHA-256 fingerprint of the secret
                let mut hasher = Sha256::new();
                hasher.update(matched_str.as_bytes());
                let fingerprint = hex::encode(hasher.finalize());

                let column = mat.start() + 1;
                let redacted = Finding::mask_secret(matched_str);

                findings.push(Finding {
                    rule_id: rule.rule_id.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity,

                    file_path: file_path.to_string(),
                    line_number,
                    column,
                    redacted_match: redacted,
                    entropy,
                    fingerprint,
                    commit_hash: commit_hash.clone(),
                });
            }
        }

        findings
    }

    /// Scans a text file's contents line-by-line, returning all detected findings.
    pub fn scan_text(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_findings = self.scan_single_line(line, file_path, line_idx + 1, None);
            findings.extend(line_findings);
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_stripe_key() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!(
            "const stripeKey = \"",
            "sk_live_",
            "51AbcDefGhIjKlMnOpQrStUvWxYz123456\";\n"
        );
        let findings = engine.scan_text(test_code, "config.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "stripe-secret-key");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].redacted_match.starts_with("sk_liv"));
    }

    #[test]
    fn test_inline_ignore() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!(
            "const stripeKey = \"",
            "sk_live_",
            "51AbcDefGhIjKlMnOpQrStUvWxYz123456\"; // sentris-ignore\n"
        );
        let findings = engine.scan_text(test_code, "config.ts");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_detect_aws_key() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!("AWS_ACCESS_KEY_ID = \"", "AKIA2J5W", "9X7Y8Z9MNO4P\"\n");
        let findings = engine.scan_text(test_code, ".env");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "aws-access-key-id");
    }

    #[test]
    fn test_suppress_aws_docs_example() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!("AWS_ACCESS_KEY_ID = \"", "AKIAIOS", "FODNN7EXAMPLE\"\n");
        let findings = engine.scan_text(test_code, ".env");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_detect_github_pat() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!(
            "export GITHUB_TOKEN=\"",
            "ghp_k9L2mP8q",
            "R4vW7xZ1bN5jC3dF6hT0sU8yA2cB\"\n"
        );
        let findings = engine.scan_text(test_code, "deploy.sh");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "github-pat");
    }

    #[test]
    fn test_suppress_sequential_github_walk() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!(
            "export GITHUB_TOKEN=\"",
            "ghp_1234",
            "567890abcdefghijklmnopqrstuvwxyz\"\n"
        );
        let findings = engine.scan_text(test_code, "deploy.sh");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_custom_rule_from_config() {
        use crate::config::{Config, CustomRule};
        let mut config = Config::default();
        config.rules.push(CustomRule {
            rule_id: "acme-corp-key".to_string(),
            name: "Acme Corp Secret".to_string(),
            description: "Internal company key".to_string(),
            severity: Severity::Critical,
            pattern: r"acme_corp_[a-zA-Z0-9]{24}".to_string(),
            min_entropy: 3.0,
        });

        let engine = DetectorEngine::with_config(Some(&config)).unwrap();
        let test_code = "const key = \"acme_corp_8f7b6c5d4e3a2b1c0d9e8f7a\";\n";
        let findings = engine.scan_text(test_code, "config.js");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "acme-corp-key");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
