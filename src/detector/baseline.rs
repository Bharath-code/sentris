use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::SentrisError;
use crate::model::Finding;

/// A single suppressed secret record within a baseline file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub line_number: usize,
    pub recorded_at: String,
}

impl BaselineRecord {
    pub fn new(
        fingerprint: String,
        rule_id: String,
        file_path: String,
        line_number: usize,
        recorded_at: String,
    ) -> Self {
        Self {
            fingerprint,
            rule_id,
            file_path,
            line_number,
            recorded_at,
        }
    }
}

/// Baseline file schema holding acknowledged legacy findings and snapshot metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(default = "default_version")]
    pub version: u32,
    pub recorded_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub findings: Vec<BaselineRecord>,
}

fn default_version() -> u32 {
    1
}

impl Default for BaselineFile {
    fn default() -> Self {
        Self {
            version: 1,
            recorded_at: current_utc_timestamp(),
            git_commit: None,
            findings: Vec::new(),
        }
    }
}

impl BaselineFile {
    /// Creates a new baseline file instance from existing baseline records.
    pub fn new(records: Vec<BaselineRecord>, git_commit: Option<String>) -> Self {
        Self {
            version: 1,
            recorded_at: current_utc_timestamp(),
            git_commit,
            findings: records,
        }
    }

    /// Creates a baseline snapshot directly from a slice of detected findings.
    pub fn from_findings(findings: &[Finding], git_commit: Option<String>) -> Self {
        let recorded_at = current_utc_timestamp();
        let records = findings
            .iter()
            .map(|f| BaselineRecord {
                fingerprint: f.fingerprint.clone(),
                rule_id: f.rule_id.clone(),
                file_path: f.file_path.clone(),
                line_number: f.line_number,
                recorded_at: recorded_at.clone(),
            })
            .collect();

        Self {
            version: 1,
            recorded_at,
            git_commit,
            findings: records,
        }
    }

    /// Loads and deserializes a baseline file from the given filesystem path.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, SentrisError> {
        let content = fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&content)?;
        Ok(baseline)
    }

    /// Serializes and writes this baseline to the given filesystem path, creating directories if needed.
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), SentrisError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Checks if a finding is suppressed by this baseline.
    /// Suppression matches by fingerprint or by matching both (file_path, rule_id).
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        self.findings.iter().any(|r| {
            r.fingerprint == finding.fingerprint
                || (r.file_path == finding.file_path && r.rule_id == finding.rule_id)
        })
    }

    /// Appends a single finding to this baseline if not already suppressed.
    pub fn add_finding(&mut self, finding: &Finding) {
        if !self.is_suppressed(finding) {
            self.findings.push(BaselineRecord {
                fingerprint: finding.fingerprint.clone(),
                rule_id: finding.rule_id.clone(),
                file_path: finding.file_path.clone(),
                line_number: finding.line_number,
                recorded_at: current_utc_timestamp(),
            });
        }
    }

    /// Filters a list of findings, returning active un-suppressed findings and the count of suppressed findings.
    pub fn filter_findings(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        let mut active = Vec::new();
        let mut suppressed_count = 0;

        for finding in findings {
            if self.is_suppressed(&finding) {
                suppressed_count += 1;
            } else {
                active.push(finding);
            }
        }

        (active, suppressed_count)
    }
}

/// Generates a current UTC ISO-8601 timestamp string (e.g. 2026-10-08T06:35:16Z).
fn current_utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = (secs / 86400) as i64;

    // Euclidean affine algorithm for civil day from epoch days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use tempfile::tempdir;

    fn make_test_finding(
        rule_id: &str,
        file_path: &str,
        line_number: usize,
        fingerprint: &str,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: format!("Test description for {rule_id}"),
            severity: Severity::High,
            file_path: file_path.to_string(),
            line_number,
            column: 1,
            redacted_match: "test_secret_redacted".to_string(),
            entropy: 4.5,
            fingerprint: fingerprint.to_string(),
            commit_hash: None,
        }
    }

    #[test]
    fn test_create_baseline_from_findings() {
        let findings = vec![
            make_test_finding("aws-access-key-id", "src/auth.rs", 12, "fp_aws_123"),
            make_test_finding("stripe-secret-key", "src/billing.ts", 45, "fp_stripe_456"),
        ];

        let git_commit = Some("a1b2c3d4e5f6".to_string());
        let baseline = BaselineFile::from_findings(&findings, git_commit.clone());

        assert_eq!(baseline.version, 1);
        assert_eq!(baseline.git_commit, git_commit);
        assert!(!baseline.recorded_at.is_empty());
        assert_eq!(baseline.findings.len(), 2);

        let rec0 = &baseline.findings[0];
        assert_eq!(rec0.rule_id, "aws-access-key-id");
        assert_eq!(rec0.file_path, "src/auth.rs");
        assert_eq!(rec0.line_number, 12);
        assert_eq!(rec0.fingerprint, "fp_aws_123");
        assert_eq!(rec0.recorded_at, baseline.recorded_at);

        let rec1 = &baseline.findings[1];
        assert_eq!(rec1.rule_id, "stripe-secret-key");
        assert_eq!(rec1.file_path, "src/billing.ts");
        assert_eq!(rec1.line_number, 45);
        assert_eq!(rec1.fingerprint, "fp_stripe_456");
        assert_eq!(rec1.recorded_at, baseline.recorded_at);
    }

    #[test]
    fn test_json_serialization_and_deserialization() {
        let records = vec![
            BaselineRecord::new(
                "fp_github_pat".to_string(),
                "github-pat".to_string(),
                "deploy.sh".to_string(),
                8,
                "2026-10-08T12:00:00Z".to_string(),
            ),
            BaselineRecord::new(
                "fp_slack_token".to_string(),
                "slack-bot-token".to_string(),
                "notify.py".to_string(),
                22,
                "2026-10-08T12:00:00Z".to_string(),
            ),
        ];

        let baseline = BaselineFile::new(records.clone(), Some("commithash123".to_string()));
        let json_str = serde_json::to_string_pretty(&baseline).expect("Failed to serialize");

        assert!(json_str.contains("fp_github_pat"));
        assert!(json_str.contains("github-pat"));
        assert!(json_str.contains("commithash123"));

        let deserialized: BaselineFile =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(deserialized.version, baseline.version);
        assert_eq!(deserialized.git_commit, baseline.git_commit);
        assert_eq!(deserialized.recorded_at, baseline.recorded_at);
        assert_eq!(deserialized.findings, records);

        // Verify default version is 1 when version is omitted from JSON
        let minimal_json = r#"{
            "recorded_at": "2026-10-08T00:00:00Z",
            "findings": []
        }"#;
        let parsed_minimal: BaselineFile =
            serde_json::from_str(minimal_json).expect("Failed to parse minimal JSON");
        assert_eq!(parsed_minimal.version, 1);
        assert_eq!(parsed_minimal.git_commit, None);
        assert_eq!(parsed_minimal.findings.len(), 0);
    }

    #[test]
    fn test_filter_findings_suppresses_existing_and_keeps_net_new_active() {
        let records = vec![
            BaselineRecord::new(
                "fingerprint_alpha".to_string(),
                "aws-access-key-id".to_string(),
                "config/aws.env".to_string(),
                10,
                "2026-10-08T00:00:00Z".to_string(),
            ),
            BaselineRecord::new(
                "fingerprint_beta".to_string(),
                "stripe-secret-key".to_string(),
                "services/payment.ts".to_string(),
                25,
                "2026-10-08T00:00:00Z".to_string(),
            ),
        ];
        let baseline = BaselineFile::new(records, None);

        // 1. Finding matching exact fingerprint and location
        let suppressed_exact = make_test_finding(
            "aws-access-key-id",
            "config/aws.env",
            10,
            "fingerprint_alpha",
        );
        assert!(baseline.is_suppressed(&suppressed_exact));

        // 2. Finding matching fingerprint, but moved to another file
        let suppressed_moved = make_test_finding(
            "stripe-secret-key",
            "services/payment_v2.ts",
            88,
            "fingerprint_beta",
        );
        assert!(baseline.is_suppressed(&suppressed_moved));

        // 3. Finding matching (file_path, rule_id), but secret value/fingerprint changed
        let suppressed_by_path_rule = make_test_finding(
            "aws-access-key-id",
            "config/aws.env",
            15,
            "fingerprint_new_aws",
        );
        assert!(baseline.is_suppressed(&suppressed_by_path_rule));

        // 4. Net-new secret in a new file with different rule
        let active_new_rule =
            make_test_finding("github-pat", "scripts/ci.sh", 4, "fingerprint_gamma");
        assert!(!baseline.is_suppressed(&active_new_rule));

        // 5. Net-new secret with same rule (aws) but in a different file
        let active_new_file = make_test_finding(
            "aws-access-key-id",
            "lambda/handler.js",
            2,
            "fingerprint_delta",
        );
        assert!(!baseline.is_suppressed(&active_new_file));

        let findings_pool = vec![
            suppressed_exact,
            active_new_rule.clone(),
            suppressed_moved,
            suppressed_by_path_rule,
            active_new_file.clone(),
        ];

        let (active_findings, suppressed_count) = baseline.filter_findings(findings_pool);

        assert_eq!(suppressed_count, 3);
        assert_eq!(active_findings.len(), 2);
        assert_eq!(active_findings[0].fingerprint, active_new_rule.fingerprint);
        assert_eq!(active_findings[1].fingerprint, active_new_file.fingerprint);
    }

    #[test]
    fn test_save_and_load_from_path() {
        let dir = tempdir().expect("Failed to create tempdir");
        let target_path = dir
            .path()
            .join("nested")
            .join("dir")
            .join(".sentris-baseline.json");

        let finding = make_test_finding("stripe-secret-key", "src/index.js", 99, "fp_stripe_99");
        let original_baseline =
            BaselineFile::from_findings(&[finding], Some("commit_abc".to_string()));

        // Save should automatically create directories
        original_baseline
            .save_to_path(&target_path)
            .expect("Failed to save baseline");
        assert!(target_path.exists());

        // Load back and verify equality
        let loaded_baseline =
            BaselineFile::load_from_path(&target_path).expect("Failed to load baseline");
        assert_eq!(loaded_baseline.version, original_baseline.version);
        assert_eq!(loaded_baseline.git_commit, original_baseline.git_commit);
        assert_eq!(loaded_baseline.recorded_at, original_baseline.recorded_at);
        assert_eq!(loaded_baseline.findings, original_baseline.findings);
    }

    #[test]
    fn test_invalid_file_handling() {
        let dir = tempdir().expect("Failed to create tempdir");

        // 1. Non-existent file
        let missing_path = dir.path().join("does_not_exist.json");
        let result = BaselineFile::load_from_path(&missing_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            SentrisError::Io(_) => (),
            other => panic!("Expected SentrisError::Io, got: {other:?}"),
        }

        // 2. Corrupt / invalid JSON content
        let corrupt_path = dir.path().join("corrupt_baseline.json");
        fs::write(&corrupt_path, "{ invalid_json_syntax: true, ")
            .expect("Failed to write corrupt file");
        let result = BaselineFile::load_from_path(&corrupt_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            SentrisError::Serialization(_) => (),
            other => panic!("Expected SentrisError::Serialization, got: {other:?}"),
        }
    }

    #[test]
    fn test_empty_baseline() {
        let baseline = BaselineFile::default();
        assert_eq!(baseline.version, 1);
        assert!(baseline.findings.is_empty());

        let finding = make_test_finding("aws-key", "main.rs", 1, "fp_1");
        assert!(!baseline.is_suppressed(&finding));

        let (active, suppressed_count) = baseline.filter_findings(vec![finding]);
        assert_eq!(suppressed_count, 0);
        assert_eq!(active.len(), 1);
    }
}
