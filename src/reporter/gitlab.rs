use serde::{Deserialize, Serialize};

use crate::model::{Finding, ScanReport, Severity};

/// Official GitLab Secret Detection report schema URL
pub const GITLAB_SECRET_DETECTION_SCHEMA: &str =
    "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.0.7/dist/secret-detection-report.json";

/// Official GitLab Secret Detection schema version
pub const GITLAB_SECRET_DETECTION_VERSION: &str = "15.0.7";

/// Top-level report matching GitLab Secret Detection schema v15.0.7
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitLabSecretDetectionReport {
    /// Schema definition URL
    pub schema: String,

    /// Schema specification version
    pub version: String,

    /// List of detected vulnerabilities/secrets
    pub vulnerabilities: Vec<GitLabVulnerability>,

    /// Available remediations (empty array if none)
    pub remediations: Vec<serde_json::Value>,

    /// Metadata describing the scan execution
    pub scan: GitLabScan,
}

/// A detected secret vulnerability matching GitLab's schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitLabVulnerability {
    /// Unique fingerprint/ID for the vulnerability
    pub id: String,

    /// Security category (always "secret_detection")
    pub category: String,

    /// Short human-readable name of the vulnerability
    pub name: String,

    /// Descriptive summary message
    pub message: String,

    /// Full detailed description of the detection
    pub description: String,

    /// Unique identifier / synthetic CVE tracking string
    pub cve: String,

    /// Severity level ("Critical", "High", "Medium", "Low")
    pub severity: String,

    /// Confidence level ("Confirmed", "High", "Medium", "Low", "Unknown")
    pub confidence: String,

    /// Code excerpt containing the redacted secret
    pub raw_source_code_extract: String,

    /// Scanner metadata
    pub scanner: GitLabScanner,

    /// File location coordinates
    pub location: GitLabLocation,

    /// Unique identifiers linking to rule definitions
    pub identifiers: Vec<GitLabIdentifier>,
}

/// Scanner metadata conforming to GitLab's schema
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitLabScanner {
    /// Scanner ID
    pub id: String,

    /// Scanner display name
    pub name: String,

    /// Scanner homepage URL
    pub url: String,

    /// Scanner version
    pub version: String,

    /// Scanner vendor info
    pub vendor: GitLabVendor,
}

/// Scanner vendor metadata conforming to GitLab's schema
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitLabVendor {
    /// Vendor name
    pub name: String,
}

/// File coordinates for the detected secret
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitLabLocation {
    /// File path relative to repository root
    pub file: String,

    /// Starting line number (1-indexed)
    pub start_line: usize,

    /// Ending line number (1-indexed)
    pub end_line: usize,
}

/// Vulnerability identifier (e.g., rule ID)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitLabIdentifier {
    /// Identifier type (e.g. "sentris_rule_id")
    #[serde(rename = "type")]
    pub identifier_type: String,

    /// Identifier display name
    pub name: String,

    /// Identifier value / rule ID
    pub value: String,
}

/// Scan execution metadata conforming to GitLab's schema
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitLabScan {
    /// Scanner metadata
    pub scanner: GitLabScanner,

    /// Scan type (always "secret_detection")
    #[serde(rename = "type")]
    pub scan_type: String,

    /// Execution status (e.g. "success")
    pub status: String,

    /// Timestamp when scan started
    pub start_time: String,

    /// Timestamp when scan finished
    pub end_time: String,
}

/// Maps internal Sentris `Severity` to GitLab's official severity string
pub fn map_severity_to_gitlab(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    }
}

/// Converts a Sentris `ScanReport` into a `GitLabSecretDetectionReport`
pub fn convert_to_gitlab_report(report: &ScanReport) -> GitLabSecretDetectionReport {
    let scanner = GitLabScanner {
        id: "sentris".to_string(),
        name: "Sentris".to_string(),
        url: "https://sentris.dev".to_string(),
        version: report.version.clone(),
        vendor: GitLabVendor {
            name: "Sentris Security".to_string(),
        },
    };

    let vulnerabilities = report
        .findings
        .iter()
        .map(|f| convert_finding_to_vulnerability(f, &scanner))
        .collect();

    let scan = GitLabScan {
        scanner,
        scan_type: "secret_detection".to_string(),
        status: "success".to_string(),
        start_time: report.timestamp.clone(),
        end_time: report.timestamp.clone(),
    };

    GitLabSecretDetectionReport {
        schema: GITLAB_SECRET_DETECTION_SCHEMA.to_string(),
        version: GITLAB_SECRET_DETECTION_VERSION.to_string(),
        vulnerabilities,
        remediations: Vec::new(),
        scan,
    }
}

/// Converts a single Sentris `Finding` into a `GitLabVulnerability`
fn convert_finding_to_vulnerability(
    finding: &Finding,
    scanner: &GitLabScanner,
) -> GitLabVulnerability {
    let id = if !finding.fingerprint.is_empty() {
        finding.fingerprint.clone()
    } else {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(finding.file_path.as_bytes());
        hasher.update(finding.line_number.to_string().as_bytes());
        hasher.update(finding.rule_id.as_bytes());
        hex::encode(hasher.finalize())
    };

    let cve = format!(
        "{}:{}:{}",
        finding.file_path, finding.line_number, finding.rule_id
    );

    let location = GitLabLocation {
        file: finding.file_path.clone(),
        start_line: finding.line_number,
        end_line: finding.line_number,
    };

    let identifiers = vec![GitLabIdentifier {
        identifier_type: "sentris_rule_id".to_string(),
        name: format!("Sentris Rule {}", finding.rule_id),
        value: finding.rule_id.clone(),
    }];

    GitLabVulnerability {
        id,
        category: "secret_detection".to_string(),
        name: finding.description.clone(),
        message: finding.description.clone(),
        description: finding.description.clone(),
        cve,
        severity: map_severity_to_gitlab(finding.severity).to_string(),
        confidence: "Confirmed".to_string(),
        raw_source_code_extract: finding.redacted_match.clone(),
        scanner: scanner.clone(),
        location,
        identifiers,
    }
}

/// Serializes a Sentris `ScanReport` to a pretty-printed GitLab Secret Detection JSON string
pub fn to_gitlab(report: &ScanReport) -> Result<String, serde_json::Error> {
    let gitlab_report = convert_to_gitlab_report(report);
    serde_json::to_string_pretty(&gitlab_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanStats;

    fn make_test_report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            timestamp: "2026-10-08T12:00:00Z".to_string(),
            version: "0.1.0".to_string(),
            stats: ScanStats {
                files_scanned: 10,
                files_ignored: 1,
                bytes_scanned: 4096,
                findings_count: findings.len(),
                duration_ms: 15,
            },
            findings,
        }
    }

    #[test]
    fn test_clean_report_gitlab_format() {
        let report = make_test_report(vec![]);
        let gitlab_report = convert_to_gitlab_report(&report);

        assert_eq!(gitlab_report.schema, GITLAB_SECRET_DETECTION_SCHEMA);
        assert_eq!(gitlab_report.version, GITLAB_SECRET_DETECTION_VERSION);
        assert!(gitlab_report.vulnerabilities.is_empty());
        assert!(gitlab_report.remediations.is_empty());
        assert_eq!(gitlab_report.scan.scan_type, "secret_detection");
        assert_eq!(gitlab_report.scan.status, "success");
        assert_eq!(gitlab_report.scan.scanner.id, "sentris");

        let json_str = to_gitlab(&report).expect("Failed to serialize");
        assert!(json_str.contains("\"version\": \"15.0.7\""));
        assert!(json_str.contains("\"vulnerabilities\": []"));
    }

    #[test]
    fn test_findings_report_gitlab_format() {
        let findings = vec![
            Finding {
                rule_id: "stripe-secret-key".to_string(),
                description: "Stripe Secret API Key".to_string(),
                severity: Severity::Critical,
                file_path: "src/payment.rs".to_string(),
                line_number: 42,
                column: 10,
                redacted_match: "sk_live_...9a8b".to_string(),
                entropy: 4.85,
                fingerprint: "a1b2c3d4e5f6".to_string(),
                commit_hash: None,
            },
            Finding {
                rule_id: "aws-access-key-id".to_string(),
                description: "AWS Access Key ID".to_string(),
                severity: Severity::High,
                file_path: "config/aws.yml".to_string(),
                line_number: 12,
                column: 5,
                redacted_match: "AKIA...1234".to_string(),
                entropy: 3.8,
                fingerprint: "f6e5d4c3b2a1".to_string(),
                commit_hash: Some("abcdef1".to_string()),
            },
        ];

        let report = make_test_report(findings);
        let gitlab_report = convert_to_gitlab_report(&report);

        assert_eq!(gitlab_report.vulnerabilities.len(), 2);

        let v0 = &gitlab_report.vulnerabilities[0];
        assert_eq!(v0.id, "a1b2c3d4e5f6");
        assert_eq!(v0.category, "secret_detection");
        assert_eq!(v0.severity, "Critical");
        assert_eq!(v0.confidence, "Confirmed");
        assert_eq!(v0.location.file, "src/payment.rs");
        assert_eq!(v0.location.start_line, 42);
        assert_eq!(v0.location.end_line, 42);
        assert_eq!(v0.raw_source_code_extract, "sk_live_...9a8b");
        assert_eq!(v0.identifiers[0].identifier_type, "sentris_rule_id");
        assert_eq!(v0.identifiers[0].value, "stripe-secret-key");

        let v1 = &gitlab_report.vulnerabilities[1];
        assert_eq!(v1.severity, "High");
        assert_eq!(v1.location.file, "config/aws.yml");

        // Verify JSON serialization and round-trip parsing
        let json_str = to_gitlab(&report).expect("Failed to serialize");
        let parsed: GitLabSecretDetectionReport =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(parsed.vulnerabilities.len(), 2);
    }
}
