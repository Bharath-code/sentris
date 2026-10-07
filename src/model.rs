use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: usize,
    pub column: usize,
    pub redacted_match: String,
    pub entropy: f64,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
}

impl Finding {
    pub fn mask_secret(secret: &str) -> String {
        let len = secret.len();
        if len <= 8 {
            "********".to_string()
        } else {
            let prefix_len = if len >= 16 { 6 } else { 4 };
            let suffix_len = 4;
            format!(
                "{}...{}",
                &secret[..prefix_len],
                &secret[len - suffix_len..]
            )
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_ignored: usize,
    pub bytes_scanned: u64,
    pub findings_count: usize,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub timestamp: String,
    pub version: String,
    pub stats: ScanStats,
    pub findings: Vec<Finding>,
}
