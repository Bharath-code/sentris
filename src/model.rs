use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "UPPERCASE")]
#[clap(rename_all = "lower")]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextKind {
    Production,
    TestFixture,
}

impl ContextKind {
    /// Classifies whether a file path belongs to a test/fixture context or production source code
    pub fn from_file_path(file_path: &str) -> Self {
        let lower = file_path.to_ascii_lowercase();
        let normalized = lower.replace('\\', "/");
        if normalized.contains("/tests/")
            || normalized.starts_with("tests/")
            || normalized.contains("/__tests__/")
            || normalized.contains("/test/")
            || normalized.starts_with("test/")
            || normalized.contains("/fixtures/")
            || normalized.starts_with("fixtures/")
            || normalized.contains("/mocks/")
            || normalized.ends_with("_test.go")
            || normalized.ends_with("_test.rs")
            || normalized.ends_with("_test.py")
            || normalized.ends_with(".test.ts")
            || normalized.ends_with(".test.js")
            || normalized.ends_with(".spec.ts")
            || normalized.ends_with(".spec.js")
        {
            Self::TestFixture
        } else {
            Self::Production
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
    /// Returns the syntactic file context classification (Production vs TestFixture)
    pub fn context_kind(&self) -> ContextKind {
        ContextKind::from_file_path(&self.file_path)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_kind_classification() {
        assert_eq!(
            ContextKind::from_file_path("src/billing/stripe.ts"),
            ContextKind::Production
        );
        assert_eq!(
            ContextKind::from_file_path("cmd/server/main.go"),
            ContextKind::Production
        );
        assert_eq!(
            ContextKind::from_file_path("pkg/auth/jwt_test.go"),
            ContextKind::TestFixture
        );
        assert_eq!(
            ContextKind::from_file_path("src/components/checkout.spec.ts"),
            ContextKind::TestFixture
        );
        assert_eq!(
            ContextKind::from_file_path("tests/fixtures/secrets.env"),
            ContextKind::TestFixture
        );
    }
}
