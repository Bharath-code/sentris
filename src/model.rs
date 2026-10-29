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
            || normalized.ends_with("_tests.rs")
            || normalized.ends_with("/tests.rs")
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

#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_date: Option<String>,
}

impl Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let field_count = 13
            + usize::from(self.commit_hash.is_some())
            + usize::from(self.commit_author.is_some())
            + usize::from(self.commit_date.is_some());
        let mut state = serializer.serialize_struct("Finding", field_count)?;
        state.serialize_field("rule_id", &self.rule_id)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("file_path", &self.file_path)?;
        state.serialize_field("line_number", &self.line_number)?;
        state.serialize_field("column", &self.column)?;
        state.serialize_field("redacted_match", &self.redacted_match)?;
        state.serialize_field("entropy", &self.entropy)?;
        state.serialize_field("fingerprint", &self.fingerprint)?;
        if let Some(ref ch) = self.commit_hash {
            state.serialize_field("commit_hash", ch)?;
        }
        if let Some(ref author) = self.commit_author {
            state.serialize_field("commit_author", author)?;
        }
        if let Some(ref date) = self.commit_date {
            state.serialize_field("commit_date", date)?;
        }
        state.serialize_field("context_kind", &self.context_kind())?;
        let env_var = crate::remediator::Remediator::env_var_name_for_rule(&self.rule_id);
        state.serialize_field("recommended_env_var", env_var)?;
        let remediate_cmd = format!("sentris fix {} --yes --json", self.file_path);
        state.serialize_field("remediate_command", &remediate_cmd)?;
        state.end()
    }
}

/// First `n` bytes of `s` (or all of it), never panicking on short or non-ASCII input.
pub fn short(s: &str, n: usize) -> &str {
    s.get(..n).unwrap_or(s)
}

impl Finding {
    /// Returns the syntactic file context classification (Production vs TestFixture)
    pub fn context_kind(&self) -> ContextKind {
        ContextKind::from_file_path(&self.file_path)
    }

    /// Shows at most a third of the secret (capped at 10 characters), so short and low-entropy values
    /// such as `admin:admin` or 9-15 character passwords are not effectively disclosed.
    pub fn mask_secret(secret: &str) -> String {
        let len = secret.len();
        let shown = (len / 3).min(10);
        if len <= 8 || shown < 3 {
            return "********".to_string();
        }
        let prefix_len = (shown * 3).div_ceil(5);
        let suffix_len = shown - prefix_len;
        match (secret.get(..prefix_len), secret.get(len - suffix_len..)) {
            (Some(head), Some(tail)) => format!("{head}...{tail}"),
            _ => "********".to_string(),
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
    /// Read-only probe verdicts keyed by finding fingerprint; empty unless `scan --probe` ran.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub exposures: std::collections::BTreeMap<String, crate::exposure::Exposure>,
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

#[cfg(test)]
mod mask_tests {
    use super::Finding;

    #[test]
    fn masks_reveal_at_most_a_third_of_any_secret() {
        for len in 1..80 {
            let secret: String = (0..len)
                .map(|i| char::from(b'a' + (i % 26) as u8))
                .collect();
            let masked = Finding::mask_secret(&secret);
            let revealed = masked
                .replace("...", "")
                .chars()
                .filter(|c| *c != '*')
                .count();
            assert!(
                revealed * 3 <= len.max(1),
                "{len}: {masked} reveals {revealed}"
            );
        }
        assert_eq!(Finding::mask_secret("admin:admin"), "ad...n");
    }
}
