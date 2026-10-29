pub mod gitleaks_migrator;
pub use gitleaks_migrator::GitleaksMigrator;

use crate::error::SentrisError;
use crate::model::Severity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub max_file_size_mb: u64,
    pub threads: Option<usize>,
    pub ignore_paths: Vec<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 10,
            threads: None,
            ignore_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub pattern: String,
    pub min_entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationConfig {
    pub dual_key_grace_hours: u32,
    pub backup_branch: bool,
}

impl Default for RemediationConfig {
    fn default() -> Self {
        Self {
            dual_key_grace_hours: 24,
            backup_branch: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub scanner: ScannerConfig,
    pub rules: Vec<CustomRule>,
    pub remediation: RemediationConfig,
}

impl Config {
    /// Returns the default production configuration template
    pub fn default_template() -> &'static str {
        r#"# ==============================================================================
# Sentris Configuration File (.sentris.toml)
# Documentation: https://github.com/Bharath-code/sentris
# ==============================================================================

[scanner]
# Maximum file size to scan in megabytes (default: 10)
max_file_size_mb = 10

# Custom path patterns to ignore in all scans
ignore_paths = [
    "target",
    "node_modules",
    "vendor",
    "tests/fixtures"
]

# Custom Enterprise Rules
# Define proprietary internal credentials, company tokens, or microservice keys
[[rules]]
rule_id = "internal-service-token"
name = "Acme Internal Service Token"
description = "Identifies hardcoded internal Acme microservice access tokens"
severity = "critical"
pattern = "acme_live_[0-9a-zA-Z]{32}"
min_entropy = 3.5

[remediation]
# Grace period before revoking deprecated credentials (hours)
dual_key_grace_hours = 24

# Create atomic git backup branch before any file modifications
backup_branch = true
"#
    }

    /// Initializes a new .sentris.toml configuration file in the target directory
    pub fn init(dir: &Path, force: bool) -> Result<PathBuf, SentrisError> {
        let config_path = dir.join(".sentris.toml");
        if config_path.exists() && !force {
            return Err(SentrisError::Config(format!(
                "Configuration file already exists at {}. Run with --force to overwrite.",
                config_path.display()
            )));
        }

        fs::write(&config_path, Self::default_template())?;
        Ok(config_path)
    }

    /// Locates and loads configuration from current directory or parent git root
    pub fn load_from_dir(dir: &Path) -> Option<Self> {
        let candidates = [
            dir.join(".sentris.toml"),
            dir.join("sentris.toml"),
            dir.join(".sentris.json"),
        ];

        candidates
            .iter()
            .find_map(|path| Self::load_file(path).ok())
    }

    /// Loads one specific config file (`.json` or TOML).
    pub fn load_file(path: &Path) -> Result<Self, SentrisError> {
        let content = fs::read_to_string(path)?;
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            Ok(serde_json::from_str(&content)?)
        } else {
            Self::from_toml_str(&content)
        }
    }

    /// Zero-dependency, safe TOML parser tailored for Sentris configuration
    #[allow(clippy::too_many_lines)]
    pub fn from_toml_str(content: &str) -> Result<Self, SentrisError> {
        let mut config = Config::default();

        #[derive(PartialEq)]
        enum Section {
            None,
            Scanner,
            Rule,
            Remediation,
        }

        let mut current_section = Section::None;
        let mut current_rule: Option<CustomRule> = None;
        let mut active_array: Option<(String, String)> = None;

        for line in content.lines() {
            let trimmed = line.trim();

            if let Some((key, mut acc)) = active_array.take() {
                acc.push(' ');
                acc.push_str(trimmed);
                if trimmed.contains(']') {
                    if key == "ignore_paths" {
                        config.scanner.ignore_paths = parse_string_array(&acc);
                    }
                } else {
                    active_array = Some((key, acc));
                }
                continue;
            }

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Section headers
            if trimmed == "[[rules]]" {
                if let Some(rule) = current_rule.take() {
                    config.rules.push(rule);
                }
                current_section = Section::Rule;
                current_rule = Some(CustomRule {
                    rule_id: String::new(),
                    name: String::new(),
                    description: String::new(),
                    severity: Severity::Medium,
                    pattern: String::new(),
                    min_entropy: 3.0,
                });
                continue;
            } else if trimmed == "[scanner]" {
                if let Some(rule) = current_rule.take() {
                    config.rules.push(rule);
                }
                current_section = Section::Scanner;
                continue;
            } else if trimmed == "[remediation]" {
                if let Some(rule) = current_rule.take() {
                    config.rules.push(rule);
                }
                current_section = Section::Remediation;
                continue;
            } else if trimmed.starts_with('[') && trimmed.ends_with(']') {
                if let Some(rule) = current_rule.take() {
                    config.rules.push(rule);
                }
                current_section = Section::None;
                continue;
            }

            // Key = Value parsing
            if let Some((key_part, val_part)) = trimmed.split_once('=') {
                let key = key_part.trim();
                let mut val = val_part.trim();

                // Check for multiline array start: key = [
                if val.starts_with('[') && !val.contains(']') {
                    active_array = Some((key.to_string(), val.to_string()));
                    continue;
                }

                // Strip inline comments if value does not contain quotes
                if let Some(idx) = val.find('#') {
                    if !val.starts_with('"') && !val.starts_with('\'') && !val.starts_with('[') {
                        val = val[..idx].trim();
                    }
                }

                let unquoted = val.trim_matches(&['"', '\''][..]);

                match current_section {
                    Section::Scanner => match key {
                        "max_file_size_mb" => {
                            if let Ok(v) = val.parse::<u64>() {
                                config.scanner.max_file_size_mb = v;
                            }
                        }
                        "threads" => {
                            if let Ok(v) = val.parse::<usize>() {
                                config.scanner.threads = Some(v);
                            }
                        }
                        "ignore_paths" => {
                            config.scanner.ignore_paths = parse_string_array(val);
                        }
                        _ => {}
                    },
                    Section::Rule => {
                        if let Some(rule) = current_rule.as_mut() {
                            match key {
                                "rule_id" | "id" => rule.rule_id = unquoted.to_string(),
                                "name" => rule.name = unquoted.to_string(),
                                "description" => rule.description = unquoted.to_string(),
                                "severity" => {
                                    rule.severity = match unquoted.to_lowercase().as_str() {
                                        "critical" => Severity::Critical,
                                        "high" => Severity::High,
                                        "low" => Severity::Low,
                                        _ => Severity::Medium,
                                    };
                                }
                                "pattern" => rule.pattern = unquoted.to_string(),
                                "min_entropy" => {
                                    if let Ok(e) = val.parse::<f64>() {
                                        rule.min_entropy = e;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Section::Remediation => match key {
                        "dual_key_grace_hours" => {
                            if let Ok(v) = val.parse::<u32>() {
                                config.remediation.dual_key_grace_hours = v;
                            }
                        }
                        "backup_branch" => {
                            config.remediation.backup_branch = val.to_lowercase() == "true";
                        }
                        _ => {}
                    },
                    Section::None => {}
                }
            }
        }

        if let Some(rule) = current_rule {
            config.rules.push(rule);
        }

        Ok(config)
    }
}

/// Robust helper to parse quoted strings from inline or multiline TOML array: ["a", "b"]
fn parse_string_array(val: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = '"';

    for c in val.chars() {
        if in_quote {
            if c == quote_char {
                in_quote = false;
                items.push(current.clone());
                current.clear();
            } else {
                current.push(c);
            }
        } else if c == '"' || c == '\'' {
            in_quote = true;
            quote_char = c;
            current.clear();
        }
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_template() {
        let template = Config::default_template();
        let config = Config::from_toml_str(template).expect("Failed to parse default template");

        assert_eq!(config.scanner.max_file_size_mb, 10);
        assert_eq!(config.scanner.ignore_paths.len(), 4);
        assert!(config.scanner.ignore_paths.contains(&"target".to_string()));

        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];
        assert_eq!(rule.rule_id, "internal-service-token");
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.pattern, "acme_live_[0-9a-zA-Z]{32}");
        assert_eq!(rule.min_entropy, 3.5);

        assert_eq!(config.remediation.dual_key_grace_hours, 24);
        assert!(config.remediation.backup_branch);
    }

    #[test]
    fn test_init_creates_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let created_path = Config::init(temp_dir.path(), false).unwrap();
        assert!(created_path.exists());

        let loaded = Config::load_from_dir(temp_dir.path()).unwrap();
        assert_eq!(loaded.scanner.max_file_size_mb, 10);
        assert_eq!(loaded.rules.len(), 1);
    }
}
