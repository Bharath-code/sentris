use std::fs;
use std::path::Path;

use crate::config::{Config, CustomRule, RemediationConfig, ScannerConfig};
use crate::error::SentrisError;
use crate::model::Severity;

/// Migrates Gitleaks `.gitleaks.toml` configuration into native Sentris `.sentris.toml` format
pub struct GitleaksMigrator;

impl GitleaksMigrator {
    /// Parses a `.gitleaks.toml` configuration string into a native `Config` struct
    pub fn parse_gitleaks_toml(content: &str) -> Result<Config, SentrisError> {
        let mut rules = Vec::new();
        let mut ignore_paths = Vec::new();

        #[derive(PartialEq)]
        enum Section {
            None,
            Rule,
            Allowlist,
            RuleAllowlist,
        }

        struct PartialRule {
            id: Option<String>,
            description: Option<String>,
            regex: Option<String>,
            entropy: Option<f64>,
        }

        let mut current_section = Section::None;
        let mut current_rule: Option<PartialRule> = None;
        let mut in_paths_array = false;
        let mut in_multiline_regex = false;
        let mut multiline_regex_buf = String::new();

        let flush_rule = |r_opt: Option<PartialRule>, rules_list: &mut Vec<CustomRule>| {
            if let Some(r) = r_opt {
                if let Some(id) = r.id {
                    let desc = r
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("Migrated Gitleaks rule: {id}"));
                    let name = r.description.unwrap_or_else(|| id.clone());
                    let pattern = r.regex.unwrap_or_default();
                    let entropy = r.entropy.unwrap_or(3.0);

                    // Infer severity based on rule_id and description
                    let id_lower = id.to_lowercase();
                    let desc_lower = desc.to_lowercase();
                    let combined = format!("{id_lower} {desc_lower}");

                    let severity = if combined.contains("critical") {
                        Severity::Critical
                    } else if combined.contains("high")
                        || combined.contains("token")
                        || combined.contains("key")
                        || combined.contains("secret")
                        || combined.contains("password")
                        || combined.contains("private")
                        || combined.contains("credential")
                    {
                        Severity::High
                    } else if combined.contains("low") {
                        Severity::Low
                    } else {
                        Severity::Medium
                    };

                    rules_list.push(CustomRule {
                        rule_id: id,
                        name,
                        description: desc,
                        severity,
                        pattern,
                        min_entropy: entropy,
                    });
                }
            }
        };

        for raw_line in content.lines() {
            let line = raw_line.trim();

            // Handle multi-line regex continuation
            if in_multiline_regex {
                if let Some(end_idx) = line.find("'''").or_else(|| line.find("\"\"\"")) {
                    multiline_regex_buf.push_str(&line[..end_idx]);
                    if let Some(ref mut r) = current_rule {
                        r.regex = Some(multiline_regex_buf.clone());
                    }
                    in_multiline_regex = false;
                    multiline_regex_buf.clear();
                } else {
                    multiline_regex_buf.push_str(line);
                }
                continue;
            }

            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            // Handle section headers
            if line.starts_with('[') && line.ends_with(']') {
                in_paths_array = false;

                if line == "[[rules]]" {
                    flush_rule(current_rule.take(), &mut rules);
                    current_section = Section::Rule;
                    current_rule = Some(PartialRule {
                        id: None,
                        description: None,
                        regex: None,
                        entropy: None,
                    });
                    continue;
                } else if line == "[allowlist]" || line == "[[allowlist]]" {
                    flush_rule(current_rule.take(), &mut rules);
                    current_section = Section::Allowlist;
                    continue;
                } else if line.starts_with("[rules.allowlist]") {
                    current_section = Section::RuleAllowlist;
                    continue;
                } else {
                    flush_rule(current_rule.take(), &mut rules);
                    current_section = Section::None;
                    continue;
                }
            }

            // Handle allowlist paths array
            if in_paths_array {
                if line.contains(']') {
                    in_paths_array = false;
                }
                for item in line.split(',') {
                    let cleaned = item.trim().trim_matches(']').trim();
                    let stripped = strip_toml_quotes(cleaned);
                    if !stripped.is_empty() && !ignore_paths.contains(&stripped) {
                        ignore_paths.push(stripped);
                    }
                }
                continue;
            }

            // Parse key-value pairs
            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim();

                match current_section {
                    Section::Rule => {
                        if let Some(ref mut r) = current_rule {
                            match key {
                                "id" => {
                                    r.id = Some(strip_toml_quotes(val));
                                }
                                "description" => {
                                    r.description = Some(strip_toml_quotes(val));
                                }
                                "regex" | "pattern" => {
                                    if (val.starts_with("'''") && !val[3..].contains("'''"))
                                        || (val.starts_with("\"\"\"")
                                            && !val[3..].contains("\"\"\""))
                                    {
                                        in_multiline_regex = true;
                                        multiline_regex_buf = val[3..].to_string();
                                    } else {
                                        r.regex = Some(strip_toml_quotes(val));
                                    }
                                }
                                "entropy" => {
                                    if let Ok(ent) = val.parse::<f64>() {
                                        r.entropy = Some(ent);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Section::Allowlist if key == "paths" => {
                        if val.starts_with('[') && !val.contains(']') {
                            in_paths_array = true;
                            let inside = val.trim_start_matches('[').trim();
                            for item in inside.split(',') {
                                let cleaned = strip_toml_quotes(item.trim());
                                if !cleaned.is_empty() && !ignore_paths.contains(&cleaned) {
                                    ignore_paths.push(cleaned);
                                }
                            }
                        } else if val.starts_with('[') && val.ends_with(']') {
                            let inside = &val[1..val.len() - 1];
                            for item in inside.split(',') {
                                let cleaned = strip_toml_quotes(item.trim());
                                if !cleaned.is_empty() && !ignore_paths.contains(&cleaned) {
                                    ignore_paths.push(cleaned);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Flush any remaining trailing rule
        flush_rule(current_rule.take(), &mut rules);

        let scanner = ScannerConfig {
            max_file_size_mb: 10,
            threads: None,
            ignore_paths,
        };

        let remediation = RemediationConfig {
            dual_key_grace_hours: 24,
            backup_branch: true,
        };

        Ok(Config {
            scanner,
            rules,
            remediation,
        })
    }

    /// Serializes a `Config` into formatted `.sentris.toml` string
    pub fn to_sentris_toml(config: &Config) -> String {
        let mut out = String::new();
        out.push_str(
            "# ==============================================================================\n",
        );
        out.push_str("# Sentris Configuration File (.sentris.toml)\n");
        out.push_str("# Automatically migrated from .gitleaks.toml\n");
        out.push_str("# Documentation: https://github.com/sentris-security/sentris\n");
        out.push_str(
            "# ==============================================================================\n\n",
        );

        out.push_str("[scanner]\n");
        out.push_str(&format!(
            "max_file_size_mb = {}\n",
            config.scanner.max_file_size_mb
        ));
        if !config.scanner.ignore_paths.is_empty() {
            out.push_str("ignore_paths = [\n");
            for p in &config.scanner.ignore_paths {
                out.push_str(&format!("    \"{}\",\n", p));
            }
            out.push_str("]\n\n");
        } else {
            out.push_str("ignore_paths = []\n\n");
        }

        if !config.rules.is_empty() {
            out.push_str("# Custom Migrated Rules\n");
            for r in &config.rules {
                out.push_str("[[rules]]\n");
                out.push_str(&format!("rule_id = \"{}\"\n", r.rule_id));
                out.push_str(&format!("name = \"{}\"\n", r.name));
                out.push_str(&format!("description = \"{}\"\n", r.description));
                out.push_str(&format!(
                    "severity = \"{}\"\n",
                    match r.severity {
                        Severity::Critical => "critical",
                        Severity::High => "high",
                        Severity::Medium => "medium",
                        Severity::Low => "low",
                    }
                ));
                out.push_str(&format!(
                    "pattern = \"{}\"\n",
                    r.pattern.replace('\\', "\\\\").replace('"', "\\\"")
                ));
                out.push_str(&format!("min_entropy = {:.2}\n\n", r.min_entropy));
            }
        }

        out.push_str("[remediation]\n");
        out.push_str(&format!(
            "dual_key_grace_hours = {}\n",
            config.remediation.dual_key_grace_hours
        ));
        out.push_str(&format!(
            "backup_branch = {}\n",
            config.remediation.backup_branch
        ));

        out
    }

    /// Migrates a `.gitleaks.toml` file to `.sentris.toml` on disk
    pub fn migrate_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        input: P1,
        output: P2,
        force: bool,
    ) -> Result<(usize, usize), SentrisError> {
        let input_path = input.as_ref();
        let output_path = output.as_ref();

        if !input_path.exists() {
            return Err(SentrisError::Config(format!(
                "Source file not found at {}",
                input_path.display()
            )));
        }

        if output_path.exists() && !force {
            return Err(SentrisError::Config(format!(
                "Destination file already exists at {}. Run with --force to overwrite.",
                output_path.display()
            )));
        }

        let content = fs::read_to_string(input_path)?;
        let config = Self::parse_gitleaks_toml(&content)?;
        let rules_count = config.rules.len();
        let ignore_count = config.scanner.ignore_paths.len();

        let rendered = Self::to_sentris_toml(&config);
        fs::write(output_path, rendered)?;

        Ok((rules_count, ignore_count))
    }
}

/// Helper to strip single, triple, and double quotes from TOML values
fn strip_toml_quotes(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("'''") && s.ends_with("'''") && s.len() >= 6 {
        return s[3..s.len() - 3].trim().to_string();
    }
    if s.starts_with("\"\"\"") && s.ends_with("\"\"\"") && s.len() >= 6 {
        return s[3..s.len() - 3].trim().to_string();
    }
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        return s[1..s.len() - 1].trim().to_string();
    }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return s[1..s.len() - 1].trim().to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_parse_gitleaks_toml_basic() {
        let sample = r#"
title = "gitleaks config"

[[rules]]
id = "custom-api-token"
description = "Custom API Token"
regex = '''(?i)(?:api_key|token)[ =:'"]+([a-z0-9]{32})'''
entropy = 3.5

[[rules]]
id = "database-password-critical"
description = "Critical Database Master Password"
regex = '''password[ =:]+[a-zA-Z0-9!@#$%^&*]{16,}'''
entropy = 4.2

[allowlist]
description = "Global allowlist"
paths = [
    '''vendor/''',
    '''tests/fixtures''',
]
"#;

        let config = GitleaksMigrator::parse_gitleaks_toml(sample).expect("Failed to parse");
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.scanner.ignore_paths.len(), 2);
        assert_eq!(config.scanner.ignore_paths[0], "vendor/");
        assert_eq!(config.scanner.ignore_paths[1], "tests/fixtures");

        let r0 = &config.rules[0];
        assert_eq!(r0.rule_id, "custom-api-token");
        assert_eq!(r0.description, "Custom API Token");
        assert_eq!(r0.severity, Severity::High);
        assert_eq!(r0.min_entropy, 3.5);
        assert_eq!(r0.pattern, r#"(?i)(?:api_key|token)[ =:'"]+([a-z0-9]{32})"#);

        let r1 = &config.rules[1];
        assert_eq!(r1.rule_id, "database-password-critical");
        assert_eq!(r1.severity, Severity::Critical);
        assert_eq!(r1.min_entropy, 4.2);
    }

    #[test]
    fn test_migrate_file_and_to_sentris_toml() {
        let dir = tempdir().unwrap();
        let gitleaks_path = dir.path().join(".gitleaks.toml");
        let sentris_path = dir.path().join(".sentris.toml");

        let sample = r#"
[[rules]]
id = "slack-webhook"
description = "Slack Webhook URL"
regex = "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}"
entropy = 2.5

[allowlist]
paths = ["node_modules", "target"]
"#;
        fs::write(&gitleaks_path, sample).unwrap();

        let (rules, ignores) =
            GitleaksMigrator::migrate_file(&gitleaks_path, &sentris_path, false).unwrap();
        assert_eq!(rules, 1);
        assert_eq!(ignores, 2);

        // Verify content written to .sentris.toml
        let written = fs::read_to_string(&sentris_path).unwrap();
        assert!(written.contains("[[rules]]"));
        assert!(written.contains("rule_id = \"slack-webhook\""));
        assert!(written.contains("node_modules"));
        assert!(written.contains("target"));

        // Overwrite without force should fail
        let err = GitleaksMigrator::migrate_file(&gitleaks_path, &sentris_path, false);
        assert!(err.is_err());

        // Overwrite with force should succeed
        let ok = GitleaksMigrator::migrate_file(&gitleaks_path, &sentris_path, true);
        assert!(ok.is_ok());
    }
}
