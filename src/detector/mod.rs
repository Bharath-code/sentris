pub mod baseline;
pub mod entropy;
pub mod false_positives;
pub mod patterns;

use crate::error::SentrisError;
use crate::model::{Finding, Severity};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use sha2::{Digest, Sha256};

/// The secret is the first participating capture group (rules may alternate several), else the whole match.
fn secret_group<'h>(caps: &regex::Captures<'h>) -> Option<regex::Match<'h>> {
    caps.iter().skip(1).flatten().next().or_else(|| caps.get(0))
}

/// Shannon entropy is capped by alphabet size (hex tops out at 4.0), so hex literals get a lower bar.
fn effective_min_entropy(min_entropy: f64, candidate: &str) -> f64 {
    if candidate.len() >= 16 && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        min_entropy.min(3.0)
    } else {
        min_entropy
    }
}

/// 0 = vendor-specific, 1 = keyed generic, 2 = broad generic
fn rule_tier(rule_id: &str) -> u8 {
    match rule_id {
        "generic-api-key" | "url-basic-auth" => 1,
        "credential-assignment" | "credential-assignment-unquoted" => 2,
        "keyed-secret-value" | "password-literal" => 3,
        _ => 0,
    }
}

pub struct CompiledRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub regex: Regex,
    pub min_entropy: f64,
}

/// Rules are screened by one Aho-Corasick pass over their required literal prefixes; rules without a
/// usable prefix (`always`) are checked with their own regex, whole-file first.
pub struct DetectorEngine {
    rules: Vec<CompiledRule>,
    prefilter: Option<AhoCorasick>,
    literal_owner: Vec<usize>,
    always: Vec<usize>,
}

const MIN_LITERAL_LEN: usize = 3;

/// Unquoted `name = value` is ordinary syntax in source code, so that rule only runs on config-style files.
const SOURCE_AND_DOC_EXTENSIONS: [&str; 41] = [
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "py", "pyi", "rb", "go", "rs", "java", "kt", "kts",
    "cs", "php", "c", "h", "cc", "cpp", "hpp", "m", "swift", "scala", "dart", "lua", "r", "pl",
    "ex", "exs", "clj", "html", "htm", "md", "mdx", "rst", "map", "svg", "css", "scss", "vue",
];

fn allows_unquoted_assignments(file_path: &str) -> bool {
    let ext = file_path
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase());
    !ext.is_some_and(|e| SOURCE_AND_DOC_EXTENSIONS.contains(&e.as_str()))
}

/// Case-folded literal prefixes every match of `pattern` must start with, or None if unbounded/too short.
fn required_prefixes(pattern: &str) -> Option<Vec<String>> {
    // The Aho-Corasick prefilter is ASCII case-insensitive, so a leading (?i) need not be expanded into literals
    let pattern = pattern.strip_prefix("(?i)").unwrap_or(pattern);
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .ok()?;
    let mut extractor = Extractor::new();
    extractor.kind(ExtractKind::Prefix).limit_total(128);
    let seq = extractor.extract(&hir);
    let lits = seq.literals()?;
    let prefixes: Vec<String> = lits
        .iter()
        .map(|l| String::from_utf8_lossy(l.as_bytes()).to_ascii_lowercase())
        .collect();
    (!prefixes.is_empty() && prefixes.iter().all(|p| p.len() >= MIN_LITERAL_LEN))
        .then_some(prefixes)
}

impl DetectorEngine {
    pub fn with_config(config: Option<&crate::config::Config>) -> Result<Self, SentrisError> {
        let raw_rules = patterns::get_rules();
        let custom_count = config.map(|c| c.rules.len()).unwrap_or(0);
        let mut compiled = Vec::with_capacity(raw_rules.len() + custom_count);
        let mut pattern_strings = Vec::with_capacity(raw_rules.len() + custom_count);

        for rule in raw_rules {
            let re = Regex::new(rule.pattern)?;
            pattern_strings.push(rule.pattern.to_string());
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
                pattern_strings.push(custom.pattern.clone());
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

        let mut literals: Vec<String> = Vec::new();
        let mut literal_owner = Vec::new();
        let mut always = Vec::new();
        for (idx, pattern) in pattern_strings.iter().enumerate() {
            match required_prefixes(pattern) {
                Some(prefixes) => {
                    literal_owner.extend(std::iter::repeat_n(idx, prefixes.len()));
                    literals.extend(prefixes);
                }
                None => always.push(idx),
            }
        }
        let prefilter = if literals.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(&literals)
                    .map_err(|e| SentrisError::Scan(format!("prefilter build failed: {e}")))?,
            )
        };

        Ok(Self {
            rules: compiled,
            prefilter,
            literal_owner,
            always,
        })
    }

    /// Indices of rules that could match somewhere in `text`: prefix hits plus unanchored rules that really match.
    fn candidate_rules(&self, text: &str, among: Option<&[usize]>) -> Vec<usize> {
        let mut hits: Vec<usize> = Vec::new();
        if let Some(ac) = &self.prefilter {
            hits.extend(
                ac.find_overlapping_iter(text)
                    .map(|m| self.literal_owner[m.pattern().as_usize()]),
            );
        }
        let always = among.unwrap_or(&self.always);
        hits.extend(
            always
                .iter()
                .copied()
                .filter(|&i| self.rules[i].regex.is_match(text)),
        );
        hits.sort_unstable();
        hits.dedup();
        hits
    }

    pub fn new() -> Result<Self, SentrisError> {
        Self::with_config(None)
    }

    /// Extracts the raw secret token from a line of code using the compiled rule's capture group
    pub fn extract_raw_secret(&self, line: &str, rule_id: &str) -> Option<String> {
        if let Some(rule) = self.rules.iter().find(|r| r.rule_id == rule_id) {
            if let Some(caps) = rule.regex.captures(line) {
                let mat = secret_group(&caps)?;
                return Some(mat.as_str().to_string());
            }
        }
        None
    }

    /// Extracts the exact secret behind `finding`: the regex match on `line` whose SHA-256 equals its fingerprint.
    pub fn extract_secret_for_fingerprint(
        &self,
        line: &str,
        rule_id: &str,
        fingerprint: &str,
    ) -> Option<String> {
        let rule = self.rules.iter().find(|r| r.rule_id == rule_id)?;
        rule.regex.captures_iter(line).find_map(|caps| {
            let m = secret_group(&caps)?.as_str();
            (hex::encode(Sha256::digest(m.as_bytes())) == fingerprint).then(|| m.to_string())
        })
    }

    /// Extracts a multi-line PEM / private key block starting at `start_line_number` (1-indexed),
    /// returning `(start_line_number, end_line_number, escaped_single_line_pem_for_env)`.
    pub fn extract_multiline_pem_block(
        content: &str,
        start_line_number: usize,
    ) -> Option<(usize, usize, String)> {
        let lines: Vec<&str> = content.lines().collect();
        if start_line_number == 0 || start_line_number > lines.len() {
            return None;
        }
        let start_idx = start_line_number - 1;
        let first_line = lines[start_idx];
        let begin_pos = first_line.find("-----BEGIN ")?;

        let mut pem_lines = Vec::new();
        let mut end_idx = None;

        for (offset, &line) in lines[start_idx..].iter().enumerate() {
            let segment = if offset == 0 {
                &line[begin_pos..]
            } else {
                line.trim()
            };
            if let Some(end_marker_idx) = segment.find("-----END ") {
                if let Some(close_dashes) = segment[end_marker_idx + 9..].find("-----") {
                    let end_slice = &segment[..end_marker_idx + 9 + close_dashes + 5];
                    pem_lines.push(end_slice.trim());
                } else {
                    pem_lines.push(segment.trim());
                }
                end_idx = Some(start_idx + offset);
                break;
            } else {
                pem_lines.push(segment.trim_end_matches(['"', '\'', '`', ';', ',']));
            }
        }

        let final_idx = end_idx?;
        if final_idx > start_idx {
            Some((start_line_number, final_idx + 1, pem_lines.join("\\n")))
        } else {
            None
        }
    }

    /// Scans a single line of text with custom line number and optional commit hash
    pub fn scan_single_line(
        &self,
        line: &str,
        file_path: &str,
        line_number: usize,
        commit_hash: Option<String>,
    ) -> Vec<Finding> {
        self.scan_line_among(line, file_path, line_number, commit_hash, None)
    }

    fn scan_line_among(
        &self,
        line: &str,
        file_path: &str,
        line_number: usize,
        commit_hash: Option<String>,
        always_in_file: Option<&[usize]>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip lines that no rule could match
        let matched_indices = self.candidate_rules(line, always_in_file);
        if matched_indices.is_empty() {
            return findings;
        }

        // Check for inline suppression comments (supports multi-tool ecosystem standards)
        if line.contains("sentris-ignore")
            || line.contains("sentris:ignore")
            || line.contains("rustscan-ignore")
            || line.contains("rustscan:ignore")
            || line.contains("gitleaks:allow")
            || line.contains("pragma: allowlist secret")
            || line.contains("nosec")
            || line.contains("trufflehog:ignore")
            || line.contains("secretlint-disable")
        {
            return findings;
        }

        let mut raw_hits: Vec<(usize, usize, Finding)> = Vec::new();

        for rule_idx in matched_indices {
            let rule = &self.rules[rule_idx];
            if rule.rule_id == "credential-assignment-unquoted"
                && !allows_unquoted_assignments(file_path)
            {
                continue;
            }
            for caps in rule.regex.captures_iter(line) {
                let mat = match secret_group(&caps) {
                    Some(m) => m,
                    None => continue,
                };
                let matched_str = mat.as_str();

                // Check Shannon entropy threshold
                let entropy = entropy::calculate_shannon_entropy(matched_str);
                if entropy < effective_min_entropy(rule.min_entropy, matched_str) {
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

                raw_hits.push((
                    mat.start(),
                    mat.end(),
                    Finding {
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
                        commit_author: None,
                        commit_date: None,
                    },
                ));
            }
        }

        // A lower-tier (more specific) rule overlapping a span suppresses higher-tier generic rules on it
        for (i, (start, end, finding)) in raw_hits.iter().enumerate() {
            let tier = rule_tier(&finding.rule_id);
            let shadowed = raw_hits.iter().enumerate().any(|(j, (os, oe, other))| {
                i != j && start < oe && end > os && rule_tier(&other.rule_id) < tier
            });
            if !shadowed {
                findings.push(finding.clone());
            }
        }

        findings
    }

    /// Scans a text file's contents line-by-line, returning all detected findings.
    pub fn scan_text(&self, content: &str, file_path: &str) -> Vec<Finding> {
        // Whole-file prefilter: skip clean files in a single pass before line splitting
        let candidates = self.candidate_rules(content, None);
        if candidates.is_empty() {
            return Vec::new();
        }
        let always_in_file: Vec<usize> = candidates
            .into_iter()
            .filter(|i| self.always.contains(i))
            .collect();

        let mut findings = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_findings =
                self.scan_line_among(line, file_path, line_idx + 1, None, Some(&always_in_file));
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

    #[test]
    fn test_detect_openai_key() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!(
            "const openaiToken = \"",
            "sk-proj-",
            "aB8kM9xL2qR5tW7zP1nY3vF6hJ0sD4gE7jK9mN2pQ4\";\n"
        );
        let findings = engine.scan_text(test_code, "config.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "openai-api-key");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_anthropic_key() {
        let engine = DetectorEngine::new().unwrap();
        let test_code = concat!(
            "const anthropicToken = \"",
            "sk-ant-api03-",
            "aB8kM9xL2qR5tW7zP1nY3vF6hJ0sD4gE7jK9mN2pQ4rT6vX8zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z\";\n"
        );
        let findings = engine.scan_text(test_code, "config.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "anthropic-api-key");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_overlapping_rule_deduplication_and_capture_extraction() {
        let engine = DetectorEngine::new().unwrap();
        // Previously matched both stripe-secret-key and generic-api-key due to `stripeApiKey`
        let line = concat!(
            "const stripeApiKey = \"",
            "sk_live_",
            "test_mock_1234567890abcdef\";\n"
        );
        let findings = engine.scan_text(line, "sample_leak.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "stripe-secret-key");

        // Verify generic-api-key extracts only the secret token inside quotes, not `api_key = "..."`
        let generic_line = concat!(
            "const my_api_key = \"",
            "xK9mP2vL8qR4tW7z",
            "N1bY5jC3dF6hT0sU8yA2\";\n"
        );
        let generic_findings = engine.scan_text(generic_line, "app.ts");
        assert_eq!(generic_findings.len(), 1);
        assert_eq!(generic_findings[0].rule_id, "generic-api-key");
        assert!(generic_findings[0].redacted_match.starts_with("xK9mP2"));
        assert_eq!(
            engine.extract_raw_secret(generic_line, "generic-api-key"),
            Some("xK9mP2vL8qR4tW7zN1bY5jC3dF6hT0sU8yA2".to_string())
        );
    }

    #[test]
    fn test_modern_2026_ai_and_cloud_rules() {
        let engine = DetectorEngine::new().unwrap();
        let groq_line = concat!(
            "export GROQ_API_KEY=\"",
            "gsk_",
            "aB8kM9xL2qR5tW7zP1nY3vF6hJ0sD4gE7jK9mN2pQ4rT6vX8zA1b\";\n"
        );
        let findings = engine.scan_text(groq_line, ".env");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "groq-api-key");

        let supabase_line = concat!(
            "SUPABASE_TOKEN=\"",
            "sbp_",
            "9f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c\"\n"
        );
        let sb_findings = engine.scan_text(supabase_line, ".env");
        assert_eq!(sb_findings.len(), 1);
        assert_eq!(sb_findings[0].rule_id, "supabase-access-token");

        let jwt_secret_line = concat!(
            "const JWT_SECRET = \"",
            "k9L2mP8qR4vW7xZ1bN5jC3dF6hT0sU8yA2cB9xQ4wE",
            "\";\n"
        );
        let struct_findings = engine.scan_text(jwt_secret_line, "src/auth.ts");
        assert_eq!(struct_findings.len(), 1);
        assert_eq!(struct_findings[0].rule_id, "structural-secret-assignment");
        assert_eq!(
            engine.extract_raw_secret(jwt_secret_line, "structural-secret-assignment"),
            Some("k9L2mP8qR4vW7xZ1bN5jC3dF6hT0sU8yA2cB9xQ4wE".to_string())
        );
    }
}
