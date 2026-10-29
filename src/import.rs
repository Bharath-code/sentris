//! Imports findings from another scanner's JSON report (Betterleaks, Gitleaks: same schema) so Sentris
//! can probe, rank and remediate them. The report is untrusted input: every entry is re-checked against the
//! file on disk, paths must stay inside the working directory, and a stale or redacted entry is dropped.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::SentrisError;
use crate::model::{Finding, ScanReport, ScanStats, Severity};

const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct Entry {
    #[serde(rename = "RuleID")]
    rule_id: String,
    description: String,
    start_line: usize,
    start_column: usize,
    secret: String,
    file: String,
    entropy: f64,
    commit: String,
    author: String,
    date: String,
    attributes: Attributes,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Attributes {
    confidence: String,
}

pub struct Imported {
    pub report: ScanReport,
    /// Plaintext secrets by finding fingerprint (SHA-256 of the secret); only ever handed to `Scanner`.
    pub secrets: HashMap<String, String>,
    pub skipped: Vec<String>,
}

/// Loads a Betterleaks/Gitleaks JSON report; file paths are resolved against, and confined to, `root`.
pub fn load(report_path: &Path, root: &Path) -> Result<Imported, SentrisError> {
    let meta = fs::metadata(report_path)?;
    if meta.len() > MAX_REPORT_BYTES {
        return Err(SentrisError::Scan(format!(
            "Report {} is larger than {} MiB",
            report_path.display(),
            MAX_REPORT_BYTES >> 20
        )));
    }
    let text = fs::read_to_string(report_path)?;
    let entries: Vec<Entry> = serde_json::from_str(&text).map_err(|e| {
        SentrisError::Scan(format!(
            "{} is not a Betterleaks/Gitleaks JSON report (-f json): {e}",
            report_path.display()
        ))
    })?;
    let root = root.canonicalize()?;
    let started = std::time::Instant::now();

    let mut findings = Vec::new();
    let mut secrets = HashMap::new();
    let mut skipped = Vec::new();
    let mut seen = HashSet::new();
    let mut contents: HashMap<String, Option<String>> = HashMap::new();

    for e in entries {
        let Some(rel) = confine(&root, &e.file) else {
            skipped.push(format!("{}: outside the working directory", e.file));
            continue;
        };
        if e.secret.is_empty() {
            skipped.push(format!(
                "{rel}:{}: report has no secret (was it run with --redact?)",
                e.start_line
            ));
            continue;
        }
        let content = contents
            .entry(rel.clone())
            .or_insert_with(|| read_source(&root, &rel));
        let Some(content) = content.as_deref() else {
            skipped.push(format!("{rel}: unreadable, binary or too large"));
            continue;
        };
        if !secret_at_line(content, e.start_line, &e.secret) {
            skipped.push(format!(
                "{rel}:{}: secret no longer at that line (file changed since the scan)",
                e.start_line
            ));
            continue;
        }
        let fingerprint = hex::encode(Sha256::digest(e.secret.as_bytes()));
        if !seen.insert((rel.clone(), e.start_line, fingerprint.clone())) {
            continue;
        }
        let rule_id = map_rule(&e.rule_id, &e.secret);
        findings.push(Finding {
            severity: severity_for(&rule_id, &e.attributes.confidence),
            rule_id,
            description: e.description,
            file_path: rel,
            line_number: e.start_line,
            column: e.start_column.max(1),
            redacted_match: Finding::mask_secret(&e.secret),
            entropy: e.entropy,
            fingerprint: fingerprint.clone(),
            commit_hash: Some(e.commit).filter(|c| !c.is_empty()),
            commit_author: Some(e.author).filter(|c| !c.is_empty()),
            commit_date: Some(e.date).filter(|c| !c.is_empty()),
        });
        secrets.insert(fingerprint, e.secret);
    }

    let files = findings
        .iter()
        .map(|f| f.file_path.as_str())
        .collect::<HashSet<_>>()
        .len();
    let report = ScanReport {
        timestamp: crate::scanner::now_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        stats: ScanStats {
            files_scanned: files,
            findings_count: findings.len(),
            duration_ms: started.elapsed().as_millis(),
            ..ScanStats::default()
        },
        findings,
        exposures: Default::default(),
    };
    Ok(Imported {
        report,
        secrets,
        skipped,
    })
}

/// `file` as a path relative to `root`, or `None` when it resolves outside it (`..`, absolute paths, symlinks).
fn confine(root: &Path, file: &str) -> Option<String> {
    if file.is_empty() {
        return None;
    }
    let resolved = root.join(file).canonicalize().ok()?;
    let rel = resolved.strip_prefix(root).ok()?;
    resolved
        .is_file()
        .then(|| rel.to_string_lossy().into_owned())
}

fn read_source(root: &Path, rel: &str) -> Option<String> {
    let path = root.join(rel);
    (fs::metadata(&path).ok()?.len() <= MAX_SOURCE_BYTES)
        .then(|| fs::read_to_string(path).ok())
        .flatten()
}

/// The secret must still start on `line` (multi-line secrets such as PEM blocks: first line there, whole block present).
pub(crate) fn secret_at_line(content: &str, line: usize, secret: &str) -> bool {
    let first = secret.lines().next().unwrap_or(secret);
    let on_line = content
        .lines()
        .nth(line.saturating_sub(1))
        .is_some_and(|l| l.contains(first));
    on_line && content.contains(secret)
}

/// Betterleaks/Gitleaks rule ids onto the ids Sentris' probes, rotators and env-var names are keyed on.
fn map_rule(rule_id: &str, secret: &str) -> String {
    match rule_id {
        "aws-access-token" if secret.starts_with("AKIA") => "aws-access-key-id",
        "github-oauth" => "github-oauth-access-token",
        "stripe-access-token" if secret.starts_with("sk_") => "stripe-secret-key",
        "stripe-access-token" if secret.starts_with("rk_") => "stripe-restricted-key",
        other => other,
    }
    .to_string()
}

fn severity_for(rule_id: &str, confidence: &str) -> Severity {
    if crate::exposure::probe_for_rule(rule_id).is_some() {
        return Severity::Critical;
    }
    match confidence {
        "high" => Severity::High,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AKIA: &str = "AKIAJ5Q7X2M9R4T6W8YB";

    fn entry(file: &str, line: usize, secret: &str, rule: &str) -> serde_json::Value {
        serde_json::json!({
            "RuleID": rule, "Description": "d", "StartLine": line, "StartColumn": 3,
            "Secret": secret, "Match": secret, "File": file, "Entropy": 3.5,
            "Attributes": {"confidence": "high"}
        })
    }

    fn setup(entries: Vec<serde_json::Value>) -> (tempfile::TempDir, Imported) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("app.py"),
            format!("a = 1\nk = \"{AKIA}\"\n"),
        )
        .unwrap();
        let report = dir.path().join("r.json");
        fs::write(&report, serde_json::to_string(&entries).unwrap()).unwrap();
        let imported = load(&report, dir.path()).unwrap();
        (dir, imported)
    }

    #[test]
    fn imports_verified_entry_with_sentris_rule_id_and_fingerprint() {
        let (_d, i) = setup(vec![entry("app.py", 2, AKIA, "aws-access-token")]);
        let f = &i.report.findings[0];
        assert_eq!(f.rule_id, "aws-access-key-id");
        assert_eq!(f.file_path, "app.py");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.fingerprint, hex::encode(Sha256::digest(AKIA.as_bytes())));
        assert_eq!(i.secrets[&f.fingerprint], AKIA);
        assert!(!serde_json::to_string(&i.report).unwrap().contains(AKIA));
    }

    #[test]
    fn drops_stale_redacted_duplicate_and_escaping_entries() {
        let (d, i) = setup(vec![
            entry("app.py", 1, AKIA, "aws-access-token"),
            entry("app.py", 2, "", "aws-access-token"),
            entry("../etc/passwd", 1, "root", "generic-api-key"),
            entry("/etc/passwd", 1, "root", "generic-api-key"),
            entry("app.py", 2, AKIA, "aws-access-token"),
            entry("app.py", 2, AKIA, "aws-access-token"),
        ]);
        assert_eq!(i.report.findings.len(), 1);
        assert_eq!(i.skipped.len(), 4, "{:?}", i.skipped);
        drop(d);
    }

    #[test]
    fn rejects_non_report_json() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.json");
        fs::write(&p, "{\"findings\": []}").unwrap();
        assert!(load(&p, dir.path()).is_err());
    }

    #[test]
    fn rule_mapping_keys_on_secret_prefix() {
        assert_eq!(map_rule("aws-access-token", "ASIAXXXX"), "aws-access-token");
        assert_eq!(
            map_rule("stripe-access-token", "sk_live_x"),
            "stripe-secret-key"
        );
        assert_eq!(
            map_rule("stripe-access-token", "rk_live_x"),
            "stripe-restricted-key"
        );
        assert_eq!(
            map_rule("stripe-access-token", "pk_live_x"),
            "stripe-access-token"
        );
        assert_eq!(map_rule("anthropic-api-key", "x"), "anthropic-api-key");
    }
}
