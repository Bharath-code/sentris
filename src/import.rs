//! Imports findings from another scanner's JSON report (Betterleaks, Gitleaks: same schema) so Sentris
//! can probe, rank and remediate them. The report is untrusted input: every entry is re-checked against the
//! file on disk, paths must stay inside the working directory, and a stale or redacted entry is dropped.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::SentrisError;
use crate::model::{Finding, ScanReport, ScanStats, Severity};

const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

/// Upper-bit flag in the 32-bit secret arena handle indicating a multi-line secret (e.g. PEM block).
const HANDLE_MULTILINE_FLAG: u32 = 1 << 31;
const HANDLE_INDEX_MASK: u32 = 0x00FF_FFFF;

/// Flat-array secret store replacing `HashMap<String, String>`.
/// Maps the 64-bit prefix of a finding's SHA-256 fingerprint to a bit-packed `u32` handle whose lower
/// 24 bits index into `values` and whose upper bits pack secret metadata flags (`HANDLE_MULTILINE_FLAG`).
#[derive(Debug, Clone, Default)]
pub struct ImportedSecrets {
    table: Vec<(u64, u32)>,
    values: Vec<String>,
}

fn fp_prefix_u64(fingerprint: &str) -> Option<u64> {
    if fingerprint.len() < 16 {
        return None;
    }
    u64::from_str_radix(&fingerprint[..16], 16).ok()
}

fn digest_prefix_u64(digest: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

impl ImportedSecrets {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            table: Vec::with_capacity(cap),
            values: Vec::with_capacity(cap),
        }
    }

    pub fn insert_digest(&mut self, digest: &[u8], secret: String) {
        let key = digest_prefix_u64(digest);
        let idx = (self.values.len() as u32) & HANDLE_INDEX_MASK;
        let flags = if secret.contains('\n') {
            HANDLE_MULTILINE_FLAG
        } else {
            0
        };
        self.values.push(secret);
        self.table.push((key, flags | idx));
    }

    pub fn finalize(&mut self) {
        self.table.sort_unstable_by_key(|&(k, _)| k);
        self.table.dedup_by_key(|&mut (k, _)| k);
    }

    /// Looks up `(secret_str, is_multiline)` by 64-char hex SHA-256 fingerprint using binary search on the flat table.
    pub fn get_with_flags(&self, fingerprint: &str) -> Option<(&str, bool)> {
        let key = fp_prefix_u64(fingerprint)?;
        let pos = self.table.binary_search_by_key(&key, |&(k, _)| k).ok()?;
        let handle = self.table[pos].1;
        let idx = (handle & HANDLE_INDEX_MASK) as usize;
        let is_multiline = (handle & HANDLE_MULTILINE_FLAG) != 0;
        self.values.get(idx).map(|s| (s.as_str(), is_multiline))
    }

    pub fn get(&self, fingerprint: &str) -> Option<&str> {
        self.get_with_flags(fingerprint).map(|(s, _)| s)
    }
}

impl std::ops::Index<&str> for ImportedSecrets {
    type Output = String;
    fn index(&self, fingerprint: &str) -> &Self::Output {
        let key = fp_prefix_u64(fingerprint).expect("invalid fingerprint");
        let pos = self
            .table
            .binary_search_by_key(&key, |&(k, _)| k)
            .expect("fingerprint not found in ImportedSecrets");
        let idx = (self.table[pos].1 & HANDLE_INDEX_MASK) as usize;
        &self.values[idx]
    }
}

impl std::ops::Index<&String> for ImportedSecrets {
    type Output = String;
    fn index(&self, fingerprint: &String) -> &Self::Output {
        self.index(fingerprint.as_str())
    }
}

impl From<HashMap<String, String>> for ImportedSecrets {
    fn from(map: HashMap<String, String>) -> Self {
        let mut out = Self::with_capacity(map.len());
        for (fp, secret) in map {
            if let Some(key) = fp_prefix_u64(&fp) {
                let idx = (out.values.len() as u32) & HANDLE_INDEX_MASK;
                let flags = if secret.contains('\n') {
                    HANDLE_MULTILINE_FLAG
                } else {
                    0
                };
                out.values.push(secret);
                out.table.push((key, flags | idx));
            }
        }
        out.finalize();
        out
    }
}

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
    /// Plaintext secrets indexed in a flat array by fingerprint prefix; only ever handed to `Scanner`.
    pub secrets: ImportedSecrets,
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

    let mut findings = Vec::with_capacity(entries.len());
    let mut secrets = ImportedSecrets::with_capacity(entries.len());
    let mut skipped = Vec::new();

    // Sort entry indices by (file, start_line, original_idx) so each file is canonicalized and read
    // at most once, lines are scanned in a single forward pass, and duplicates on the same line are adjacent.
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|&a, &b| {
        entries[a]
            .file
            .cmp(&entries[b].file)
            .then_with(|| entries[a].start_line.cmp(&entries[b].start_line))
            .then_with(|| a.cmp(&b))
    });

    let mut groups: Vec<&[usize]> = Vec::new();
    let mut group_start = 0;
    while group_start < order.len() {
        let file_key = &entries[order[group_start]].file;
        let mut group_end = group_start + 1;
        while group_end < order.len() && &entries[order[group_end]].file == file_key {
            group_end += 1;
        }
        groups.push(&order[group_start..group_end]);
        group_start = group_end;
    }

    use rayon::prelude::*;
    struct GroupOutcome {
        findings: Vec<Finding>,
        secrets: Vec<([u8; 32], String)>,
        skipped: Vec<String>,
        had_finding: bool,
    }

    let group_outcomes: Vec<GroupOutcome> = groups
        .par_iter()
        .map(|&group| {
            let file_key = &entries[group[0]].file;
            let mut g_findings = Vec::new();
            let mut g_secrets = Vec::new();
            let mut g_skipped = Vec::new();

            let Some(rel) = confine(&root, file_key) else {
                for &idx in group {
                    g_skipped.push(format!(
                        "{}: outside the working directory",
                        entries[idx].file
                    ));
                }
                return GroupOutcome {
                    findings: g_findings,
                    secrets: g_secrets,
                    skipped: g_skipped,
                    had_finding: false,
                };
            };

            let mut source_loaded = false;
            let mut source_text: Option<String> = None;
            let mut file_had_finding = false;
            let mut cur_seen_line = usize::MAX;
            let mut line_seen: Vec<[u8; 32]> = Vec::with_capacity(4);
            let mut line_cursor_idx: usize = 0;
            let mut line_cursor_byte_offset: usize = 0;

            for &idx in group {
                let e = &entries[idx];
                if e.secret.is_empty() {
                    g_skipped.push(format!(
                        "{rel}:{}: report has no secret (was it run with --redact?)",
                        e.start_line
                    ));
                    continue;
                }

                if !source_loaded {
                    source_text = read_source(&root, &rel);
                    source_loaded = true;
                }
                let Some(content) = source_text.as_deref() else {
                    g_skipped.push(format!("{rel}: unreadable, binary or too large"));
                    continue;
                };

                let target_line_idx = e.start_line.saturating_sub(1);
                let on_line = if let Some(line_slice) = advance_to_line(
                    content,
                    &mut line_cursor_idx,
                    &mut line_cursor_byte_offset,
                    target_line_idx,
                ) {
                    if e.secret.contains('\n') {
                        let first = e.secret.lines().next().unwrap_or(&e.secret);
                        line_slice.contains(first) && content.contains(&e.secret)
                    } else {
                        line_slice.contains(&e.secret)
                    }
                } else {
                    false
                };

                if !on_line {
                    g_skipped.push(format!(
                        "{rel}:{}: secret no longer at that line (file changed since the scan)",
                        e.start_line
                    ));
                    continue;
                }

                if e.start_line != cur_seen_line {
                    cur_seen_line = e.start_line;
                    line_seen.clear();
                }

                let digest = Sha256::digest(e.secret.as_bytes());
                let mut digest_arr = [0u8; 32];
                digest_arr.copy_from_slice(&digest);
                if line_seen.contains(&digest_arr) {
                    continue;
                }
                line_seen.push(digest_arr);

                let fingerprint = hex::encode(digest_arr);
                let rule_id = map_rule(&e.rule_id, &e.secret);
                g_findings.push(Finding {
                    severity: severity_for(&rule_id, &e.attributes.confidence),
                    rule_id,
                    description: e.description.clone(),
                    file_path: rel.clone(),
                    line_number: e.start_line,
                    column: e.start_column.max(1),
                    redacted_match: Finding::mask_secret(&e.secret),
                    entropy: e.entropy,
                    fingerprint,
                    commit_hash: (!e.commit.is_empty()).then(|| e.commit.clone()),
                    commit_author: (!e.author.is_empty()).then(|| e.author.clone()),
                    commit_date: (!e.date.is_empty()).then(|| e.date.clone()),
                });
                g_secrets.push((digest_arr, e.secret.clone()));
                file_had_finding = true;
            }

            GroupOutcome {
                findings: g_findings,
                secrets: g_secrets,
                skipped: g_skipped,
                had_finding: file_had_finding,
            }
        })
        .collect();

    let mut unique_files_with_findings = 0usize;
    for out in group_outcomes {
        if out.had_finding {
            unique_files_with_findings += 1;
        }
        findings.extend(out.findings);
        for (digest_arr, secret) in out.secrets {
            secrets.insert_digest(&digest_arr, secret);
        }
        skipped.extend(out.skipped);
    }

    secrets.finalize();

    let report = ScanReport {
        timestamp: crate::scanner::now_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        stats: ScanStats {
            files_scanned: unique_files_with_findings,
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

/// Advances `(cur_line_idx, cur_byte_offset)` monotonically to `target_line_idx` (0-indexed) and returns that line.
fn advance_to_line<'a>(
    content: &'a str,
    cur_line_idx: &mut usize,
    cur_byte_offset: &mut usize,
    target_line_idx: usize,
) -> Option<&'a str> {
    let bytes = content.as_bytes();
    if *cur_byte_offset >= bytes.len() && content.is_empty() {
        return None;
    }
    while *cur_line_idx < target_line_idx {
        let rest = &bytes[*cur_byte_offset..];
        let nl = rest.iter().position(|&b| b == b'\n')?;
        *cur_byte_offset += nl + 1;
        *cur_line_idx += 1;
        if *cur_byte_offset >= bytes.len() {
            return None;
        }
    }
    if *cur_byte_offset >= bytes.len() {
        return None;
    }
    let rest = &content[*cur_byte_offset..];
    let line = match rest.as_bytes().iter().position(|&b| b == b'\n') {
        Some(nl) => &rest[..nl],
        None => rest,
    };
    Some(line.strip_suffix('\r').unwrap_or(line))
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
    if secret.contains('\n') {
        let first = secret.lines().next().unwrap_or(secret);
        let on_line = content
            .lines()
            .nth(line.saturating_sub(1))
            .is_some_and(|l| l.contains(first));
        on_line && content.contains(secret)
    } else {
        content
            .lines()
            .nth(line.saturating_sub(1))
            .is_some_and(|l| l.contains(secret))
    }
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
