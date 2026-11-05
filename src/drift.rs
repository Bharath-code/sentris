//! Enterprise "Vault Coverage %", Secret Rot & Configuration Drift Auditor (`sentris drift` / `sentris rot`).
//! Audits source code environment variable references (`process.env.*`, `os.environ.get(...)`,
//! `std::env::var(...)`, `${{ secrets.* }}`, `var.*`) against `.env.example`, `.env`, and active
//! secret-backend remediation ledgers to surface:
//! - Missing runtime keys (`missing_from_env`) & undocumented keys (`missing_from_env_example`)
//! - Orphaned shadow secrets rotting in `.env` (`shadow_env_vars`)
//! - Stale unrotated credentials exceeding `--max-age-days` (`stale_keys`)
//! - Dead / revoked vendor API keys after deploy (`dead_or_revoked_keys` with `--verify`)
//! - Overall Vault Coverage % (`vault_coverage_pct`) and Secret Rot Score (`rot_score_pct`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::SentrisError;
use crate::remediator::rollback::RollbackLedger;
use crate::remediator::Remediator;
use crate::scanner::Scanner;
use crate::verifier::{LiveStatus, VerifierRegistry};

const IGNORED_SYSTEM_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "USERNAME",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "TEMP",
    "TMP",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "NODE_ENV",
    "NEXT_PUBLIC_APP_URL",
    "BASE_URL",
    "PUBLIC_URL",
    "PORT",
    "HOST",
    "HOSTNAME",
    "TZ",
    "CI",
    "DEBUG",
    "VERBOSE",
    "NO_COLOR",
    "FORCE_COLOR",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "CARGO_MANIFEST_DIR",
    "CARGO_PKG_VERSION",
    "CARGO_PKG_NAME",
    "OUT_DIR",
    "TARGET",
    "PROFILE",
    "GITHUB_ACTIONS",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_EVENT_NAME",
    "GITHUB_ACTOR",
    "RUNNER_OS",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaleKeyItem {
    pub key_name: String,
    pub source: String,
    pub age_days: u64,
    pub max_age_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VendorKeyStatus {
    pub key_name: String,
    pub rule_id: String,
    pub provider: String,
    pub source: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftReport {
    pub code_referenced_vars: Vec<String>,
    pub documented_vars: Vec<String>,
    pub provisioned_vars: Vec<String>,
    /// Referenced in code or `.env`, but missing from `.env.example`.
    pub missing_from_env_example: Vec<String>,
    /// Required by code or `.env.example`, but not provisioned in `.env` / secret backend ledger.
    pub missing_from_env: Vec<String>,
    /// Present in `.env`, but never referenced in code or documented in `.env.example` (Orphaned Secret Rot).
    pub shadow_env_vars: Vec<String>,
    /// Remaining un-remediated hardcoded secret findings in source code.
    pub hardcoded_leaks_count: usize,
    /// Credentials in `.env` or git history older than `max_age_days` without rotation (Age Rot).
    #[serde(default)]
    pub stale_keys: Vec<StaleKeyItem>,
    /// Vendor credentials in `.env` or repo confirmed `REVOKED` via live provider APIs (`--verify`).
    #[serde(default)]
    pub dead_or_revoked_keys: Vec<VendorKeyStatus>,
    /// Vendor credentials in `.env` or repo confirmed `ACTIVE` via live provider APIs (`--verify`).
    #[serde(default)]
    pub active_vendor_keys: Vec<VendorKeyStatus>,
    /// Percentage of total secret touchpoints abstracted into env/vault (`0.0`..=`100.0`).
    pub vault_coverage_pct: f64,
    /// Percentage of secret touchpoints affected by rot or drift (`0.0`..=`100.0`, lower is healthier).
    #[serde(default)]
    pub rot_score_pct: f64,
    pub has_drift: bool,
    #[serde(default)]
    pub has_rot: bool,
}

fn is_valid_env_var_name(name: &str) -> bool {
    if name.len() < 3 || name.len() > 80 {
        return false;
    }
    if IGNORED_SYSTEM_VARS.contains(&name) || name.starts_with("SENTRIS_") {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_uppercase()
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && name.contains('_')
}

fn parse_dotenv_keys(path: &Path) -> BTreeSet<String> {
    let Ok(content) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    let mut keys = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((key, _)) = stripped.split_once('=') {
            let k = key.trim();
            if is_valid_env_var_name(k) {
                keys.insert(k.to_string());
            }
        }
    }
    keys
}

fn collect_code_env_vars(root: &Path, re_code_env: &Regex, re_tf_var: &Regex) -> BTreeSet<String> {
    let mut code_vars = BTreeSet::new();
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .ignore(true)
        .git_ignore(true)
        .add_custom_ignore_filename(".sentrisignore");

    for entry in builder.build().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let rel = path.to_string_lossy().replace('\\', "/");
        if rel.contains("/.git/")
            || rel.starts_with(".git/")
            || rel.contains("/.sentris/")
            || rel.starts_with(".sentris/")
            || rel.ends_with("/.env")
            || rel == ".env"
            || rel.ends_with(".env.example")
        {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for caps in re_code_env.captures_iter(&content) {
            if let Some(m) = caps.iter().skip(1).flatten().next() {
                let candidate = m.as_str();
                if is_valid_env_var_name(candidate) {
                    code_vars.insert(candidate.to_string());
                }
            }
        }
        if rel.ends_with(".tf") {
            for caps in re_tf_var.captures_iter(&content) {
                if let Some(m) = caps.get(1) {
                    let upper = m.as_str().to_ascii_uppercase();
                    if is_valid_env_var_name(&upper) {
                        code_vars.insert(upper);
                    }
                }
            }
        }
    }
    code_vars
}

/// Parses an optional `# rotated: YYYY-MM-DD` or `# created: YYYY-MM-DD` comment into epoch seconds.
fn parse_iso_date_comment_epoch(text: &str) -> Option<u64> {
    let lower = text.to_ascii_lowercase();
    for marker in ["rotated:", "created:", "updated:"] {
        if let Some(idx) = lower.find(marker) {
            let after = text[idx + marker.len()..].trim();
            let date_part: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            if date_part.len() == 10 {
                let iso = format!("{date_part}T00:00:00Z");
                if let Some(ts) = crate::rotator::timefmt::parse_rfc3339(&iso) {
                    return Some(ts);
                }
            }
        }
    }
    None
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Inspects `.env` keys for age rot (`stale_keys`) and optionally live provider verification (`--verify`).
#[allow(clippy::too_many_lines)]
fn audit_dotenv_rot_and_live_keys(
    root: &Path,
    max_age_days: u64,
    verify_live: bool,
) -> (
    Vec<StaleKeyItem>,
    Vec<VendorKeyStatus>,
    Vec<VendorKeyStatus>,
) {
    let dotenv_path = root.join(".env");
    let Ok(content) = fs::read_to_string(&dotenv_path) else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let now_secs = current_epoch_secs();
    let file_mtime_secs = fs::metadata(&dotenv_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(now_secs);

    let mut key_ages: BTreeMap<String, u64> = BTreeMap::new();
    let mut pending_comment_ts: Option<u64> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            pending_comment_ts = None;
            continue;
        }
        if trimmed.starts_with('#') {
            if let Some(ts) = parse_iso_date_comment_epoch(trimmed) {
                pending_comment_ts = Some(ts);
            }
            continue;
        }
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((key, rest)) = stripped.split_once('=') {
            let k = key.trim();
            if is_valid_env_var_name(k) {
                let inline_ts = parse_iso_date_comment_epoch(rest);
                let ts = inline_ts.or(pending_comment_ts).unwrap_or(file_mtime_secs);
                let age_days = now_secs.saturating_sub(ts) / 86_400;
                key_ages.insert(k.to_string(), age_days);
            }
        }
        pending_comment_ts = None;
    }

    let mut stale_keys = Vec::new();
    for (key_name, age_days) in key_ages {
        if age_days > max_age_days {
            stale_keys.push(StaleKeyItem {
                key_name,
                source: ".env".to_string(),
                age_days,
                max_age_days,
            });
        }
    }

    let mut dead_or_revoked_keys = Vec::new();
    let mut active_vendor_keys = Vec::new();

    if verify_live {
        if let Ok(detector) = crate::detector::DetectorEngine::new() {
            let registry = VerifierRegistry::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
                let Some((key, raw_val)) = stripped.split_once('=') else {
                    continue;
                };
                let key_name = key.trim().to_string();
                let findings = detector.scan_single_line(trimmed, ".env", 1, None);
                for finding in findings {
                    let Some(verifier) = registry.find_verifier(&finding.rule_id) else {
                        continue;
                    };
                    let mut secret = raw_val
                        .split('#')
                        .next()
                        .unwrap_or(raw_val)
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    if crate::verifier::detect_canary_token(&secret, Some(trimmed)).is_some() {
                        Remediator::zeroize_secret_string(&mut secret);
                        continue;
                    }
                    if let Ok(status) = verifier.verify_live(&secret) {
                        match status {
                            LiveStatus::Revoked => {
                                dead_or_revoked_keys.push(VendorKeyStatus {
                                    key_name: key_name.clone(),
                                    rule_id: finding.rule_id.clone(),
                                    provider: verifier.provider_name().to_string(),
                                    source: ".env".to_string(),
                                    status: "REVOKED".to_string(),
                                });
                            }
                            LiveStatus::Active { scopes } => {
                                active_vendor_keys.push(VendorKeyStatus {
                                    key_name: key_name.clone(),
                                    rule_id: finding.rule_id.clone(),
                                    provider: verifier.provider_name().to_string(),
                                    source: ".env".to_string(),
                                    status: format!("ACTIVE ({})", scopes.join(", ")),
                                });
                            }
                            LiveStatus::Unverified(_) => {}
                        }
                    }
                    Remediator::zeroize_secret_string(&mut secret);
                }
            }
        }
    }

    (stale_keys, dead_or_revoked_keys, active_vendor_keys)
}

/// Audits `<root>` to compute Vault Coverage % and configuration drift between code, `.env.example`, and `.env` / vault.
pub fn analyze_drift(root: &Path) -> Result<DriftReport, SentrisError> {
    analyze_drift_with_options(root, 90, false)
}

/// Audits `<root>` for Secret Rot (stale keys > `max_age_days`, dead/revoked vendor keys, orphaned `.env` keys) and configuration drift.
#[allow(clippy::too_many_lines)]
pub fn analyze_drift_with_options(
    root: &Path,
    max_age_days: u64,
    verify_live: bool,
) -> Result<DriftReport, SentrisError> {
    let re_code_env = Regex::new(
        r#"(?:process\.env\.([A-Z][A-Z0-9_]{2,79})\b|import\.meta\.env\.([A-Z][A-Z0-9_]{2,79})\b|os\.(?:environ(?:\.get)?|getenv)\s*[\(\[]\s*['"]([A-Z][A-Z0-9_]{2,79})['"]|(?:std::)?env::var(?:_os)?\s*\(\s*"([A-Z][A-Z0-9_]{2,79})"|\bENV\s*\[\s*['"]([A-Z][A-Z0-9_]{2,79})['"]\s*\]|\bos\.Getenv\s*\(\s*"([A-Z][A-Z0-9_]{2,79})"|\$\{\{\s*secrets\.([A-Z][A-Z0-9_]{2,79})\s*\}\}|\$\{([A-Z][A-Z0-9_]{2,79})\})"#,
    )?;
    let re_tf_var = Regex::new(r"\bvar\.([a-zA-Z][a-zA-Z0-9_]{2,79})\b")?;
    let code_vars = collect_code_env_vars(root, &re_code_env, &re_tf_var);

    let documented = [
        root.join(".env.example"),
        root.join(".env.sample"),
        root.join(".env.template"),
    ]
    .iter()
    .find(|p| p.exists())
    .map(|p| parse_dotenv_keys(p))
    .unwrap_or_default();

    let mut provisioned = parse_dotenv_keys(&root.join(".env"));
    if let Ok(ledger) = RollbackLedger::load_from(&root.join(".sentris/rollback_ledger.json")) {
        for tx in ledger.transactions {
            for caps in re_code_env.captures_iter(&tx.replacement_line) {
                if let Some(m) = caps.iter().skip(1).flatten().next() {
                    let candidate = m.as_str();
                    if is_valid_env_var_name(candidate) {
                        provisioned.insert(candidate.to_string());
                    }
                }
            }
        }
    }

    let scanner = Scanner::new()?;
    let scan_report = scanner.scan_path(root)?;
    let hardcoded_leaks_count = scan_report
        .findings
        .iter()
        .filter(|f| {
            if matches!(
                f.rule_id.as_str(),
                "mcp-unpinned-npx-server"
                    | "unicode-prompt-injection"
                    | "ai-prompt-injection-exfil"
            ) {
                return false;
            }
            let norm = f.file_path.replace('\\', "/");
            let trimmed = norm.trim_start_matches("./");
            trimmed != ".env"
                && !trimmed.ends_with("/.env")
                && !trimmed.starts_with(".sentris/")
                && !trimmed.contains("/.sentris/")
        })
        .count();

    let (stale_keys, dead_or_revoked_keys, active_vendor_keys) =
        audit_dotenv_rot_and_live_keys(root, max_age_days, verify_live);

    let all_known_vars: BTreeSet<String> = code_vars
        .union(&documented)
        .cloned()
        .collect::<BTreeSet<_>>()
        .union(&provisioned)
        .cloned()
        .collect();

    let missing_from_env_example: Vec<String> = code_vars
        .union(&provisioned)
        .filter(|k| !documented.contains(*k))
        .cloned()
        .collect();

    let missing_from_env: Vec<String> = code_vars
        .union(&documented)
        .filter(|k| !provisioned.contains(*k))
        .cloned()
        .collect();

    let shadow_env_vars: Vec<String> = provisioned
        .iter()
        .filter(|k| !code_vars.contains(*k) && !documented.contains(*k))
        .cloned()
        .collect();

    let managed_count = all_known_vars.len();
    let total_secret_touchpoints = managed_count + hardcoded_leaks_count;
    let vault_coverage_pct = if total_secret_touchpoints == 0 {
        100.0
    } else {
        ((managed_count as f64 / total_secret_touchpoints as f64) * 1000.0).round() / 10.0
    };

    let rotted_touchpoints = shadow_env_vars.len()
        + stale_keys.len()
        + dead_or_revoked_keys.len()
        + hardcoded_leaks_count;
    let rot_score_pct = if total_secret_touchpoints == 0 {
        0.0
    } else {
        ((rotted_touchpoints.min(total_secret_touchpoints) as f64
            / total_secret_touchpoints as f64)
            * 1000.0)
            .round()
            / 10.0
    };

    let has_rot = !shadow_env_vars.is_empty()
        || !stale_keys.is_empty()
        || !dead_or_revoked_keys.is_empty()
        || hardcoded_leaks_count > 0;

    let has_drift = !missing_from_env_example.is_empty() || !missing_from_env.is_empty() || has_rot;

    Ok(DriftReport {
        code_referenced_vars: code_vars.into_iter().collect(),
        documented_vars: documented.into_iter().collect(),
        provisioned_vars: provisioned.into_iter().collect(),
        missing_from_env_example,
        missing_from_env,
        shadow_env_vars,
        hardcoded_leaks_count,
        stale_keys,
        dead_or_revoked_keys,
        active_vendor_keys,
        vault_coverage_pct,
        rot_score_pct,
        has_drift,
        has_rot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn computes_vault_coverage_and_detects_env_drift() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("app.ts"),
            "const a = process.env.STRIPE_SECRET_KEY;\nconst b = process.env.OPENAI_API_KEY;\n",
        )
        .expect("write app.ts");
        fs::write(dir.path().join(".env.example"), "STRIPE_SECRET_KEY=\n").expect("write example");
        fs::write(
            dir.path().join(".env"),
            "STRIPE_SECRET_KEY=sk_test_123\n# created: 2024-01-15\nSHADOW_LEGACY_KEY=abc\n",
        )
        .expect("write .env");

        let report = analyze_drift_with_options(dir.path(), 90, false).expect("analyze drift");
        assert_eq!(
            report.code_referenced_vars,
            vec!["OPENAI_API_KEY", "STRIPE_SECRET_KEY"]
        );
        assert_eq!(report.documented_vars, vec!["STRIPE_SECRET_KEY"]);
        assert!(report
            .missing_from_env_example
            .contains(&"OPENAI_API_KEY".to_string()));
        assert!(report
            .missing_from_env
            .contains(&"OPENAI_API_KEY".to_string()));
        assert_eq!(report.shadow_env_vars, vec!["SHADOW_LEGACY_KEY"]);
        assert_eq!(report.stale_keys.len(), 1);
        assert_eq!(report.stale_keys[0].key_name, "SHADOW_LEGACY_KEY");
        assert!(report.stale_keys[0].age_days > 90);
        assert_eq!(report.hardcoded_leaks_count, 0);
        assert!((report.vault_coverage_pct - 100.0).abs() < f64::EPSILON);
        assert!(report.has_drift);
        assert!(report.has_rot);
    }
}
