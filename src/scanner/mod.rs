use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use ignore::{WalkBuilder, WalkState};

use crate::config::Config;
use crate::detector::DetectorEngine;
use crate::error::SentrisError;
use crate::model::{Finding, ScanReport, ScanStats};

/// Patterns that would match every path (or none meaningfully) are refused.
fn is_safe_ignore(pattern: &str) -> bool {
    let p = pattern.trim().trim_matches('/');
    !(p.is_empty() || matches!(p, "." | ".." | "*" | "**"))
}

/// Component-aware match: `vendor` hides `a/vendor/x` but not `my-vendor-notes.txt`.
fn path_matches_ignore(path: &str, pattern: &str) -> bool {
    let pat = pattern.trim().trim_matches('/');
    if !is_safe_ignore(pattern) {
        return false;
    }
    let norm = path.replace('\\', "/");
    let norm = norm.trim_start_matches("./");
    norm == pat
        || norm.starts_with(&format!("{pat}/"))
        || norm.contains(&format!("/{pat}/"))
        || norm.ends_with(&format!("/{pat}"))
}

pub struct Scanner {
    detector: DetectorEngine,
    config: Option<Config>,
}

impl Scanner {
    pub fn new() -> Result<Self, SentrisError> {
        // CI should point SENTRIS_CONFIG_FILE at a config the scanned (possibly hostile) tree cannot edit
        let mut config = match std::env::var_os("SENTRIS_CONFIG_FILE").filter(|v| !v.is_empty()) {
            Some(file) => Some(Config::load_file(Path::new(&file)).map_err(|e| {
                SentrisError::Config(format!("Cannot load SENTRIS_CONFIG_FILE: {e}"))
            })?),
            None => Config::load_from_dir(Path::new(".")),
        };
        if let Some(cfg) = config.as_mut() {
            let before = cfg.scanner.ignore_paths.len();
            cfg.scanner.ignore_paths.retain(|p| is_safe_ignore(p));
            if cfg.scanner.ignore_paths.len() != before {
                eprintln!("warning: ignored overly broad ignore_paths entries (empty, '/', '.', '*'); they would hide every file");
            }
        }
        let detector = DetectorEngine::with_config(config.as_ref())?;
        Ok(Self { detector, config })
    }

    /// Scanner for guardrails (hooks): built-in rules plus only a config the user names in `SENTRIS_CONFIG_FILE`.
    /// A config inside the working tree is ignored, so a hostile repo cannot weaken or break the guard.
    pub fn trusted() -> Result<Self, SentrisError> {
        let config = match std::env::var_os("SENTRIS_CONFIG_FILE").filter(|v| !v.is_empty()) {
            Some(file) => Some(Config::load_file(Path::new(&file)).map_err(|e| {
                SentrisError::Config(format!("Cannot load SENTRIS_CONFIG_FILE: {e}"))
            })?),
            None => None,
        };
        let detector = DetectorEngine::with_config(config.as_ref())?;
        Ok(Self { detector, config })
    }

    /// Extracts the raw secret token from a line using the compiled rule's regex capture
    /// Resolves the secret a finding points at, shared by CLI and MCP remediation.
    /// PEM blocks come from the file; anything else must hash to the finding's fingerprint.
    pub fn resolve_finding_secret(
        &self,
        content: &str,
        finding: &Finding,
    ) -> Result<String, SentrisError> {
        if let Some((_, _, pem)) = crate::detector::DetectorEngine::extract_multiline_pem_block(
            content,
            finding.line_number,
        ) {
            return Ok(pem);
        }
        let line = content
            .lines()
            .nth(finding.line_number.saturating_sub(1))
            .ok_or_else(|| {
                SentrisError::Scan(format!(
                    "Line {} no longer exists in {}",
                    finding.line_number, finding.file_path
                ))
            })?;
        self.detector
            .extract_secret_for_fingerprint(line, &finding.rule_id, &finding.fingerprint)
            .ok_or_else(|| {
                SentrisError::Scan(format!(
                    "Could not isolate the flagged secret on line {} of {} (file changed since the scan?); refusing to guess",
                    finding.line_number, finding.file_path
                ))
            })
    }

    pub fn extract_raw_secret(&self, line: &str, rule_id: &str) -> Option<String> {
        self.detector.extract_raw_secret(line, rule_id)
    }

    /// Replaces every detected secret in `text` with a `«sentris:<rule>:<fp8>»` marker.
    pub fn redact_text(&self, text: &str) -> crate::redact::Redaction {
        crate::redact::redact(&self.detector, text)
    }

    /// Scans a target path recursively using Rayon parallelism and the `ignore` crate.
    #[allow(clippy::too_many_lines)]
    pub fn scan_path<P: AsRef<Path>>(&self, root_path: P) -> Result<ScanReport, SentrisError> {
        let start_time = Instant::now();
        let path = root_path.as_ref();

        if !path.exists() {
            return Err(SentrisError::Scan(format!(
                "Path does not exist: {}",
                path.display()
            )));
        }

        // Configure walker respecting .gitignore, .ignore, and .sentrisignore
        let mut builder = WalkBuilder::new(path);
        builder
            .hidden(false) // Still scan hidden files like .env
            .ignore(true)
            .git_global(true)
            .git_ignore(true)
            .git_exclude(true)
            .add_custom_ignore_filename(".sentrisignore");

        let files_ignored = AtomicUsize::new(0);
        let total_files_scanned = AtomicUsize::new(0);
        let total_bytes_scanned = AtomicU64::new(0);

        let max_file_bytes = self
            .config
            .as_ref()
            .map(|c| c.scanner.max_file_size_mb * 1024 * 1024)
            .unwrap_or(10 * 1024 * 1024);

        let aggregated_findings: Mutex<Vec<Finding>> = Mutex::new(Vec::new());

        // Lock-free work-stealing parallel directory traversal & file scanning
        builder.build_parallel().run(|| {
            let detector = &self.detector;
            let config = &self.config;
            let root = path;
            let files_ignored = &files_ignored;
            let total_files_scanned = &total_files_scanned;
            let total_bytes_scanned = &total_bytes_scanned;
            let aggregated_findings = &aggregated_findings;

            Box::new(move |result| {
                let entry = match result {
                    Ok(e) => e,
                    Err(_) => {
                        files_ignored.fetch_add(1, Ordering::Relaxed);
                        return WalkState::Continue;
                    }
                };

                let file_type = match entry.file_type() {
                    Some(ft) => ft,
                    None => return WalkState::Continue,
                };

                // Git internals are never tracked content; .sentris/ is scanned (its ledgers hold secrets)
                // unless the user's gitignore already excludes it. Only look below the scan root.
                let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
                if rel.components().any(|c| c.as_os_str() == ".git")
                    || entry.file_name() == ".sentris-baseline.json"
                {
                    files_ignored.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Skip;
                }

                if !file_type.is_file() {
                    return WalkState::Continue;
                }

                let file_path = entry.path();
                let path_str = file_path.to_string_lossy();

                // Check custom ignore_paths from config
                if let Some(cfg) = config {
                    if cfg
                        .scanner
                        .ignore_paths
                        .iter()
                        .any(|p| path_matches_ignore(&path_str, p))
                    {
                        files_ignored.fetch_add(1, Ordering::Relaxed);
                        return WalkState::Continue;
                    }
                }

                let mut file = match File::open(file_path) {
                    Ok(f) => f,
                    Err(_) => return WalkState::Continue,
                };

                // Skip oversized files exceeding max_file_bytes to protect memory and CPU
                if let Ok(meta) = file.metadata() {
                    if meta.len() > max_file_bytes {
                        files_ignored.fetch_add(1, Ordering::Relaxed);
                        return WalkState::Continue;
                    }
                }

                let mut buffer = Vec::new();
                if file.read_to_end(&mut buffer).is_err() {
                    return WalkState::Continue;
                }

                // Check for null bytes in initial 512 bytes (binary file detection)
                let check_len = buffer.len().min(512);
                if buffer[..check_len].contains(&0) {
                    files_ignored.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Continue;
                }

                let content = match std::str::from_utf8(&buffer) {
                    Ok(s) => s,
                    Err(_) => return WalkState::Continue,
                };

                total_files_scanned.fetch_add(1, Ordering::Relaxed);
                total_bytes_scanned.fetch_add(buffer.len() as u64, Ordering::Relaxed);

                let file_findings = detector.scan_text(content, &path_str);
                if !file_findings.is_empty() {
                    if let Ok(mut guard) = aggregated_findings.lock() {
                        guard.extend(file_findings);
                    }
                }

                WalkState::Continue
            })
        });

        let mut findings = aggregated_findings.into_inner().unwrap_or_default();
        findings.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then_with(|| a.line_number.cmp(&b.line_number))
        });

        let duration = start_time.elapsed();

        let stats = ScanStats {
            files_scanned: total_files_scanned.load(Ordering::Relaxed),
            files_ignored: files_ignored.load(Ordering::Relaxed),
            bytes_scanned: total_bytes_scanned.load(Ordering::Relaxed),
            findings_count: findings.len(),
            duration_ms: duration.as_millis(),
        };

        Ok(ScanReport {
            timestamp: chrono_now_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats,
            findings,
            exposures: Default::default(),
        })
    }

    /// Scans only staged diff hunks (`git diff --cached -U0`) from the git index for sub-25ms pre-commit execution.
    pub fn scan_staged(&self) -> Result<ScanReport, SentrisError> {
        let start_time = Instant::now();
        let (findings, files_scanned, total_bytes) =
            crate::git::GitManager::scan_staged_diff_hunks(&self.detector)?;

        let duration = start_time.elapsed();

        let stats = ScanStats {
            files_scanned,
            files_ignored: 0,
            bytes_scanned: total_bytes,
            findings_count: findings.len(),
            duration_ms: duration.as_millis(),
        };

        Ok(ScanReport {
            timestamp: chrono_now_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats,
            findings,
            exposures: Default::default(),
        })
    }

    /// Scans the entire git commit graph and diff history.
    pub fn scan_git_history(&self) -> Result<ScanReport, SentrisError> {
        let start_time = Instant::now();
        let (findings, commits_count, total_bytes) =
            crate::git::GitManager::scan_git_history(&self.detector)?;

        let duration = start_time.elapsed();

        let stats = ScanStats {
            files_scanned: commits_count,
            files_ignored: 0,
            bytes_scanned: total_bytes,
            findings_count: findings.len(),
            duration_ms: duration.as_millis(),
        };

        Ok(ScanReport {
            timestamp: chrono_now_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats,
            findings,
            exposures: Default::default(),
        })
    }

    /// Scans git commits since a given commit ref or branch range (e.g. `HEAD~1` or `origin/main..HEAD`).
    pub fn scan_git_since(&self, since_ref: &str) -> Result<ScanReport, SentrisError> {
        let start_time = Instant::now();
        let (findings, commits_count, total_bytes) =
            crate::git::GitManager::scan_git_since(&self.detector, since_ref)?;

        let duration = start_time.elapsed();

        let stats = ScanStats {
            files_scanned: commits_count,
            files_ignored: 0,
            bytes_scanned: total_bytes,
            findings_count: findings.len(),
            duration_ms: duration.as_millis(),
        };

        Ok(ScanReport {
            timestamp: chrono_now_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats,
            findings,
            exposures: Default::default(),
        })
    }
}

fn chrono_now_string() -> String {
    // Standard ISO-8601 UTC timestamp approximation without heavy chrono dependency
    use std::time::SystemTime;
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{}", duration.as_secs(), duration.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_scan_directory_with_secrets() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.js");
        fs::write(
            &file_path,
            concat!(
                "const apiKey = '",
                "sk_live_",
                "51AbcDefGhIjKlMnOpQrStUvWxYz123456';"
            ),
        )
        .unwrap();

        let scanner = Scanner::new().unwrap();
        let report = scanner.scan_path(dir.path()).unwrap();

        assert!(report.stats.findings_count >= 1);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "stripe-secret-key"));
    }

    #[test]
    fn test_scan_directory_clean() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("clean.js");
        fs::write(&file_path, "const port = 8080;\nconsole.log(port);").unwrap();

        let scanner = Scanner::new().unwrap();
        let report = scanner.scan_path(dir.path()).unwrap();

        assert_eq!(report.stats.findings_count, 0);
    }

    #[test]
    fn resolve_picks_the_flagged_secret_not_the_first_match() {
        let dir = tempdir().unwrap();
        let a = concat!("ghp_", "R8sT2vXq9LmN4pWz7KdJ3hYb6FcA1eUo5GtV");
        let b = concat!("ghp_", "Zq7Lm3Xv9Tn2Kp8Wd4Rb6Yc1Fa5Ho0Ej9Gsq");
        let src = format!("x = \"{a}\"; y = \"{b}\"\n");
        let p = dir.path().join("t.py");
        fs::write(&p, &src).unwrap();
        let scanner = Scanner::new().unwrap();
        let report = scanner.scan_path(&p).unwrap();
        assert_eq!(report.findings.len(), 2);
        for f in &report.findings {
            let got = scanner.resolve_finding_secret(&src, f).unwrap();
            assert!(got == a || got == b);
            assert_eq!(
                f.fingerprint,
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(got.as_bytes()))
            );
        }
        let mut stale = report.findings[0].clone();
        stale.fingerprint = "0".repeat(64);
        assert!(scanner.resolve_finding_secret(&src, &stale).is_err());
    }
}

#[cfg(test)]
mod ignore_tests {
    use super::*;

    #[test]
    fn ignore_patterns_are_component_aware_and_never_match_everything() {
        assert!(path_matches_ignore("./vendor/a.js", "vendor"));
        assert!(path_matches_ignore("src/vendor/a.js", "vendor/"));
        assert!(path_matches_ignore(
            "tests/fixtures/x.env",
            "tests/fixtures"
        ));
        assert!(!path_matches_ignore("src/my-vendor-notes.txt", "vendor"));
        for bad in ["", "/", ".", "*", "**", "  "] {
            assert!(!path_matches_ignore("src/secrets.env", bad), "{bad:?}");
            assert!(!is_safe_ignore(bad));
        }
    }

    #[test]
    fn config_file_env_overrides_the_scanned_trees_own_config() {
        let _g = crate::keystore::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let trusted = tempfile::tempdir().unwrap();
        let cfg = trusted.path().join("ci.toml");
        std::fs::write(
            &cfg,
            "[scanner]\nmax_file_size_mb = 3\nignore_paths = [\"\", \"/\", \"vendor\"]\n",
        )
        .unwrap();
        std::env::set_var("SENTRIS_CONFIG_FILE", &cfg);
        let scanner = Scanner::new();
        std::env::remove_var("SENTRIS_CONFIG_FILE");
        let c = scanner.unwrap().config.unwrap();
        assert_eq!(c.scanner.max_file_size_mb, 3);
        assert_eq!(c.scanner.ignore_paths, vec!["vendor".to_string()]);
    }

    #[test]
    fn secrets_under_dot_sentris_and_nested_dirs_are_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join("sub").join(".sentris");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(
            hidden.join("note.txt"),
            concat!("token = \"ghp_", "R8sT2vXq9LmN4pWz7KdJ3hYb6FcA1eUo5GtV\"\n"),
        )
        .unwrap();
        let report = Scanner::new().unwrap().scan_path(dir.path()).unwrap();
        assert_eq!(report.findings.len(), 1);
    }
}
