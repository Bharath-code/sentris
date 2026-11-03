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

/// Zero-allocation component-aware match against an already trimmed pattern (`pat`) and normalized path (`norm`).
fn matches_trimmed_component(norm: &str, pat: &str) -> bool {
    if norm == pat {
        return true;
    }
    if norm
        .strip_prefix(pat)
        .is_some_and(|rest| rest.starts_with('/'))
    {
        return true;
    }
    if norm
        .strip_suffix(pat)
        .is_some_and(|pre| pre.ends_with('/'))
    {
        return true;
    }
    let bytes = norm.as_bytes();
    let mut start = 0;
    while let Some(rel) = norm[start..].find(pat) {
        let pos = start + rel;
        let end = pos + pat.len();
        if pos > 0 && bytes[pos - 1] == b'/' && bytes.get(end) == Some(&b'/') {
            return true;
        }
        start = pos + 1;
    }
    false
}

/// Component-aware match: `vendor` hides `a/vendor/x` but not `my-vendor-notes.txt`.
#[cfg(test)]
fn path_matches_ignore(path: &str, pattern: &str) -> bool {
    let pat = pattern.trim().trim_matches('/');
    if pat.is_empty() || matches!(pat, "." | ".." | "*" | "**") {
        return false;
    }
    let norm: std::borrow::Cow<'_, str> = if path.contains('\\') {
        std::borrow::Cow::Owned(path.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(path)
    };
    let norm = norm.trim_start_matches("./");
    matches_trimmed_component(norm, pat)
}

pub struct Scanner {
    detector: DetectorEngine,
    config: Option<Config>,
    /// Secrets of findings imported from another scanner's report, indexed in a flat array (see `crate::import`).
    imported: crate::import::ImportedSecrets,
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
        Ok(Self {
            detector,
            config,
            imported: Default::default(),
        })
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
        Ok(Self {
            detector,
            config,
            imported: Default::default(),
        })
    }

    /// Registers the secrets of findings imported from a Betterleaks/Gitleaks report so they can be probed and remediated.
    pub fn use_imported_secrets(&mut self, secrets: impl Into<crate::import::ImportedSecrets>) {
        self.imported = secrets.into();
    }

    /// Extracts the raw secret token from a line using the compiled rule's regex capture
    /// Resolves the secret a finding points at, shared by CLI and MCP remediation.
    /// PEM blocks come from the file; anything else must hash to the finding's fingerprint.
    pub fn resolve_finding_secret(
        &self,
        content: &str,
        finding: &Finding,
    ) -> Result<String, SentrisError> {
        if let Some(secret) = self.imported.get(&finding.fingerprint) {
            return if crate::import::secret_at_line(content, finding.line_number, secret) {
                Ok(secret.to_string())
            } else {
                Err(SentrisError::Scan(format!(
                    "Imported secret is no longer on line {} of {} (file changed since the scan?); refusing to guess",
                    finding.line_number, finding.file_path
                )))
            };
        }
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

        let ignore_patterns: Vec<&str> = self
            .config
            .as_ref()
            .map(|cfg| {
                cfg.scanner
                    .ignore_paths
                    .iter()
                    .map(|p| p.trim().trim_matches('/'))
                    .filter(|&pat| !(pat.is_empty() || matches!(pat, "." | ".." | "*" | "**")))
                    .collect()
            })
            .unwrap_or_default();

        let aggregated_findings: Mutex<Vec<Finding>> = Mutex::new(Vec::new());

        struct WorkerFlush<'a> {
            findings: Vec<Finding>,
            scanned: usize,
            ignored: usize,
            bytes: u64,
            aggregated_findings: &'a Mutex<Vec<Finding>>,
            total_files_scanned: &'a AtomicUsize,
            files_ignored: &'a AtomicUsize,
            total_bytes_scanned: &'a AtomicU64,
        }

        impl Drop for WorkerFlush<'_> {
            fn drop(&mut self) {
                if self.scanned != 0 {
                    self.total_files_scanned
                        .fetch_add(self.scanned, Ordering::Relaxed);
                }
                if self.ignored != 0 {
                    self.files_ignored
                        .fetch_add(self.ignored, Ordering::Relaxed);
                }
                if self.bytes != 0 {
                    self.total_bytes_scanned
                        .fetch_add(self.bytes, Ordering::Relaxed);
                }
                if !self.findings.is_empty() {
                    if let Ok(mut guard) = self.aggregated_findings.lock() {
                        guard.append(&mut self.findings);
                    }
                }
            }
        }

        // Lock-free work-stealing parallel directory traversal & file scanning
        builder.build_parallel().run(|| {
            let detector = &self.detector;
            let ignore_patterns = &ignore_patterns;
            let root = path;
            let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
            let mut worker = WorkerFlush {
                findings: Vec::new(),
                scanned: 0,
                ignored: 0,
                bytes: 0,
                aggregated_findings: &aggregated_findings,
                total_files_scanned: &total_files_scanned,
                files_ignored: &files_ignored,
                total_bytes_scanned: &total_bytes_scanned,
            };

            Box::new(move |result| {
                let entry = match result {
                    Ok(e) => e,
                    Err(_) => {
                        worker.ignored += 1;
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
                    worker.ignored += 1;
                    return WalkState::Skip;
                }

                if !file_type.is_file() {
                    return WalkState::Continue;
                }

                let file_path = entry.path();
                let path_str = file_path.to_string_lossy();

                // Check custom ignore_paths from config using pre-trimmed patterns without heap allocations
                if !ignore_patterns.is_empty() {
                    let norm: std::borrow::Cow<'_, str> = if path_str.contains('\\') {
                        std::borrow::Cow::Owned(path_str.replace('\\', "/"))
                    } else {
                        std::borrow::Cow::Borrowed(&path_str)
                    };
                    let norm = norm.trim_start_matches("./");
                    if ignore_patterns
                        .iter()
                        .any(|&pat| matches_trimmed_component(norm, pat))
                    {
                        worker.ignored += 1;
                        return WalkState::Continue;
                    }
                }

                let mut file = match File::open(file_path) {
                    Ok(f) => f,
                    Err(_) => return WalkState::Continue,
                };

                // Skip oversized files exceeding max_file_bytes to protect memory and CPU
                let mut file_len = 0usize;
                if let Ok(meta) = file.metadata() {
                    if meta.len() > max_file_bytes {
                        worker.ignored += 1;
                        return WalkState::Continue;
                    }
                    file_len = meta.len() as usize;
                }

                buffer.clear();
                buffer.reserve(file_len);
                if file.read_to_end(&mut buffer).is_err() {
                    return WalkState::Continue;
                }

                // Check for null bytes in initial 512 bytes (binary file detection)
                let check_len = buffer.len().min(512);
                if buffer[..check_len].contains(&0) {
                    worker.ignored += 1;
                    return WalkState::Continue;
                }

                let content = match std::str::from_utf8(&buffer) {
                    Ok(s) => s,
                    Err(_) => return WalkState::Continue,
                };

                worker.scanned += 1;
                worker.bytes += buffer.len() as u64;

                let file_findings = detector.scan_text(content, &path_str);
                if !file_findings.is_empty() {
                    worker.findings.extend(file_findings);
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
            timestamp: now_string(),
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
            timestamp: now_string(),
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
            timestamp: now_string(),
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
            timestamp: now_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats,
            findings,
            exposures: Default::default(),
        })
    }

    /// Returns well-known workstation AI coding agent and developer credential config paths under `home` and cwd.
    pub fn workstation_candidate_paths(home: &Path) -> Vec<std::path::PathBuf> {
        vec![
            std::path::PathBuf::from(".mcp.json"),
            std::path::PathBuf::from(".cursor/mcp.json"),
            home.join(".cursor/mcp.json"),
            home.join(".claude.json"),
            home.join(".claude/settings.json"),
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
            home.join(".config/claude/claude_desktop_config.json"),
            home.join(".codeium/windsurf/mcp_config.json"),
            home.join(".npmrc"),
            home.join(".pypirc"),
            home.join(".netrc"),
            home.join(".git-credentials"),
        ]
    }

    /// Audits well-known local AI agent (MCP, Claude Code, Cursor, Windsurf) and package manager config files for plaintext secrets.
    pub fn scan_workstation(&self) -> Result<ScanReport, SentrisError> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(std::path::PathBuf::from)
            .ok_or_else(|| {
                SentrisError::Scan(
                    "Cannot determine user home directory ($HOME or %USERPROFILE% not set)".into(),
                )
            })?;
        self.scan_workstation_in(&home)
    }

    /// Audits workstation candidate files resolved relative to `home`.
    pub fn scan_workstation_in(&self, home: &Path) -> Result<ScanReport, SentrisError> {
        let start_time = Instant::now();
        let candidates = Self::workstation_candidate_paths(home);
        let mut findings = Vec::new();
        let mut files_scanned = 0usize;
        let mut files_ignored = 0usize;
        let mut bytes_scanned = 0u64;

        for path in candidates {
            if !path.is_file() {
                continue;
            }
            if crate::fsutil::reject_symlinks(&path).is_err() {
                files_ignored += 1;
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    files_scanned += 1;
                    bytes_scanned += content.len() as u64;
                    let path_str = path.to_string_lossy().to_string();
                    findings.extend(self.detector.scan_text(&content, &path_str));
                }
                Err(_) => {
                    files_ignored += 1;
                }
            }
        }

        let stats = ScanStats {
            files_scanned,
            files_ignored,
            bytes_scanned,
            findings_count: findings.len(),
            duration_ms: start_time.elapsed().as_millis(),
        };

        Ok(ScanReport {
            timestamp: now_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats,
            findings,
            exposures: Default::default(),
        })
    }
}

pub(crate) fn now_string() -> String {
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

    #[test]
    fn workstation_scan_detects_secret_in_cursor_mcp_config() {
        let dir = tempdir().unwrap();
        let cursor_dir = dir.path().join(".cursor");
        fs::create_dir_all(&cursor_dir).unwrap();
        let mcp_json = cursor_dir.join("mcp.json");
        let tok = concat!("ghp_", "R8sT2vXq9LmN4pWz7KdJ3hYb6FcA1eUo5GtV");
        fs::write(
            &mcp_json,
            format!(r#"{{"mcpServers":{{"github":{{"env":{{"GITHUB_TOKEN":"{tok}"}}}}}}}}"#),
        )
        .unwrap();
        let scanner = Scanner::new().unwrap();
        let report = scanner.scan_workstation_in(dir.path()).unwrap();
        assert!(report.stats.files_scanned >= 1);
        assert!(report.findings.iter().any(|f| f.rule_id == "github-pat"));
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
