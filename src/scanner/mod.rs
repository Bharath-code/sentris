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

pub struct Scanner {
    detector: DetectorEngine,
    config: Option<Config>,
}

impl Scanner {
    pub fn new() -> Result<Self, SentrisError> {
        let config = Config::load_from_dir(Path::new("."));
        let detector = DetectorEngine::with_config(config.as_ref())?;
        Ok(Self { detector, config })
    }

    /// Extracts the raw secret token from a line using the compiled rule's regex capture
    pub fn extract_raw_secret(&self, line: &str, rule_id: &str) -> Option<String> {
        self.detector.extract_raw_secret(line, rule_id)
    }

    /// Scans a target path recursively using Rayon parallelism and the `ignore` crate.
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

                // Skip .git and .sentris internal state directory trees immediately
                if entry.path().components().any(|c| {
                    let s = c.as_os_str();
                    s == ".git" || s == ".sentris" || s == ".sentris-baseline.json"
                }) {
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
                        .any(|p| path_str.contains(p))
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
}
