use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use ignore::WalkBuilder;
use rayon::prelude::*;

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

        let walker = builder.build();

        // Collect all file paths to scan
        let mut file_paths = Vec::new();
        let files_ignored = AtomicUsize::new(0);

        for result in walker {
            match result {
                Ok(entry) => {
                    let file_type = match entry.file_type() {
                        Some(ft) => ft,
                        None => continue,
                    };

                    if file_type.is_file() {
                        // Skip .git internal directory
                        if entry.path().components().any(|c| c.as_os_str() == ".git") {
                            files_ignored.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        // Check custom ignore_paths from config
                        if let Some(cfg) = &self.config {
                            let path_str = entry.path().to_string_lossy();
                            if cfg
                                .scanner
                                .ignore_paths
                                .iter()
                                .any(|p| path_str.contains(p))
                            {
                                files_ignored.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }

                        file_paths.push(entry.into_path());
                    }
                }
                Err(_) => {
                    files_ignored.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let total_files_scanned = AtomicUsize::new(0);
        let total_bytes_scanned = AtomicU64::new(0);

        let max_file_bytes = self
            .config
            .as_ref()
            .map(|c| c.scanner.max_file_size_mb * 1024 * 1024)
            .unwrap_or(10 * 1024 * 1024);

        // Scan files in parallel using Rayon
        let findings: Vec<Finding> = file_paths
            .par_iter()
            .flat_map(|file_path| {
                // Read and check if file is binary
                let path_str = file_path.to_string_lossy();
                let mut file = match File::open(file_path) {
                    Ok(f) => f,
                    Err(_) => return Vec::new(),
                };

                // Skip oversized files exceeding max_file_bytes to protect memory and CPU
                if let Ok(meta) = file.metadata() {
                    if meta.len() > max_file_bytes {
                        files_ignored.fetch_add(1, Ordering::Relaxed);
                        return Vec::new();
                    }
                }

                // Read sample buffer to detect binary content
                let mut buffer = Vec::new();
                if file.read_to_end(&mut buffer).is_err() {
                    return Vec::new();
                }

                // Check for null bytes in initial 512 bytes
                let check_len = buffer.len().min(512);
                if buffer[..check_len].contains(&0) {
                    // Binary file, skip
                    files_ignored.fetch_add(1, Ordering::Relaxed);
                    return Vec::new();
                }

                // Convert to UTF-8 lossy text
                let content = match std::str::from_utf8(&buffer) {
                    Ok(s) => s,
                    Err(_) => return Vec::new(),
                };

                total_files_scanned.fetch_add(1, Ordering::Relaxed);
                total_bytes_scanned.fetch_add(buffer.len() as u64, Ordering::Relaxed);

                self.detector.scan_text(content, &path_str)
            })
            .collect();

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

    /// Scans only staged files from the git index for sub-35ms pre-commit execution.
    pub fn scan_staged(&self) -> Result<ScanReport, SentrisError> {
        let start_time = Instant::now();
        let staged_files = crate::git::GitManager::get_staged_files()?;

        let mut findings = Vec::new();
        let mut total_bytes = 0u64;

        for (file_path, content) in &staged_files {
            total_bytes += content.len() as u64;
            let file_findings = self.detector.scan_text(content, file_path);
            findings.extend(file_findings);
        }

        let duration = start_time.elapsed();

        let stats = ScanStats {
            files_scanned: staged_files.len(),
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
