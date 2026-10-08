pub mod quarantine;

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::error::SentrisError;

pub struct GitManager;

impl GitManager {
    /// Discovers the root directory of the current git repository
    pub fn find_git_root() -> Result<PathBuf, SentrisError> {
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .map_err(|e| SentrisError::Scan(format!("Failed to execute git command: {e}")))?;

        if !output.status.success() {
            return Err(SentrisError::Scan(
                "Not currently inside a git repository".to_string(),
            ));
        }

        let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(PathBuf::from(path_str))
    }

    /// Scans the entire git commit graph and diff history for leaked credentials
    pub fn scan_git_history(
        detector: &crate::detector::DetectorEngine,
    ) -> Result<(Vec<crate::model::Finding>, usize, u64), SentrisError> {
        Self::find_git_root()?;

        let mut child = match Command::new("git")
            .args(["log", "-p", "-U0", "--full-history"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return Err(SentrisError::Scan(format!("Failed to spawn git log: {e}"))),
        };

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SentrisError::Scan("Failed to capture git stdout".to_string()))?;

        let reader = BufReader::new(stdout);

        let mut findings = Vec::new();
        let mut current_commit: Option<String> = None;
        let mut current_file: Option<String> = None;
        let mut current_line: usize = 0;
        let mut commits_count: usize = 0;
        let mut total_bytes: u64 = 0;

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            if let Some(stripped) = line.strip_prefix("commit ") {
                let hash = stripped.trim().to_string();
                if current_commit.as_ref() != Some(&hash) {
                    current_commit = Some(hash);
                    commits_count += 1;
                }
                current_file = None;
                current_line = 0;
            } else if line.starts_with("diff --git ") {
                if let Some(pos) = line.rfind(" b/") {
                    current_file = Some(line[pos + 3..].trim().to_string());
                }
                current_line = 0;
            } else if line.starts_with("@@ ") {
                if let Some(plus_idx) = line.find('+') {
                    let rest = &line[plus_idx + 1..];
                    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = num_str.parse::<usize>() {
                        current_line = n;
                    }
                }
            } else if line.starts_with('+') && !line.starts_with("+++") {
                let content = &line[1..];
                total_bytes += content.len() as u64;
                let line_num = if current_line > 0 { current_line } else { 1 };
                let file_path = current_file.as_deref().unwrap_or("unknown");

                let hits =
                    detector.scan_single_line(content, file_path, line_num, current_commit.clone());
                findings.extend(hits);

                current_line += 1;
            } else if line.starts_with(' ') {
                current_line += 1;
            }
        }

        let status = child.wait()?;
        if !status.success() && commits_count == 0 {
            if let Some(mut stderr) = child.stderr.take() {
                let mut err_msg = String::new();
                let _ = stderr.read_to_string(&mut err_msg);
                if err_msg.contains("does not have any commits yet") {
                    return Ok((Vec::new(), 0, 0));
                }
            }
        }

        Ok((findings, commits_count, total_bytes))
    }

    /// Installs an idempotent, fast pre-commit hook in `.git/hooks/pre-commit`
    pub fn install_pre_commit_hook(force: bool) -> Result<String, SentrisError> {
        let root = Self::find_git_root()?;
        let hooks_dir = root.join(".git").join("hooks");

        if !hooks_dir.exists() {
            fs::create_dir_all(&hooks_dir)?;
        }

        let hook_file = hooks_dir.join("pre-commit");

        let hook_script = r#"#!/bin/sh
# --- Sentris Autonomous Pre-Commit Hook (Sub-35ms) ---
# Blocks commits containing exposed secrets or credentials.
# Bypass in emergencies using: git commit --no-verify

if command -v sentris >/dev/null 2>&1; then
    sentris scan --staged --fail-on-secret
else
    # Fallback to local cargo build if sentris is not globally in PATH
    if [ -f "./target/release/sentris" ]; then
        ./target/release/sentris scan --staged --fail-on-secret
    else
        echo "⚠️  Sentris binary not found in PATH or target/release. Skipping scan."
    fi
fi
"#;

        if hook_file.exists() && !force {
            let existing_content = fs::read_to_string(&hook_file)?;
            if existing_content.contains("sentris scan --staged") {
                return Ok(
                    "Sentris pre-commit hook is already installed and up to date.".to_string(),
                );
            }

            // Append to existing hook cleanly
            let appended = format!("{}\n\n{}", existing_content.trim(), hook_script);
            fs::write(&hook_file, appended)?;
        } else {
            fs::write(&hook_file, hook_script)?;
        }

        // Set executable permissions on Unix systems
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&hook_file)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_file, perms)?;
        }

        Ok(format!(
            "✔ Successfully installed Sentris pre-commit hook at {}",
            hook_file.display()
        ))
    }

    /// Removes the Sentris pre-commit hook
    pub fn uninstall_pre_commit_hook() -> Result<String, SentrisError> {
        let root = Self::find_git_root()?;
        let hook_file = root.join(".git").join("hooks").join("pre-commit");

        if !hook_file.exists() {
            return Ok("No pre-commit hook found to uninstall.".to_string());
        }

        let content = fs::read_to_string(&hook_file)?;
        if !content.contains("Sentris") {
            return Ok(
                "Pre-commit hook does not appear to contain Sentris configuration.".to_string(),
            );
        }

        // If hook was generated by Sentris and contains no custom commands, remove it entirely
        let non_comment_lines: Vec<&str> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();

        let is_purely_sentris = non_comment_lines.iter().all(|l| {
            l.starts_with("if")
                || l.starts_with("else")
                || l.starts_with("fi")
                || l.contains("sentris")
                || l.contains("echo")
        });

        if is_purely_sentris {
            fs::remove_file(&hook_file)?;
            Ok("✔ Successfully removed Sentris pre-commit hook.".to_string())
        } else {
            // Strip sentris lines
            let filtered: Vec<&str> = content
                .lines()
                .filter(|l| !l.contains("sentris") && !l.contains("Sentris"))
                .collect();
            fs::write(&hook_file, filtered.join("\n"))?;
            Ok("✔ Cleaned Sentris invocation from existing pre-commit hook.".to_string())
        }
    }

    /// Fetches all staged file paths and their staged contents from the git index
    pub fn get_staged_files() -> Result<Vec<(String, String)>, SentrisError> {
        // Get list of staged files
        let output = Command::new("git")
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
            .output()
            .map_err(|e| SentrisError::Scan(format!("Failed to execute git diff: {e}")))?;

        if !output.status.success() {
            return Err(SentrisError::Scan("Git index diff failed".to_string()));
        }

        let file_list = String::from_utf8_lossy(&output.stdout);
        let mut staged_files = Vec::new();

        for file_path in file_list.lines().map(str::trim).filter(|s| !s.is_empty()) {
            // Retrieve staged content from git index: git show :<file_path>
            let show_arg = format!(":{file_path}");
            let show_output = Command::new("git").args(["show", &show_arg]).output();

            if let Ok(out) = show_output {
                if out.status.success() {
                    let content = String::from_utf8_lossy(&out.stdout).to_string();
                    staged_files.push((file_path.to_string(), content));
                }
            }
        }

        Ok(staged_files)
    }

    /// Returns current HEAD git commit hash if available
    pub fn get_head_commit() -> Result<Option<String>, SentrisError> {
        let output = Command::new("git").args(["rev-parse", "HEAD"]).output();

        match output {
            Ok(out) if out.status.success() => {
                let commit = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if commit.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(commit))
                }
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_git_root() {
        // Our workspace is initialized with git
        let root = GitManager::find_git_root();
        assert!(root.is_ok());
        let path = root.unwrap();
        assert!(path.join(".git").exists());
    }
}
