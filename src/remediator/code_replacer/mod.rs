#[cfg(test)]
mod accessor_tests;
#[cfg(test)]
mod replacement_tests;

use crate::error::SentrisError;
use crate::fsutil::{split_eol, write_atomic};
use std::fs;
use std::path::Path;

pub struct CodeReplacer;

impl CodeReplacer {
    /// Generates the idiomatic environment variable accessor for the given file extension.
    pub fn get_env_accessor(file_path: &str, var_name: &str) -> String {
        let path = Path::new(file_path);
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        let norm_path = file_path.replace('\\', "/").to_ascii_lowercase();

        // Handle dotfiles like .env, .env.local, .env.production
        if file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env") {
            return var_name.to_string();
        }

        // Handle AI agent session transcripts and shell histories (in-place scrubbing)
        if ext == "jsonl" || matches!(file_name.as_str(), ".zsh_history" | ".bash_history") {
            return format!("[REDACTED_BY_SENTRIS:{var_name}]");
        }

        // Handle GitHub Actions workflows (.github/workflows/*.yml)
        if norm_path.contains(".github/workflows/") && matches!(ext.as_str(), "yml" | "yaml") {
            return format!("${{{{ secrets.{var_name} }}}}");
        }

        // Handle Dockerfiles and Containerfiles
        if file_name == "dockerfile"
            || file_name.starts_with("dockerfile.")
            || file_name == "containerfile"
            || ext == "dockerfile"
        {
            return format!("\"${{{var_name}}}\"");
        }

        // Handle Docker Compose and Kubernetes manifest files
        if (file_name.starts_with("docker-compose")
            || file_name.starts_with("compose.")
            || file_name.ends_with(".k8s.yml")
            || file_name.ends_with(".k8s.yaml"))
            && matches!(ext.as_str(), "yml" | "yaml")
        {
            return format!("\"${{{var_name}}}\"");
        }

        match ext.as_str() {
            "ts" | "js" | "tsx" | "jsx" | "mjs" | "cjs" => {
                format!("process.env.{var_name}")
            }
            "py" => {
                format!("os.environ.get(\"{var_name}\")")
            }
            "rs" => {
                format!("std::env::var(\"{var_name}\").expect(\"{var_name} must be set\")")
            }
            "go" => {
                format!("os.Getenv(\"{var_name}\")")
            }
            "java" => {
                format!("System.getenv(\"{var_name}\")")
            }
            "cs" => {
                format!("Environment.GetEnvironmentVariable(\"{var_name}\")")
            }
            "rb" => {
                format!("ENV[\"{var_name}\"]")
            }
            "php" => {
                format!("getenv(\"{var_name}\")")
            }
            "sh" | "bash" | "zsh" | "json" | "jsonc" => {
                format!("\"${{{var_name}}}\"")
            }
            "tf" | "tfvars" => {
                format!("var.{}", var_name.to_ascii_lowercase())
            }
            "env" | "yml" | "yaml" | "toml" | "ini" => var_name.to_string(),
            _ => format!("process.env.{var_name}"),
        }
    }

    /// Replaces the hardcoded secret in a line of code with the appropriate env var expression.
    /// Handles string quoting and language-specific interpolation/substitution without leftover quotes.
    pub fn replace_secret_in_line(
        file_path: &str,
        target_line: &str,
        secret: &str,
        var_name: &str,
    ) -> String {
        let accessor = Self::get_env_accessor(file_path, var_name);
        let path = Path::new(file_path);
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // In AI transcripts (.jsonl) and shell history files, scrub the raw secret token directly
        // so surrounding JSON string quotes and escaping remain 100% intact.
        if ext == "jsonl" || matches!(file_name.as_str(), ".zsh_history" | ".bash_history") {
            return target_line.replace(secret, &accessor);
        }

        let uses_dollar_brace_quotes = accessor == format!("\"${{{var_name}}}\"");

        // Quoted patterns in descending order of specificity
        let r_hash_double = format!("r#\"{secret}\"#");
        let r_hash_single = format!("r#'{secret}'#");
        let r_double = format!("r\"{secret}\"");
        let r_single = format!("r'{secret}'");
        let b_double = format!("b\"{secret}\"");
        let b_single = format!("b'{secret}'");
        let f_double = format!("f\"{secret}\"");
        let f_single = format!("f'{secret}'");
        let triple_double = format!("\"\"\"{secret}\"\"\"");
        let triple_single = format!("'''{secret}'''");
        let double_quoted = format!("\"{secret}\"");
        let single_quoted = format!("'{secret}'");
        let backtick_quoted = format!("`{secret}`");

        if target_line.contains(&r_hash_double) {
            target_line.replace(&r_hash_double, &accessor)
        } else if target_line.contains(&r_hash_single) {
            target_line.replace(&r_hash_single, &accessor)
        } else if target_line.contains(&r_double) {
            target_line.replace(&r_double, &accessor)
        } else if target_line.contains(&r_single) {
            target_line.replace(&r_single, &accessor)
        } else if target_line.contains(&b_double) {
            target_line.replace(&b_double, &accessor)
        } else if target_line.contains(&b_single) {
            target_line.replace(&b_single, &accessor)
        } else if target_line.contains(&f_double) {
            target_line.replace(&f_double, &accessor)
        } else if target_line.contains(&f_single) {
            target_line.replace(&f_single, &accessor)
        } else if target_line.contains(&triple_double) {
            target_line.replace(&triple_double, &accessor)
        } else if target_line.contains(&triple_single) {
            target_line.replace(&triple_single, &accessor)
        } else if target_line.contains(&double_quoted) {
            target_line.replace(&double_quoted, &accessor)
        } else if target_line.contains(&single_quoted) {
            target_line.replace(&single_quoted, &accessor)
        } else if target_line.contains(&backtick_quoted) {
            target_line.replace(&backtick_quoted, &accessor)
        } else if uses_dollar_brace_quotes && is_inside_quotes(target_line, secret, '"') {
            // In shell scripts, Dockerfiles, Compose/K8s manifests, and JSON configs, if secret is
            // embedded inside an existing double-quoted string, interpolate with ${VAR_NAME} without outer quotes.
            let interpolated = format!("${{{var_name}}}");
            target_line.replace(secret, &interpolated)
        } else {
            target_line.replace(secret, &accessor)
        }
    }

    /// Replaces the hardcoded secret in the target file at line_number with the env var expression
    pub fn replace_secret(
        file_path: &str,
        line_number: usize,
        secret: &str,
        var_name: &str,
    ) -> Result<(String, String), SentrisError> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Err(SentrisError::Scan(format!(
                "Target file does not exist: {file_path}"
            )));
        }

        let content = fs::read_to_string(path)?;
        // Keep each line's own terminator so CRLF files stay CRLF
        let segs: Vec<&str> = content.split_inclusive('\n').collect();

        if line_number == 0 || line_number > segs.len() {
            return Err(SentrisError::Scan(format!(
                "Invalid line number {line_number} for file {file_path}"
            )));
        }

        let idx = line_number - 1;
        let (target_line, eol) = split_eol(segs[idx]);

        // Multi-line PEM private key block (`-----BEGIN ... KEY-----`) collapses to a single accessor line
        if let Some((start_ln, end_ln, _)) =
            crate::detector::DetectorEngine::extract_multiline_pem_block(&content, line_number)
        {
            let accessor = Self::get_env_accessor(file_path, var_name);
            let (start, end) = (start_ln - 1, end_ln - 1);
            let (first, _) = split_eol(segs[start]);
            let (last, last_eol) = split_eol(segs[end]);

            let prefix = match first.find("-----BEGIN ") {
                Some(p) => first[..p].trim_end_matches(['"', '\'', '`']),
                None => "",
            };
            let suffix = match last.rfind("-----") {
                Some(p) => last[p + 5..].trim_start_matches(['"', '\'', '`']),
                None => "",
            };
            let replacement_line = format!("{prefix}{accessor}{suffix}");
            let original_block = split_eol(&segs[start..=end].concat()).0.to_string();

            let updated = format!(
                "{}{replacement_line}{last_eol}{}",
                segs[..start].concat(),
                segs[end + 1..].concat()
            );
            write_atomic(path, &updated)?;
            return Ok((original_block, replacement_line));
        }

        let replacement_line =
            Self::replace_secret_in_line(file_path, target_line, secret, var_name);
        if replacement_line == target_line {
            return Err(SentrisError::Scan(format!(
                "Secret not found on line {line_number} of {file_path}; file left unchanged"
            )));
        }

        let updated = format!(
            "{}{replacement_line}{eol}{}",
            segs[..idx].concat(),
            segs[idx + 1..].concat()
        );
        write_atomic(path, &updated)?;

        Ok((target_line.to_string(), replacement_line))
    }
}

/// Helper to determine if a substring is inside an unescaped pair of quotes in a line.
fn is_inside_quotes(line: &str, substring: &str, quote: char) -> bool {
    if let Some(idx) = line.find(substring) {
        let before = &line[..idx];
        let after = &line[idx + substring.len()..];

        let count_unescaped = |s: &str| -> usize {
            let mut count = 0;
            let mut prev_backslash = false;
            for c in s.chars() {
                if c == '\\' {
                    prev_backslash = !prev_backslash;
                } else {
                    if c == quote && !prev_backslash {
                        count += 1;
                    }
                    prev_backslash = false;
                }
            }
            count
        };

        let count_before = count_unescaped(before);
        let count_after = count_unescaped(after);
        count_before % 2 == 1 && count_after % 2 == 1
    } else {
        false
    }
}
