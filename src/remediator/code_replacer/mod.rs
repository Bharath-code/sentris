#[cfg(test)]
mod accessor_tests;
#[cfg(test)]
mod replacement_tests;

use crate::error::SentrisError;
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

        // Handle dotfiles like .env, .env.local, .env.production
        if file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env") {
            return var_name.to_string();
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
            "sh" | "bash" | "zsh" => {
                format!("\"${{{var_name}}}\"")
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
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let is_shell = matches!(ext.as_str(), "sh" | "bash" | "zsh");

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
        } else if is_shell && is_inside_quotes(target_line, secret, '"') {
            // In shell scripts, if secret is already embedded inside an existing double-quoted string,
            // interpolate with ${VAR_NAME} without introducing redundant outer quotes.
            let shell_interpolated = format!("${{{var_name}}}");
            target_line.replace(secret, &shell_interpolated)
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
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        if line_number == 0 || line_number > lines.len() {
            return Err(SentrisError::Scan(format!(
                "Invalid line number {line_number} for file {file_path}"
            )));
        }

        let target_line = &lines[line_number - 1];
        let original_line = target_line.clone();

        // Check if this line begins a multi-line PEM private key block (`-----BEGIN ... KEY-----`)
        if let Some((start_ln, end_ln, _)) =
            crate::detector::DetectorEngine::extract_multiline_pem_block(&content, line_number)
        {
            let accessor = Self::get_env_accessor(file_path, var_name);
            let start_idx = start_ln - 1;
            let end_idx = end_ln - 1;
            let first = &lines[start_idx];
            let last = &lines[end_idx];

            let prefix = if let Some(begin_pos) = first.find("-----BEGIN ") {
                first[..begin_pos]
                    .trim_end_matches(['"', '\'', '`'])
                    .to_string()
            } else {
                String::new()
            };

            let suffix = if let Some(end_pos) = last.rfind("-----") {
                last[end_pos + 5..]
                    .trim_start_matches(['"', '\'', '`'])
                    .to_string()
            } else {
                String::new()
            };

            let replacement_line = format!("{prefix}{accessor}{suffix}");
            lines.splice(
                start_idx..=end_idx,
                std::iter::once(replacement_line.clone()),
            );

            let trailing_newline = if content.ends_with("\r\n") {
                "\r\n"
            } else if content.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            fs::write(path, format!("{}{}", lines.join("\n"), trailing_newline))?;
            return Ok((original_line, replacement_line));
        }

        let replacement_line =
            Self::replace_secret_in_line(file_path, target_line, secret, var_name);

        lines[line_number - 1] = replacement_line.clone();
        let trailing_newline = if content.ends_with("\r\n") {
            "\r\n"
        } else if content.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        fs::write(path, format!("{}{}", lines.join("\n"), trailing_newline))?;

        Ok((original_line, replacement_line))
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
