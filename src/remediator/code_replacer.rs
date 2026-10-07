use crate::error::SentrisError;
use std::fs;
use std::path::Path;

pub struct CodeReplacer;

impl CodeReplacer {
    /// Generates the idiomatic environment variable accessor for the given file extension
    pub fn get_env_accessor(file_path: &str, var_name: &str) -> String {
        let path = Path::new(file_path);
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        match ext.to_lowercase().as_str() {
            "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => {
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
            "sh" | "bash" | "zsh" => {
                format!("\"${{{var_name}}}\"")
            }
            "rb" => {
                format!("ENV['{var_name}']")
            }
            "php" => {
                format!("getenv('{var_name}')")
            }
            _ => format!("process.env.{var_name}"),
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

        let accessor = Self::get_env_accessor(file_path, var_name);

        // Intelligently replace the literal quoted string or raw match
        let single_quoted = format!("'{secret}'");
        let double_quoted = format!("\"{secret}\"");

        let replacement_line = if target_line.contains(&double_quoted) {
            target_line.replace(&double_quoted, &accessor)
        } else if target_line.contains(&single_quoted) {
            target_line.replace(&single_quoted, &accessor)
        } else {
            target_line.replace(secret, &accessor)
        };

        lines[line_number - 1] = replacement_line.clone();
        fs::write(path, lines.join("\n") + "\n")?;

        Ok((original_line, replacement_line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accessor_generation() {
        assert_eq!(
            CodeReplacer::get_env_accessor("app.ts", "STRIPE_KEY"),
            "process.env.STRIPE_KEY"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor("server.py", "STRIPE_KEY"),
            "os.environ.get(\"STRIPE_KEY\")"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor("main.rs", "STRIPE_KEY"),
            "std::env::var(\"STRIPE_KEY\").expect(\"STRIPE_KEY must be set\")"
        );
    }
}
