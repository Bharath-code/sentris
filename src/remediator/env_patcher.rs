use crate::error::SentrisError;
use std::fs;
use std::path::Path;

pub struct EnvPatcher;

impl EnvPatcher {
    /// Ensures `.env` and `.env.*` patterns exist in `.gitignore` to prevent re-leaking
    #[allow(dead_code)]
    pub fn ensure_env_gitignored() -> Result<(), SentrisError> {
        Self::ensure_env_gitignored_in(Path::new("."))
    }

    pub fn ensure_env_gitignored_in(base_dir: &Path) -> Result<(), SentrisError> {
        let gitignore_path = base_dir.join(".gitignore");
        if !gitignore_path.exists() {
            fs::write(&gitignore_path, ".env\n.env.*\n*.log\n")?;
            return Ok(());
        }

        let content = fs::read_to_string(&gitignore_path)?;
        let lines: Vec<&str> = content.lines().map(str::trim).collect();

        let mut additions = Vec::new();
        if !lines.contains(&".env") {
            additions.push(".env");
        }
        if !lines.contains(&".env.*") {
            additions.push(".env.*");
        }

        if !additions.is_empty() {
            let mut updated = content.trim_end().to_string();
            updated.push('\n');
            for add in additions {
                updated.push_str(add);
                updated.push('\n');
            }
            fs::write(&gitignore_path, updated)?;
        }

        Ok(())
    }

    /// Injects or updates an environment variable inside `.env`
    pub fn inject_env_variable(var_name: &str, secret_value: &str) -> Result<(), SentrisError> {
        Self::inject_env_variable_in(Path::new("."), var_name, secret_value)
    }

    pub fn inject_env_variable_in(
        base_dir: &Path,
        var_name: &str,
        secret_value: &str,
    ) -> Result<(), SentrisError> {
        Self::ensure_env_gitignored_in(base_dir)?;

        let env_path = base_dir.join(".env");
        let new_line = format!("{var_name}={secret_value}");

        if !env_path.exists() {
            fs::write(&env_path, format!("{new_line}\n"))?;
            return Ok(());
        }

        let content = fs::read_to_string(&env_path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        // Check if variable already exists in .env
        let prefix = format!("{var_name}=");
        let mut found = false;

        for line in &mut lines {
            if line.trim().starts_with(&prefix) {
                *line = new_line.clone();
                found = true;
                break;
            }
        }

        if !found {
            lines.push(new_line);
        }

        fs::write(&env_path, lines.join("\n") + "\n")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ensure_env_gitignored() {
        let dir = tempdir().unwrap();
        EnvPatcher::ensure_env_gitignored_in(dir.path()).unwrap();
        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".env"));
    }
}
