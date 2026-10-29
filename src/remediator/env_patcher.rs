use crate::error::SentrisError;
use std::fs;
use std::path::Path;

pub struct EnvPatcher;

impl EnvPatcher {
    /// Ensures `.env` and `.env.*` patterns exist in `.gitignore` to prevent re-leaking
    pub fn ensure_env_gitignored() -> Result<(), SentrisError> {
        Self::ensure_env_gitignored_in(Path::new("."))
    }

    pub fn ensure_env_gitignored_in(base_dir: &Path) -> Result<(), SentrisError> {
        let gitignore_path = base_dir.join(".gitignore");
        if !gitignore_path.exists() {
            fs::write(
                &gitignore_path,
                ".env\n.env.*\n!.env.example\n.sentris/\n*.log\n",
            )?;
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
        if !lines.contains(&"!.env.example") {
            additions.push("!.env.example");
        }
        if !lines.contains(&".sentris/") {
            additions.push(".sentris/");
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

    /// Current value of `var_name` in `<base_dir>/.env`, if any.
    pub fn existing_value_in(base_dir: &Path, var_name: &str) -> Option<String> {
        let prefix = format!("{var_name}=");
        fs::read_to_string(base_dir.join(".env"))
            .ok()?
            .lines()
            .find_map(|l| l.trim().strip_prefix(&prefix).map(str::to_string))
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
            crate::remediator::backend::write_private(&env_path, &format!("{new_line}\n"))?;
            let _ = Self::sync_env_example_in(base_dir, var_name);
            return Ok(());
        }

        let content = fs::read_to_string(&env_path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        // Check if variable already exists in .env
        let prefix = format!("{var_name}=");
        let mut found = false;

        for line in &mut lines {
            if let Some(current) = line.trim().strip_prefix(&prefix) {
                if current != secret_value {
                    return Err(SentrisError::Scan(format!(
                        "{var_name} already holds a different value in .env; refusing to overwrite it"
                    )));
                }
                found = true;
                break;
            }
        }

        if !found {
            lines.push(new_line);
        }

        fs::write(&env_path, lines.join("\n") + "\n")?;
        let _ = Self::sync_env_example_in(base_dir, var_name);
        Ok(())
    }

    /// Synchronizes `.env.example` with a safe empty key placeholder (`VAR_NAME=`)
    /// so teammates know a new environment variable is required without exposing the secret.
    pub fn sync_env_example_in(base_dir: &Path, var_name: &str) -> Result<(), SentrisError> {
        let example_path = base_dir.join(".env.example");
        let placeholder_line = format!("{var_name}=");

        if !example_path.exists() {
            fs::write(
                &example_path,
                format!(
                    "# Sentris Secret Contract (safe empty placeholders for team onboarding)\n{placeholder_line}\n"
                ),
            )?;
            return Ok(());
        }

        let content = fs::read_to_string(&example_path)?;
        let prefix = format!("{var_name}=");
        if content.lines().any(|l| l.trim().starts_with(&prefix)) {
            return Ok(());
        }

        let mut updated = content.trim_end().to_string();
        if !updated.is_empty() {
            updated.push('\n');
        }
        updated.push_str(&placeholder_line);
        updated.push('\n');
        fs::write(&example_path, updated)?;
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

    #[test]
    fn inject_refuses_to_overwrite_a_different_value() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".env"), "A=1\nSTRIPE_KEY=prod\n").unwrap();
        assert!(EnvPatcher::inject_env_variable_in(dir.path(), "STRIPE_KEY", "leaked").is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join(".env")).unwrap(),
            "A=1\nSTRIPE_KEY=prod\n"
        );
        EnvPatcher::inject_env_variable_in(dir.path(), "STRIPE_KEY", "prod").unwrap();
        EnvPatcher::inject_env_variable_in(dir.path(), "OTHER", "x").unwrap();
        assert!(fs::read_to_string(dir.path().join(".env"))
            .unwrap()
            .contains("OTHER=x"));
    }

    #[test]
    fn test_inject_env_syncs_env_example_without_secret() {
        let dir = tempdir().unwrap();
        EnvPatcher::inject_env_variable_in(dir.path(), "STRIPE_SECRET_KEY", "sk_live_real123")
            .unwrap();

        let env_content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env_content.contains("STRIPE_SECRET_KEY=sk_live_real123"));

        let example_content = fs::read_to_string(dir.path().join(".env.example")).unwrap();
        assert!(example_content.contains("STRIPE_SECRET_KEY="));
        assert!(!example_content.contains("sk_live_real123"));
    }
}
