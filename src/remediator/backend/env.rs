use crate::error::SentrisError;
use crate::remediator::backend::SecretStoreBackend;
use crate::remediator::env_patcher::EnvPatcher;
use std::path::{Path, PathBuf};

/// Driver storing secrets in a `.env` file, ensuring `.gitignore` protection.
#[derive(Debug, Clone)]
pub struct EnvFileBackend {
    base_dir: PathBuf,
}

impl EnvFileBackend {
    pub fn new() -> Self {
        Self {
            base_dir: PathBuf::from("."),
        }
    }

    pub fn with_base_dir<P: Into<PathBuf>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }
}

impl Default for EnvFileBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStoreBackend for EnvFileBackend {
    fn backend_name(&self) -> &'static str {
        "Env"
    }

    fn inject_secret(
        &self,
        key: &str,
        secret: &str,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        if dry_run {
            return Ok(format!("[dry-run] Staged injection of {key} into .env"));
        }

        if self.base_dir == Path::new(".") {
            EnvPatcher::inject_env_variable(key, secret)?;
        } else {
            EnvPatcher::inject_env_variable_in(&self.base_dir, key, secret)?;
        }

        Ok(format!("Successfully injected {key} into .env"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_env_file_backend_dry_run_and_inject() {
        let dir = tempdir().unwrap();
        let backend = EnvFileBackend::with_base_dir(dir.path());
        assert_eq!(backend.backend_name(), "Env");

        // Dry-run should not create .env
        let dry_res = backend
            .inject_secret("STRIPE_KEY", "sk_test_dry123", true)
            .unwrap();
        assert!(dry_res.contains("[dry-run]"));
        assert!(!dir.path().join(".env").exists());

        // Live injection creates .env and updates .gitignore
        let live_res = backend
            .inject_secret("STRIPE_KEY", "sk_live_prod456", false)
            .unwrap();
        assert!(live_res.contains("Successfully injected STRIPE_KEY into .env"));

        let env_content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env_content.contains("STRIPE_KEY=sk_live_prod456"));

        let gitignore_content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(gitignore_content.contains(".env"));
    }
}
