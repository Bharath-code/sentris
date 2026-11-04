use crate::error::SentrisError;
use crate::remediator::backend::{
    mock_notice, mock_requested, read_mock_entry, record_mock, SecretStoreBackend, SecretTempFile,
};
use std::path::PathBuf;

/// Infisical Cloud / Self-Hosted Secret Manager backend driver.
#[derive(Debug, Clone)]
pub struct InfisicalBackend {
    env_slug: String,
    secret_path: String,
    mock: bool,
    mock_ledger_path: Option<PathBuf>,
}

impl InfisicalBackend {
    pub fn new() -> Self {
        Self {
            env_slug: std::env::var("INFISICAL_ENV").unwrap_or_else(|_| "dev".to_string()),
            secret_path: std::env::var("INFISICAL_PATH").unwrap_or_else(|_| "/".to_string()),
            mock: mock_requested(),
            mock_ledger_path: None,
        }
    }

    pub fn with_env(mut self, env_slug: impl Into<String>) -> Self {
        self.env_slug = env_slug.into();
        self
    }

    pub fn with_path(mut self, secret_path: impl Into<String>) -> Self {
        self.secret_path = secret_path.into();
        self
    }

    pub fn with_mock(mut self, mock: bool) -> Self {
        self.mock = mock;
        self
    }

    pub fn with_mock_ledger_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.mock_ledger_path = Some(path.into());
        self
    }

    pub fn format_cli_command(&self, key: &str, secret: &str) -> String {
        format!(
            "infisical secrets set {}='{}' --env={} --path={}",
            key, secret, self.env_slug, self.secret_path
        )
    }

    pub fn format_api_payload(&self, key: &str, secret: &str) -> serde_json::Value {
        serde_json::json!({
            "environment": self.env_slug,
            "secretPath": self.secret_path,
            "secretKey": key,
            "secretValue": secret
        })
    }
}

impl Default for InfisicalBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStoreBackend for InfisicalBackend {
    fn backend_name(&self) -> &'static str {
        "Infisical"
    }

    fn inject_secret(
        &self,
        key: &str,
        secret: &str,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        if dry_run {
            let shown = "<redacted>";
            return Ok(format!(
                "[dry-run] Staged Infisical secret '{key}' (CLI: '{}', API: {})",
                self.format_cli_command(key, shown),
                serde_json::to_string(&self.format_api_payload(key, shown))?
            ));
        }

        if self.mock {
            let path = record_mock(
                self.mock_ledger_path.as_deref(),
                "infisical_mock.json",
                key,
                self.format_api_payload(key, secret),
            )?;
            return Ok(format!(
                "{} (ledger: {})",
                mock_notice("Infisical"),
                path.display()
            ));
        }

        // Stage a 0600 env file so the secret value never appears in argv (`ps`)
        let secret_file = SecretTempFile::create(&format!("{key}={secret}\n")).map_err(|e| {
            SentrisError::Scan(format!("Cannot stage secret for infisical CLI: {e}"))
        })?;
        let file_arg = format!("--file={}", secret_file.path().display());
        let env_arg = format!("--env={}", self.env_slug);
        let path_arg = format!("--path={}", self.secret_path);
        let output = std::process::Command::new("infisical")
            .args(["secrets", "set", &file_arg, &env_arg, &path_arg])
            .output();

        match output {
            Ok(out) if out.status.success() => Ok(format!(
                "Updated Infisical secret '{key}' via infisical CLI in env '{}'",
                self.env_slug
            )),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(SentrisError::Scan(format!(
                    "infisical secrets set failed for '{key}': {}",
                    stderr.trim()
                )))
            }
            Err(e) => Err(SentrisError::Scan(format!(
                "Failed to spawn 'infisical' CLI for '{key}': {e}"
            ))),
        }
    }

    fn is_mock(&self) -> bool {
        self.mock
    }

    fn fetch_secret(&self, key: &str) -> Result<String, SentrisError> {
        if self.mock {
            let entry =
                read_mock_entry(self.mock_ledger_path.as_deref(), "infisical_mock.json", key)?;
            return entry["secretValue"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    SentrisError::Scan(format!(
                        "Secret '{key}' missing from Infisical mock ledger entry"
                    ))
                });
        }

        let env_arg = format!("--env={}", self.env_slug);
        let path_arg = format!("--path={}", self.secret_path);
        let output = std::process::Command::new("infisical")
            .args(["secrets", "get", key, "--plain", &env_arg, &path_arg])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let val = String::from_utf8_lossy(&out.stdout);
                Ok(val.trim_end_matches(&['\r', '\n'][..]).to_string())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(SentrisError::Scan(format!(
                    "infisical secrets get failed for '{key}': {}",
                    stderr.trim()
                )))
            }
            Err(e) => Err(SentrisError::Scan(format!(
                "Failed to spawn 'infisical' CLI to fetch '{key}': {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_infisical_backend() {
        let dir = tempdir().unwrap();
        let inf_ledger = dir.path().join("infisical_ledger.json");
        let inf_backend = InfisicalBackend::new()
            .with_env("prod")
            .with_path("/payments")
            .with_mock(true)
            .with_mock_ledger_path(&inf_ledger);
        assert_eq!(inf_backend.backend_name(), "Infisical");
        let inf_dry = inf_backend
            .inject_secret("STRIPE_SECRET_KEY", "sk_live_inf456", true)
            .unwrap();
        assert!(inf_dry.contains("[dry-run]"));
        assert!(inf_dry.contains("infisical secrets set STRIPE_SECRET_KEY"));
        inf_backend
            .inject_secret("STRIPE_SECRET_KEY", "sk_live_inf456", false)
            .unwrap();
        assert!(inf_ledger.exists());
    }
}
