use crate::error::SentrisError;
use crate::remediator::backend::{
    mock_notice, mock_requested, record_mock, run_with_stdin, SecretStoreBackend,
};
use std::path::PathBuf;

/// Doppler backend driver supporting CLI command generation and REST API payload formatting.
#[derive(Debug, Clone)]
pub struct DopplerBackend {
    project: String,
    config: String,
    mock: bool,
    mock_ledger_path: Option<PathBuf>,
}

impl DopplerBackend {
    pub fn new() -> Self {
        let project = std::env::var("DOPPLER_PROJECT").unwrap_or_else(|_| "sentris".to_string());
        let config = std::env::var("DOPPLER_CONFIG").unwrap_or_else(|_| "prd".to_string());
        Self {
            project,
            config,
            mock: mock_requested(),
            mock_ledger_path: None,
        }
    }

    pub fn with_project<S: Into<String>>(mut self, project: S) -> Self {
        self.project = project.into();
        self
    }

    pub fn with_config<S: Into<String>>(mut self, config: S) -> Self {
        self.config = config.into();
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

    /// Formats Doppler REST API payload (POST /v1/configs/config/secrets).
    pub fn format_api_payload(&self, key: &str, secret: &str) -> serde_json::Value {
        serde_json::json!({
            "project": self.project,
            "config": self.config,
            "secrets": {
                key: secret
            }
        })
    }

    /// Formats Doppler CLI command (`doppler secrets set KEY=VALUE`).
    pub fn format_cli_command(&self, key: &str, secret: &str) -> String {
        format!(
            "doppler secrets set {}='{}' --project {} --config {}",
            key, secret, self.project, self.config
        )
    }
}

impl Default for DopplerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStoreBackend for DopplerBackend {
    fn backend_name(&self) -> &'static str {
        "Doppler"
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
                "[dry-run] Formatted Doppler secret update for '{key}' (CLI: '{}', API: {})",
                self.format_cli_command(key, shown),
                serde_json::to_string(&self.format_api_payload(key, shown))?
            ));
        }

        if self.mock {
            let path = record_mock(
                self.mock_ledger_path.as_deref(),
                "doppler_mock.json",
                key,
                self.format_api_payload(key, secret),
            )?;
            return Ok(format!(
                "{} (ledger: {})",
                mock_notice("Doppler"),
                path.display()
            ));
        }

        // Value goes over stdin, never argv
        let mut cmd = std::process::Command::new("doppler");
        cmd.args([
            "secrets",
            "set",
            key,
            "--project",
            &self.project,
            "--config",
            &self.config,
            "--silent",
        ]);

        match run_with_stdin(cmd, secret) {
            Ok(out) if out.status.success() => Ok(format!(
                "Updated Doppler secret '{key}' via doppler CLI in project '{}', config '{}'",
                self.project, self.config
            )),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(SentrisError::Scan(format!(
                    "doppler secrets set failed for '{key}': {}",
                    stderr.trim()
                )))
            }
            Err(e) => Err(SentrisError::Scan(format!(
                "Failed to spawn 'doppler' CLI for '{key}': {e}"
            ))),
        }
    }

    fn is_mock(&self) -> bool {
        self.mock
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_doppler_backend() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("doppler_ledger.json");
        let backend = DopplerBackend::new()
            .with_project("acme-app")
            .with_config("staging")
            .with_mock(true)
            .with_mock_ledger_path(&ledger_path);
        assert_eq!(backend.backend_name(), "Doppler");

        let cli_cmd = backend.format_cli_command("GITHUB_TOKEN", "ghp_mocktoken123");
        assert_eq!(
            cli_cmd,
            "doppler secrets set GITHUB_TOKEN='ghp_mocktoken123' --project acme-app --config staging"
        );

        let api_payload = backend.format_api_payload("GITHUB_TOKEN", "ghp_mocktoken123");
        assert_eq!(api_payload["project"], "acme-app");
        assert_eq!(api_payload["config"], "staging");
        assert_eq!(api_payload["secrets"]["GITHUB_TOKEN"], "ghp_mocktoken123");

        let dry_res = backend
            .inject_secret("GITHUB_TOKEN", "ghp_mocktoken123", true)
            .unwrap();
        assert!(dry_res.contains("[dry-run]"));
        assert!(dry_res.contains("doppler secrets set GITHUB_TOKEN"));

        let live_res = backend
            .inject_secret("GITHUB_TOKEN", "ghp_mocktoken123", false)
            .unwrap();
        assert!(live_res.contains("[MOCK]"));
        assert!(!dry_res.contains("ghp_mocktoken123"));
        assert!(ledger_path.exists());
    }
}
