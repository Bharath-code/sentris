use crate::error::SentrisError;
use crate::remediator::backend::{current_timestamp_secs, SecretStoreBackend};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Transaction log entry for Vault mock ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMockEntry {
    pub timestamp: u64,
    pub endpoint: String,
    pub path: String,
    pub key: String,
    pub payload: serde_json::Value,
}

/// Mock ledger storing simulated Vault KV v2 secret transactions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultMockLedger {
    pub transactions: Vec<VaultMockEntry>,
}

/// HashiCorp Vault KV v2 backend driver (POST /v1/secret/data/<path>).
#[derive(Debug, Clone)]
pub struct VaultBackend {
    vault_addr: Option<String>,
    vault_token: Option<String>,
    mount: String,
    secret_path: String,
    mock: bool,
    mock_ledger_path: Option<PathBuf>,
}

impl VaultBackend {
    pub fn new() -> Self {
        let vault_addr = std::env::var("VAULT_ADDR").ok();
        let vault_token = std::env::var("VAULT_TOKEN").ok();
        let mock = vault_addr.is_none();
        Self {
            vault_addr,
            vault_token,
            mount: "secret".to_string(),
            secret_path: "sentris".to_string(),
            mock,
            mock_ledger_path: None,
        }
    }

    pub fn with_vault_addr<S: Into<String>>(mut self, addr: S) -> Self {
        self.vault_addr = Some(addr.into());
        self
    }

    pub fn with_token<S: Into<String>>(mut self, token: S) -> Self {
        self.vault_token = Some(token.into());
        self
    }

    pub fn with_mount<S: Into<String>>(mut self, mount: S) -> Self {
        self.mount = mount.into();
        self
    }

    pub fn with_secret_path<S: Into<String>>(mut self, path: S) -> Self {
        self.secret_path = path.into();
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

    /// Formats the standard HashiCorp Vault KV v2 data payload.
    pub fn format_payload(key: &str, secret: &str) -> serde_json::Value {
        serde_json::json!({
            "data": {
                key: secret
            }
        })
    }

    /// Computes the API endpoint path: /v1/<mount>/data/<path>
    pub fn endpoint_path(&self) -> String {
        format!(
            "/v1/{}/data/{}",
            self.mount.trim_matches('/'),
            self.secret_path.trim_matches('/')
        )
    }

    fn write_to_mock_ledger(
        &self,
        key: &str,
        payload: &serde_json::Value,
    ) -> Result<PathBuf, SentrisError> {
        let ledger_path = self
            .mock_ledger_path
            .clone()
            .unwrap_or_else(|| Path::new(".sentris").join("vault_mock_ledger.json"));

        if let Some(parent) = ledger_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut ledger: VaultMockLedger = if ledger_path.exists() {
            let content = fs::read_to_string(&ledger_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            VaultMockLedger::default()
        };

        ledger.transactions.push(VaultMockEntry {
            timestamp: current_timestamp_secs(),
            endpoint: self.endpoint_path(),
            path: self.secret_path.clone(),
            key: key.to_string(),
            payload: payload.clone(),
        });

        let serialized = serde_json::to_string_pretty(&ledger)?;
        fs::write(&ledger_path, serialized)?;
        Ok(ledger_path)
    }
}

impl Default for VaultBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStoreBackend for VaultBackend {
    fn backend_name(&self) -> &'static str {
        "Vault"
    }

    fn inject_secret(
        &self,
        key: &str,
        secret: &str,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        let payload = Self::format_payload(key, secret);
        let endpoint = self.endpoint_path();

        if dry_run {
            return Ok(format!(
                "[dry-run] Formatted HashiCorp Vault v2 payload for POST {endpoint}: {}",
                serde_json::to_string(&payload)?
            ));
        }

        if self.mock || self.vault_addr.is_none() {
            let path = self.write_to_mock_ledger(key, &payload)?;
            return Ok(format!(
                "Injected secret '{key}' to local Vault mock ledger at {} (POST {endpoint})",
                path.display()
            ));
        }

        let base_addr = self
            .vault_addr
            .as_deref()
            .unwrap_or("http://127.0.0.1:8200");
        let full_url = format!("{}{}", base_addr.trim_end_matches('/'), endpoint);
        let token = self.vault_token.as_deref().unwrap_or("root");

        let response = ureq::post(&full_url)
            .set("X-Vault-Token", token)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(5))
            .send_json(&payload);

        match response {
            Ok(res) if res.status() >= 200 && res.status() < 300 => Ok(format!(
                "Successfully posted secret '{key}' to Vault at {full_url} (HTTP {})",
                res.status()
            )),
            Ok(res) => Err(SentrisError::Scan(format!(
                "Vault API error: HTTP {} from {full_url}",
                res.status()
            ))),
            Err(err) => Err(SentrisError::Scan(format!(
                "Failed to post secret to Vault at {full_url}: {err}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_backend_format_payload_and_dry_run() {
        let backend = VaultBackend::new()
            .with_mount("secret")
            .with_secret_path("sentris/app");
        assert_eq!(backend.backend_name(), "Vault");
        assert_eq!(backend.endpoint_path(), "/v1/secret/data/sentris/app");

        let payload = VaultBackend::format_payload("API_KEY", "sec_vault_123");
        assert_eq!(payload["data"]["API_KEY"], "sec_vault_123");

        let dry_res = backend
            .inject_secret("API_KEY", "sec_vault_123", true)
            .unwrap();
        assert!(dry_res.contains("[dry-run]"));
        assert!(dry_res.contains("/v1/secret/data/sentris/app"));
        assert!(dry_res.contains("sec_vault_123"));
    }

    #[test]
    fn test_vault_backend_mock_ledger() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("vault_ledger.json");
        let backend = VaultBackend::new()
            .with_mock(true)
            .with_mock_ledger_path(&ledger_path);

        let res = backend
            .inject_secret("DATABASE_URL", "postgres://mock:5432/db", false)
            .unwrap();
        assert!(res.contains("Injected secret 'DATABASE_URL' to local Vault mock ledger"));
        assert!(ledger_path.exists());

        let content = fs::read_to_string(&ledger_path).unwrap();
        let ledger: VaultMockLedger = serde_json::from_str(&content).unwrap();
        assert_eq!(ledger.transactions.len(), 1);
        assert_eq!(ledger.transactions[0].key, "DATABASE_URL");
        assert_eq!(
            ledger.transactions[0].payload["data"]["DATABASE_URL"],
            "postgres://mock:5432/db"
        );
    }

    #[test]
    fn test_vault_backend_builder_options() {
        let backend = VaultBackend::new()
            .with_vault_addr("https://vault.corp.internal:8200")
            .with_token("s.my-token-123")
            .with_mount("kv")
            .with_secret_path("services/auth");

        assert_eq!(backend.endpoint_path(), "/v1/kv/data/services/auth");
        let dry_res = backend.inject_secret("SECRET_KEY", "value", true).unwrap();
        assert!(dry_res.contains("/v1/kv/data/services/auth"));
    }
}
