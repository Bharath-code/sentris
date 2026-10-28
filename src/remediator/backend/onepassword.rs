use crate::error::SentrisError;
use crate::remediator::backend::{
    current_timestamp_secs, mock_notice, mock_requested, record_mock, SecretStoreBackend,
};
use std::path::PathBuf;

/// 1Password backend driver supporting `op://` secret reference URIs and `op` CLI mutations.
#[derive(Debug, Clone)]
pub struct OnePasswordBackend {
    vault_name: String,
    item_name: String,
    mock: bool,
    mock_ledger_path: Option<PathBuf>,
}

impl OnePasswordBackend {
    pub fn new() -> Self {
        Self {
            vault_name: std::env::var("OP_VAULT").unwrap_or_else(|_| "Engineering".to_string()),
            item_name: std::env::var("OP_ITEM").unwrap_or_else(|_| "SentrisSecrets".to_string()),
            mock: mock_requested(),
            mock_ledger_path: None,
        }
    }

    pub fn with_vault(mut self, vault: impl Into<String>) -> Self {
        self.vault_name = vault.into();
        self
    }

    pub fn with_item(mut self, item: impl Into<String>) -> Self {
        self.item_name = item.into();
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

    /// Formats the canonical 1Password `op://` secret reference URI
    pub fn format_op_reference(&self, key: &str) -> String {
        format!("op://{}/{}/{}", self.vault_name, self.item_name, key)
    }

    /// Formats the `op item edit` CLI command
    pub fn format_cli_command(&self, key: &str, secret: &str) -> String {
        format!(
            "op item edit '{}' --vault '{}' '{}[password]={}'",
            self.item_name, self.vault_name, key, secret
        )
    }
}

impl Default for OnePasswordBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStoreBackend for OnePasswordBackend {
    fn backend_name(&self) -> &'static str {
        "1Password"
    }

    fn inject_secret(
        &self,
        key: &str,
        secret: &str,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        let op_ref = self.format_op_reference(key);
        if dry_run {
            return Ok(format!(
                "[dry-run] Staged 1Password secret '{key}' -> {op_ref} (CLI: '{}')",
                self.format_cli_command(key, "<redacted>")
            ));
        }

        if self.mock {
            let path = record_mock(
                self.mock_ledger_path.as_deref(),
                "1password_mock.json",
                key,
                serde_json::json!({
                    "vault": self.vault_name,
                    "item": self.item_name,
                    "op_reference": op_ref,
                    "secret": secret,
                    "timestamp": current_timestamp_secs()
                }),
            )?;
            return Ok(format!(
                "{} (ledger: {})",
                mock_notice("1Password"),
                path.display()
            ));
        }

        if !crate::remediator::backend::argv_secrets_allowed() {
            return Err(SentrisError::Scan(format!(
                "Live {} writes pass the secret as a CLI argument, visible to other local users via ps. Refusing; set SENTRIS_ALLOW_ARGV_SECRETS=1 to accept that risk, or use the aws, doppler or vault backend.",
                self.backend_name()
            )));
        }

        let assignment = format!("{key}[password]={secret}");
        let output = std::process::Command::new("op")
            .args([
                "item",
                "edit",
                &self.item_name,
                "--vault",
                &self.vault_name,
                &assignment,
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => Ok(format!(
                "Provisioned 1Password secret reference {op_ref} via op CLI"
            )),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(SentrisError::Scan(format!(
                    "1Password 'op item edit' failed for '{key}': {}",
                    stderr.trim()
                )))
            }
            Err(e) => Err(SentrisError::Scan(format!(
                "Failed to spawn 1Password 'op' CLI for '{key}': {e}"
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
    fn test_onepassword_backend() {
        let dir = tempdir().unwrap();
        let op_ledger = dir.path().join("op_ledger.json");
        let op_backend = OnePasswordBackend::new()
            .with_vault("ProdVault")
            .with_item("BillingService")
            .with_mock(true)
            .with_mock_ledger_path(&op_ledger);
        assert_eq!(op_backend.backend_name(), "1Password");
        assert_eq!(
            op_backend.format_op_reference("STRIPE_SECRET_KEY"),
            "op://ProdVault/BillingService/STRIPE_SECRET_KEY"
        );
        let op_dry = op_backend
            .inject_secret("STRIPE_SECRET_KEY", "sk_live_op123", true)
            .unwrap();
        assert!(op_dry.contains("[dry-run]"));
        assert!(op_dry.contains("op://ProdVault/BillingService/STRIPE_SECRET_KEY"));
        op_backend
            .inject_secret("STRIPE_SECRET_KEY", "sk_live_op123", false)
            .unwrap();
        assert!(op_ledger.exists());
    }
}
