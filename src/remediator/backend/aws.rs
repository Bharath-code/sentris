use crate::error::SentrisError;
use crate::remediator::backend::{
    mock_notice, mock_requested, record_mock, SecretStoreBackend, SecretTempFile,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operation mode for AWS Secrets Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AwsActionMode {
    PutSecretValue,
    CreateSecret,
}

impl AwsActionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PutSecretValue => "PutSecretValue",
            Self::CreateSecret => "CreateSecret",
        }
    }
}

/// AWS Secrets Manager backend driver supporting PutSecretValue and CreateSecret.
#[derive(Debug, Clone)]
pub struct AwsSecretsManagerBackend {
    region: String,
    action: AwsActionMode,
    kms_key_id: Option<String>,
    mock: bool,
    mock_ledger_path: Option<PathBuf>,
}

impl AwsSecretsManagerBackend {
    pub fn new() -> Self {
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_string());
        Self {
            region,
            action: AwsActionMode::PutSecretValue,
            kms_key_id: None,
            mock: mock_requested(),
            mock_ledger_path: None,
        }
    }

    pub fn with_region<S: Into<String>>(mut self, region: S) -> Self {
        self.region = region.into();
        self
    }

    pub fn with_action(mut self, action: AwsActionMode) -> Self {
        self.action = action;
        self
    }

    pub fn with_kms_key_id<S: Into<String>>(mut self, kms: S) -> Self {
        self.kms_key_id = Some(kms.into());
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

    /// Formats the AWS Secrets Manager PutSecretValue JSON payload.
    pub fn format_put_secret_value_payload(
        secret_id: &str,
        secret_string: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "SecretId": secret_id,
            "SecretString": secret_string
        })
    }

    /// Formats the AWS Secrets Manager CreateSecret JSON payload.
    pub fn format_create_secret_payload(
        name: &str,
        secret_string: &str,
        description: Option<&str>,
        kms_key_id: Option<&str>,
    ) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "Name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
        map.insert(
            "SecretString".to_string(),
            serde_json::Value::String(secret_string.to_string()),
        );
        if let Some(desc) = description {
            map.insert(
                "Description".to_string(),
                serde_json::Value::String(desc.to_string()),
            );
        }
        if let Some(kms) = kms_key_id {
            map.insert(
                "KmsKeyId".to_string(),
                serde_json::Value::String(kms.to_string()),
            );
        }
        serde_json::Value::Object(map)
    }

    /// Formats the payload according to the configured action mode.
    pub fn format_payload(&self, key: &str, secret: &str) -> serde_json::Value {
        match self.action {
            AwsActionMode::PutSecretValue => Self::format_put_secret_value_payload(key, secret),
            AwsActionMode::CreateSecret => Self::format_create_secret_payload(
                key,
                secret,
                Some("Managed by Sentris Autonomous Remediator"),
                self.kms_key_id.as_deref(),
            ),
        }
    }
}

impl Default for AwsSecretsManagerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStoreBackend for AwsSecretsManagerBackend {
    fn backend_name(&self) -> &'static str {
        "Aws"
    }

    fn inject_secret(
        &self,
        key: &str,
        secret: &str,
        dry_run: bool,
    ) -> Result<String, SentrisError> {
        let action_name = self.action.as_str();

        if dry_run {
            let payload = self.format_payload(key, "<redacted>");
            return Ok(format!(
                "[dry-run] Formatted AWS Secrets Manager {action_name} payload for '{key}' (region: {}): {}",
                self.region,
                serde_json::to_string(&payload)?
            ));
        }

        if self.mock {
            let payload = self.format_payload(key, secret);
            let path = record_mock(
                self.mock_ledger_path.as_deref(),
                "aws_secrets_manager_mock.json",
                key,
                payload,
            )?;
            return Ok(format!(
                "{} (ledger: {})",
                mock_notice("Aws"),
                path.display()
            ));
        }

        let subcommand = match self.action {
            AwsActionMode::PutSecretValue => "put-secret-value",
            AwsActionMode::CreateSecret => "create-secret",
        };
        let id_flag = match self.action {
            AwsActionMode::PutSecretValue => "--secret-id",
            AwsActionMode::CreateSecret => "--name",
        };

        // file:// keeps the secret out of argv; the temp file is 0600 and removed on drop
        let secret_file = SecretTempFile::create(secret)
            .map_err(|e| SentrisError::Scan(format!("Cannot stage secret for aws CLI: {e}")))?;
        let secret_arg = format!("file://{}", secret_file.path().display());

        let mut cmd = std::process::Command::new("aws");
        cmd.args([
            "secretsmanager",
            subcommand,
            id_flag,
            key,
            "--secret-string",
            &secret_arg,
            "--region",
            &self.region,
        ]);
        if let (AwsActionMode::CreateSecret, Some(kms)) = (&self.action, &self.kms_key_id) {
            cmd.args(["--kms-key-id", kms]);
        }

        match cmd.output() {
            Ok(out) if out.status.success() => Ok(format!(
                "AWS Secrets Manager {action_name} executed via aws CLI for '{key}' in region {}",
                self.region
            )),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(SentrisError::Scan(format!(
                    "aws secretsmanager {subcommand} failed for '{key}': {}",
                    stderr.trim()
                )))
            }
            Err(e) => Err(SentrisError::Scan(format!(
                "Failed to spawn 'aws' CLI for '{key}' (install AWS CLI v2): {e}"
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
    fn test_aws_secrets_manager_backend() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("aws_ledger.json");

        // 1. PutSecretValue action
        let backend_put = AwsSecretsManagerBackend::new()
            .with_region("eu-west-1")
            .with_action(AwsActionMode::PutSecretValue)
            .with_mock(true)
            .with_mock_ledger_path(&ledger_path);
        assert_eq!(backend_put.backend_name(), "Aws");

        let dry_put = backend_put
            .inject_secret("RDS_PASSWORD", "pwd_aws_123", true)
            .unwrap();
        assert!(dry_put.contains("[dry-run]"));
        assert!(dry_put.contains("PutSecretValue"));
        assert!(dry_put.contains("eu-west-1"));

        backend_put
            .inject_secret("RDS_PASSWORD", "pwd_aws_123", false)
            .unwrap();
        assert!(ledger_path.exists());

        // 2. CreateSecret action
        let backend_create = AwsSecretsManagerBackend::new()
            .with_action(AwsActionMode::CreateSecret)
            .with_kms_key_id("arn:aws:kms:us-east-1:123456789:key/dummy")
            .with_mock(true)
            .with_mock_ledger_path(&ledger_path);

        let dry_create = backend_create
            .inject_secret("NEW_SECRET", "val_create_456", true)
            .unwrap();
        assert!(dry_create.contains("CreateSecret"));
        assert!(dry_create.contains("NEW_SECRET"));
        assert!(dry_create.contains("arn:aws:kms"));
    }
}
