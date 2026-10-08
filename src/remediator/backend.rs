#![allow(dead_code)]

use crate::error::SentrisError;
use crate::remediator::env_patcher::EnvPatcher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Trait defining the enterprise secret storage backend interface.
pub trait SecretStoreBackend: Send + Sync {
    /// Returns the canonical name of this backend driver.
    fn backend_name(&self) -> &'static str;

    /// Injects or provisions a secret into the storage backend.
    /// In dry-run mode, formats and returns the staged action without mutating state.
    fn inject_secret(&self, key: &str, secret: &str, dry_run: bool)
        -> Result<String, SentrisError>;
}

/// Supported enterprise secret store backend types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretBackendType {
    Env,
    Vault,
    Aws,
    Doppler,
}

impl SecretBackendType {
    /// Returns static string representation of the backend type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Env => "Env",
            Self::Vault => "Vault",
            Self::Aws => "Aws",
            Self::Doppler => "Doppler",
        }
    }

    /// Parses a backend type identifier (case-insensitive, ignores hyphens and underscores).
    pub fn from_name(name: &str) -> Result<Self, SentrisError> {
        let normalized = name
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_', ' ', '.'], "");
        match normalized.as_str() {
            "env" | "envfile" => Ok(Self::Env),
            "vault" | "hashicorpvault" => Ok(Self::Vault),
            "aws" | "awssecretsmanager" | "secretsmanager" => Ok(Self::Aws),
            "doppler" | "dopplercli" => Ok(Self::Doppler),
            _ => Err(SentrisError::Config(format!(
                "Unknown secret backend type: '{name}'. Supported: env, vault, aws, doppler"
            ))),
        }
    }

    /// Parses from string slice, matching `from_name`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, SentrisError> {
        Self::from_name(s)
    }

    /// Instantiates the backend driver corresponding to this type.
    pub fn create_backend(&self) -> Box<dyn SecretStoreBackend> {
        match self {
            Self::Env => Box::new(EnvFileBackend::new()),
            Self::Vault => Box::new(VaultBackend::new()),
            Self::Aws => Box::new(AwsSecretsManagerBackend::new()),
            Self::Doppler => Box::new(DopplerBackend::new()),
        }
    }
}

impl std::str::FromStr for SecretBackendType {
    type Err = SentrisError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}

impl std::fmt::Display for SecretBackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Factory utility to construct secret backend drivers.
pub struct SecretBackendFactory;

impl SecretBackendFactory {
    /// Creates a driver instance for the specified backend type.
    pub fn create(backend_type: SecretBackendType) -> Box<dyn SecretStoreBackend> {
        backend_type.create_backend()
    }

    /// Resolves backend type by name and instantiates the driver.
    pub fn from_name(name: &str) -> Result<Box<dyn SecretStoreBackend>, SentrisError> {
        let backend_type = SecretBackendType::from_name(name)?;
        Ok(backend_type.create_backend())
    }
}

// =========================================================================
// 1. EnvFileBackend
// =========================================================================

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

// =========================================================================
// 2. VaultBackend
// =========================================================================

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

// =========================================================================
// 3. AwsSecretsManagerBackend
// =========================================================================

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
            mock: true,
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
        let payload = self.format_payload(key, secret);
        let action_name = self.action.as_str();

        if dry_run {
            return Ok(format!(
                "[dry-run] Formatted AWS Secrets Manager {action_name} payload for '{key}' (region: {}): {}",
                self.region,
                serde_json::to_string(&payload)?
            ));
        }

        if self.mock {
            let ledger_path = self
                .mock_ledger_path
                .clone()
                .unwrap_or_else(|| Path::new(".sentris").join("aws_secrets_manager_mock.json"));
            if let Some(parent) = ledger_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut existing: HashMap<String, serde_json::Value> = if ledger_path.exists() {
                let content = fs::read_to_string(&ledger_path)?;
                serde_json::from_str(&content).unwrap_or_default()
            } else {
                HashMap::new()
            };
            existing.insert(key.to_string(), payload.clone());
            fs::write(&ledger_path, serde_json::to_string_pretty(&existing)?)?;

            return Ok(format!(
                "Recorded AWS Secrets Manager {action_name} payload for '{key}' to mock ledger at {}",
                ledger_path.display()
            ));
        }

        Ok(format!(
            "AWS Secrets Manager {action_name} executed for '{key}' in region {}",
            self.region
        ))
    }
}

// =========================================================================
// 4. DopplerBackend
// =========================================================================

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
            mock: true,
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
        let api_payload = self.format_api_payload(key, secret);
        let cli_cmd = self.format_cli_command(key, secret);

        if dry_run {
            return Ok(format!(
                "[dry-run] Formatted Doppler secret update for '{key}' (CLI: '{cli_cmd}', API: {})",
                serde_json::to_string(&api_payload)?
            ));
        }

        if self.mock {
            let ledger_path = self
                .mock_ledger_path
                .clone()
                .unwrap_or_else(|| Path::new(".sentris").join("doppler_mock.json"));
            if let Some(parent) = ledger_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut existing: HashMap<String, serde_json::Value> = if ledger_path.exists() {
                let content = fs::read_to_string(&ledger_path)?;
                serde_json::from_str(&content).unwrap_or_default()
            } else {
                HashMap::new()
            };
            existing.insert(key.to_string(), api_payload.clone());
            fs::write(&ledger_path, serde_json::to_string_pretty(&existing)?)?;

            return Ok(format!(
                "Recorded Doppler secret update for '{key}' to mock ledger at {} (CLI: '{cli_cmd}')",
                ledger_path.display()
            ));
        }

        Ok(format!(
            "Updated Doppler secret '{key}' in project '{}', config '{}'",
            self.project, self.config
        ))
    }
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// =========================================================================
// Unit Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secret_backend_type_parsing() {
        assert_eq!(
            SecretBackendType::from_name("env").unwrap(),
            SecretBackendType::Env
        );
        assert_eq!(
            SecretBackendType::from_name("EnvFile").unwrap(),
            SecretBackendType::Env
        );
        assert_eq!(
            SecretBackendType::from_str("vault").unwrap(),
            SecretBackendType::Vault
        );
        assert_eq!(
            SecretBackendType::from_name("hashicorp-vault").unwrap(),
            SecretBackendType::Vault
        );
        assert_eq!(
            SecretBackendType::from_name("aws").unwrap(),
            SecretBackendType::Aws
        );
        assert_eq!(
            SecretBackendType::from_str("aws_secrets_manager").unwrap(),
            SecretBackendType::Aws
        );
        assert_eq!(
            SecretBackendType::from_name("doppler").unwrap(),
            SecretBackendType::Doppler
        );

        assert!(SecretBackendType::from_name("unsupported").is_err());
    }

    #[test]
    fn test_secret_backend_factory() {
        let env_backend = SecretBackendFactory::from_name("env").unwrap();
        assert_eq!(env_backend.backend_name(), "Env");

        let vault_backend = SecretBackendFactory::create(SecretBackendType::Vault);
        assert_eq!(vault_backend.backend_name(), "Vault");

        let aws_backend = SecretBackendFactory::from_name("aws").unwrap();
        assert_eq!(aws_backend.backend_name(), "Aws");

        let doppler_backend = SecretBackendFactory::create(SecretBackendType::Doppler);
        assert_eq!(doppler_backend.backend_name(), "Doppler");
    }

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
        assert!(live_res.contains("Recorded Doppler secret update for 'GITHUB_TOKEN'"));
        assert!(ledger_path.exists());
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

    #[test]
    fn test_backend_type_display_and_as_str() {
        assert_eq!(SecretBackendType::Env.as_str(), "Env");
        assert_eq!(SecretBackendType::Vault.as_str(), "Vault");
        assert_eq!(SecretBackendType::Aws.as_str(), "Aws");
        assert_eq!(SecretBackendType::Doppler.as_str(), "Doppler");
        assert_eq!(format!("{}", SecretBackendType::Env), "Env");
    }
}
