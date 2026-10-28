pub mod aws;
pub mod doppler;
pub mod env;
pub mod infisical;
pub mod onepassword;
pub mod vault;

pub use aws::{AwsActionMode, AwsSecretsManagerBackend};
pub use doppler::DopplerBackend;
pub use env::EnvFileBackend;
pub use infisical::InfisicalBackend;
pub use onepassword::OnePasswordBackend;
pub use vault::{VaultBackend, VaultMockEntry, VaultMockLedger};

use crate::error::SentrisError;
use serde::{Deserialize, Serialize};
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
    OnePassword,
    Infisical,
}

impl SecretBackendType {
    /// Returns static string representation of the backend type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Env => "Env",
            Self::Vault => "Vault",
            Self::Aws => "Aws",
            Self::Doppler => "Doppler",
            Self::OnePassword => "1Password",
            Self::Infisical => "Infisical",
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
            "1password" | "onepassword" | "op" => Ok(Self::OnePassword),
            "infisical" | "infisicalcli" => Ok(Self::Infisical),
            _ => Err(SentrisError::Config(format!(
                "Unknown secret backend type: '{name}'. Supported: env, vault, aws, doppler, 1password, infisical"
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
            Self::OnePassword => Box::new(OnePasswordBackend::new()),
            Self::Infisical => Box::new(InfisicalBackend::new()),
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

pub(crate) fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            SecretBackendType::from_name("1password").unwrap(),
            SecretBackendType::OnePassword
        );
        assert_eq!(
            SecretBackendType::from_name("infisical").unwrap(),
            SecretBackendType::Infisical
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
    fn test_backend_type_display_and_as_str() {
        assert_eq!(SecretBackendType::Env.as_str(), "Env");
        assert_eq!(SecretBackendType::Vault.as_str(), "Vault");
        assert_eq!(SecretBackendType::Aws.as_str(), "Aws");
        assert_eq!(SecretBackendType::Doppler.as_str(), "Doppler");
        assert_eq!(SecretBackendType::OnePassword.as_str(), "1Password");
        assert_eq!(SecretBackendType::Infisical.as_str(), "Infisical");
        assert_eq!(format!("{}", SecretBackendType::Env), "Env");
    }
}
