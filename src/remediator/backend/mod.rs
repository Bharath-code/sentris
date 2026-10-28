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
use crate::remediator::env_patcher::EnvPatcher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

/// Trait defining the enterprise secret storage backend interface.
pub trait SecretStoreBackend: Send + Sync {
    /// Returns the canonical name of this backend driver.
    fn backend_name(&self) -> &'static str;

    /// Injects or provisions a secret into the storage backend.
    /// In dry-run mode, formats and returns the staged action without mutating state.
    fn inject_secret(&self, key: &str, secret: &str, dry_run: bool)
        -> Result<String, SentrisError>;

    /// True when writes go to a local simulation file instead of the real store.
    fn is_mock(&self) -> bool {
        false
    }
}

/// Simulated backends are opt-in only: a silent fallback would report success while the real store never received the secret.
pub(crate) fn mock_requested() -> bool {
    std::env::var("SENTRIS_MOCK_BACKEND")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Writes a file readable by the owner only (secrets live in these files).
pub(crate) fn write_private(path: &Path, content: &str) -> Result<(), SentrisError> {
    crate::fsutil::reject_symlinks(path)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Appends one entry to a simulation ledger under `.sentris/` (or `custom`), 0600, and gitignores `.sentris/`.
pub(crate) fn record_mock(
    custom: Option<&Path>,
    default_name: &str,
    key: &str,
    value: serde_json::Value,
) -> Result<PathBuf, SentrisError> {
    let path = custom
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(".sentris").join(default_name));
    let mut entries: HashMap<String, serde_json::Value> = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?)?
    } else {
        HashMap::new()
    };
    entries.insert(key.to_string(), value);
    write_private(&path, &serde_json::to_string_pretty(&entries)?)?;
    if custom.is_none() {
        EnvPatcher::ensure_env_gitignored()?;
    }
    Ok(path)
}

/// Explicit opt-in for backends whose CLI offers no stdin/file input for the value.
pub(crate) fn argv_secrets_allowed() -> bool {
    std::env::var("SENTRIS_ALLOW_ARGV_SECRETS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub(crate) fn mock_notice(backend: &str) -> String {
    format!(
        "[MOCK] secret was NOT stored in the real {backend} backend (SENTRIS_MOCK_BACKEND is set)"
    )
}

/// Runs `cmd` with `input` on stdin so the secret never appears in argv (`ps`, /proc/*/cmdline).
pub(crate) fn run_with_stdin(mut cmd: Command, input: &str) -> std::io::Result<Output> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    child.wait_with_output()
}

/// Owner-only temp file holding a secret; removed on drop.
pub(crate) struct SecretTempFile(PathBuf);

impl SecretTempFile {
    pub(crate) fn create(secret: &str) -> std::io::Result<Self> {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).map_err(|e| std::io::Error::other(e.to_string()))?;
        let path = std::env::temp_dir().join(format!("sentris-{}", hex::encode(rnd)));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&path)?.write_all(secret.as_bytes())?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SecretTempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
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

    #[cfg(unix)]
    #[test]
    fn live_cli_backends_never_put_secret_in_argv() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("calls.log");
        for bin in ["aws", "doppler"] {
            let path = dir.path().join(bin);
            // Records argv, stdin and (for aws) the file:// payload, then succeeds
            let script = format!(
                "#!/bin/sh\necho \"ARGV: $@\" >> {log}\nfor a in \"$@\"; do case \"$a\" in file://*) echo \"FILE: $(cat ${{a#file://}})\" >> {log};; esac; done\nif [ ! -t 0 ]; then echo \"STDIN: $(cat)\" >> {log}; fi\n",
                log = log.display()
            );
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", dir.path().display()));

        let secret = "sk_live_SUPERSECRETVALUE123";
        let aws = AwsSecretsManagerBackend::new().with_mock(false);
        let doppler = DopplerBackend::new().with_mock(false);
        let a = aws.inject_secret("STRIPE_KEY", secret, false);
        let d = doppler.inject_secret("STRIPE_KEY", secret, false);
        std::env::set_var("PATH", old_path);
        a.unwrap();
        d.unwrap();

        let calls = fs::read_to_string(&log).unwrap();
        for line in calls.lines().filter(|l| l.starts_with("ARGV:")) {
            assert!(!line.contains(secret), "secret leaked into argv: {line}");
        }
        assert!(calls.contains(&format!("FILE: {secret}")));
        assert!(calls.contains(&format!("STDIN: {secret}")));
        let leftovers = fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("sentris-"))
            .filter(|e| {
                fs::read_to_string(e.path())
                    .map(|c| c == secret)
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(leftovers, 0);
    }
}
