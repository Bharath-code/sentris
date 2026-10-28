use crate::cloud::client::{mock_mode, validate_server_url, DEFAULT_SERVER_URL};
use crate::error::SentrisError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Developer authentication and license credentials for Sentris Pro Cloud
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    pub api_key: String,
    pub server_url: String,
    pub org_id: String,
    pub org_name: String,
    pub tier: String,
    pub seat_limit: u32,
    pub seats_used: u32,
    pub user_email: String,
    pub expires_at: Option<String>,
    /// 256-bit team secret (hex) used as the HMAC key for zero-knowledge fingerprints.
    /// Shared between teammates out of band and never transmitted to Sentris Cloud.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_secret: Option<String>,
}

/// Generate a fresh 256-bit team secret from the OS CSPRNG.
pub fn generate_team_secret() -> Result<String, SentrisError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| SentrisError::Cloud(format!("OS random number generator unavailable: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Accept only 64 hex chars (256 bits); anything shorter weakens the fingerprint HMAC.
pub fn validate_team_secret(secret: &str) -> Result<String, SentrisError> {
    let s = secret.trim().to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err(SentrisError::Cloud(
            "Team secret must be 64 hex characters (as printed by the first teammate's `sentris auth login`)."
                .to_string(),
        ))
    }
}

impl Credentials {
    /// Return the standard path to user credentials (`~/.sentris/credentials.json`)
    pub fn default_credentials_path() -> PathBuf {
        if let Ok(dir) = std::env::var("SENTRIS_CONFIG_DIR") {
            return PathBuf::from(dir).join("credentials.json");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".sentris")
                .join("credentials.json");
        }
        PathBuf::from(".sentris").join("credentials.json")
    }

    /// Load credentials from the default user configuration path
    pub fn load_default() -> Result<Self, SentrisError> {
        let path = Self::default_credentials_path();
        Self::load_from_path(&path)
    }

    /// Load credentials from a specific JSON file path
    pub fn load_from_path(path: &Path) -> Result<Self, SentrisError> {
        if !path.exists() {
            return Err(SentrisError::Cloud(format!(
                "No active credentials found at {}. Please run `sentris auth login --token <TOKEN>`.",
                path.display()
            )));
        }
        let content = fs::read_to_string(path)?;
        let creds: Credentials = serde_json::from_str(&content)
            .map_err(|e| SentrisError::Cloud(format!("Failed to parse credentials file: {e}")))?;
        Ok(creds)
    }

    /// Save credentials securely to a specific file path (creating parent directories as needed)
    pub fn save_to_path(&self, path: &Path) -> Result<(), SentrisError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SentrisError::Cloud(format!("Failed to serialize credentials: {e}")))?;
        // Holds the API key and team secret: created owner-only, never briefly world-readable
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
            if let Some(parent) = path.parent() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            // mode() only applies on create; tighten files left by older versions
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(json.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, json)?;
        }
        Ok(())
    }

    /// Delete credentials file from the default configuration path
    pub fn delete_default() -> Result<(), SentrisError> {
        let path = Self::default_credentials_path();
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Parse and validate a Sentris Pro license token or API key
    pub fn from_token(token: &str, server_url: Option<String>) -> Result<Self, SentrisError> {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return Err(SentrisError::Cloud(
                "API token cannot be empty. Expected format: `sp_live_<hex>` or license key."
                    .to_string(),
            ));
        }

        // Validate token format
        let is_valid_prefix = trimmed.starts_with("sp_live_")
            || trimmed.starts_with("sp_test_")
            || trimmed.starts_with("sentris_pro_")
            || trimmed.len() >= 24;

        if !is_valid_prefix {
            return Err(SentrisError::Cloud(
                "Invalid Sentris Pro API token format. Must start with `sp_live_` or be a valid 24+ char license key."
                    .to_string(),
            ));
        }

        let default_url = server_url.unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());
        validate_server_url(&default_url)?;

        // Org details are unknown until the server confirms the key (`refresh_from_server`)
        Ok(Credentials {
            api_key: trimmed.to_string(),
            server_url: default_url,
            org_id: String::new(),
            org_name: "(unverified)".to_string(),
            tier: "Unverified".to_string(),
            seat_limit: 0,
            seats_used: 0,
            user_email: String::new(),
            expires_at: None,
            team_secret: None,
        })
    }

    /// Validates the key against the server and replaces placeholders with the real org, plan and seats.
    pub fn refresh_from_server(&mut self) -> Result<(), SentrisError> {
        validate_server_url(&self.server_url)?;
        if mock_mode() {
            self.org_id = "org_mock".to_string();
            self.org_name = "[MOCK] offline workspace".to_string();
            self.tier = "Mock".to_string();
            return Ok(());
        }
        let url = format!("{}/api/v1/me", self.server_url.trim_end_matches('/'));
        let res = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .timeout(std::time::Duration::from_secs(8))
            .call();
        let me: serde_json::Value = match res {
            Ok(r) => r
                .into_json()
                .map_err(|e| SentrisError::Cloud(format!("Unreadable response from {url}: {e}")))?,
            Err(ureq::Error::Status(401, _)) => {
                return Err(SentrisError::Cloud(
                    "The server rejected this API key (invalid or revoked).".to_string(),
                ))
            }
            Err(ureq::Error::Status(code, _)) => {
                return Err(SentrisError::Cloud(format!("{url} returned HTTP {code}")))
            }
            Err(ureq::Error::Transport(e)) => {
                return Err(SentrisError::Cloud(format!("Could not reach {url}: {e}")))
            }
        };
        let text = |k: &str| me[k].as_str().unwrap_or_default().to_string();
        self.org_id = text("org_id");
        self.org_name = text("org_name");
        self.user_email = text("owner_email");
        self.tier = if me["plan"] == "pro" {
            "Pro".into()
        } else {
            "Free (beta)".into()
        };
        self.seat_limit = me["seats"].as_u64().unwrap_or(1) as u32;
        self.seats_used = 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_credentials_token_parsing_valid() {
        let token = "sp_live_9f8e7d6c5b4a3210deadbeef";
        let creds = Credentials::from_token(token, None).expect("Valid token should parse");
        assert_eq!(creds.api_key, token);
        assert_eq!(creds.tier, "Unverified");
        assert_eq!(creds.seat_limit, 0);
        assert_eq!(creds.server_url, DEFAULT_SERVER_URL);
        assert!(Credentials::from_token(token, Some("http://example.com".into())).is_err());
        assert!(Credentials::from_token(token, Some("https://u:p@evil.test".into())).is_err());
    }

    #[test]
    fn test_credentials_token_parsing_invalid() {
        let token = "short";
        let err = Credentials::from_token(token, None).unwrap_err();
        assert!(err.to_string().contains("Invalid Sentris Pro API token"));
    }

    #[test]
    fn test_credentials_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sub").join("creds.json");

        let creds = Credentials {
            api_key: "sp_live_1234567890abcdef".to_string(),
            server_url: "https://api.sentris.dev".to_string(),
            org_id: "org_acme".to_string(),
            org_name: "Acme Corp".to_string(),
            tier: "Pro ($8/seat)".to_string(),
            seat_limit: 50,
            seats_used: 28,
            user_email: "lead@acme.com".to_string(),
            expires_at: Some("2028-01-01T00:00:00Z".to_string()),
            team_secret: None,
        };

        creds.save_to_path(&path).expect("Save should succeed");
        let loaded = Credentials::load_from_path(&path).expect("Load should succeed");
        assert_eq!(creds, loaded);
    }
}
