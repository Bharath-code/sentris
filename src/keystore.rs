use crate::audit::crypto::hmac_sha256;
use crate::error::SentrisError;
use std::fs;
use std::path::PathBuf;

/// Per-user state directory, always outside the scanned repo so a cloned repo cannot ship its own keys.
pub fn state_dir() -> Result<PathBuf, SentrisError> {
    if let Some(dir) = std::env::var_os("SENTRIS_STATE_DIR").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("sentris"));
    }
    match std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        Some(home) => Ok(PathBuf::from(home).join(".sentris").join("state")),
        None => Err(SentrisError::Config(
            "Cannot locate a per-user state directory; set SENTRIS_STATE_DIR".to_string(),
        )),
    }
}

/// Returns the 32-byte secret stored as `<state_dir>/<name>.key`, creating it (0600) on first use.
pub fn key(name: &str) -> Result<Vec<u8>, SentrisError> {
    let path = state_dir()?.join(format!("{name}.key"));
    if let Ok(existing) = fs::read_to_string(&path) {
        return hex::decode(existing.trim())
            .ok()
            .filter(|k| k.len() == 32)
            .ok_or_else(|| {
                SentrisError::Config(format!(
                    "Corrupt key file {}; delete it to regenerate",
                    path.display()
                ))
            });
    }
    let mut fresh = [0u8; 32];
    getrandom::getrandom(&mut fresh).map_err(|e| SentrisError::Config(e.to_string()))?;
    crate::remediator::backend::write_private(&path, &hex::encode(fresh))?;
    Ok(fresh.to_vec())
}

pub fn mac_hex(name: &str, message: &[u8]) -> Result<String, SentrisError> {
    Ok(hex::encode(hmac_sha256(&key(name)?, message)))
}

/// Constant-time equality for MACs/hashes.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_normal_equality() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(ct_eq("", ""));
    }
}
