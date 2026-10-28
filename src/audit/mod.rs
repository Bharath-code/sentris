pub mod crypto;
pub mod vanta;

#[cfg(test)]
mod tests;

pub use crypto::{get_audit_salt, hmac_sha256, GENESIS_PREVIOUS_HASH};

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SentrisError;

/// Action types recorded in the SOC 2 cryptographic audit ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditAction {
    ScanCompleted {
        files_scanned: usize,
        findings_count: usize,
        duration_ms: u64,
    },
    SecretRemediated {
        session_id: String,
        rule_id: String,
        backend: String,
    },
    BaselineRecorded {
        entries_count: usize,
        git_commit: Option<String>,
    },
    QuarantineCreated {
        finding_id: String,
        branch: String,
    },
}

/// A tamper-evident cryptographic audit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub index: u64,
    pub timestamp: u64,
    pub action: AuditAction,
    pub details: serde_json::Value,
    pub previous_hash: String,
    pub entry_hash: String,
    pub hmac_signature: String,
}

impl AuditRecord {
    /// Computes SHA-256 hash of index + timestamp + action json + previous_hash.
    pub fn compute_entry_hash(
        index: u64,
        timestamp: u64,
        action: &AuditAction,
        previous_hash: &str,
    ) -> Result<String, SentrisError> {
        let action_json = serde_json::to_string(action)?;
        let mut hasher = Sha256::new();
        let payload = format!("{}:{}:{}:{}", index, timestamp, action_json, previous_hash);
        hasher.update(payload.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// Computes HMAC-SHA256 signature using the salt and record payload (entry_hash + details).
    pub fn compute_hmac_signature(
        entry_hash: &str,
        details: &serde_json::Value,
        salt: &[u8],
    ) -> Result<String, SentrisError> {
        let details_json = serde_json::to_string(details)?;
        let payload = format!("{}:{}", entry_hash, details_json);
        let sig = hmac_sha256(salt, payload.as_bytes());
        Ok(hex::encode(sig))
    }
}

/// Append-only SOC 2 cryptographic audit ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLedger {
    pub records: Vec<AuditRecord>,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub file_path: PathBuf,
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            file_path: Self::default_path(),
        }
    }
}

impl AuditLedger {
    /// Default storage path for the audit ledger in `.sentris/audit_ledger.json`.
    pub fn default_path() -> PathBuf {
        Path::new(".sentris").join("audit_ledger.json")
    }

    /// Loads the ledger from disk, or initializes an empty ledger if the file does not exist.
    pub fn load_or_init<P: AsRef<Path>>(path: P) -> Result<Self, SentrisError> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(Self {
                records: Vec::new(),
                file_path: p.to_path_buf(),
            });
        }

        let content = fs::read_to_string(p)?;
        if content.trim().is_empty() {
            return Ok(Self {
                records: Vec::new(),
                file_path: p.to_path_buf(),
            });
        }

        let records: Vec<AuditRecord> = match serde_json::from_str::<Vec<AuditRecord>>(&content) {
            Ok(recs) => recs,
            Err(_) => {
                #[derive(Deserialize)]
                struct LedgerWrapper {
                    records: Vec<AuditRecord>,
                }
                match serde_json::from_str::<LedgerWrapper>(&content) {
                    Ok(wrapper) => wrapper.records,
                    Err(e) => return Err(SentrisError::Serialization(e)),
                }
            }
        };

        Ok(Self {
            records,
            file_path: p.to_path_buf(),
        })
    }

    /// Records an event with the default system salt.
    pub fn record_event(
        &mut self,
        action: AuditAction,
        details: serde_json::Value,
    ) -> Result<&AuditRecord, SentrisError> {
        let salt = get_audit_salt();
        self.record_event_with_salt(action, details, &salt)
    }

    /// Records an event with an explicit salt.
    pub fn record_event_with_salt(
        &mut self,
        action: AuditAction,
        details: serde_json::Value,
        salt: &[u8],
    ) -> Result<&AuditRecord, SentrisError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.record_event_with_timestamp_and_salt(action, details, timestamp, salt)
    }

    /// Records an event with explicit timestamp and salt.
    pub fn record_event_with_timestamp_and_salt(
        &mut self,
        action: AuditAction,
        details: serde_json::Value,
        timestamp: u64,
        salt: &[u8],
    ) -> Result<&AuditRecord, SentrisError> {
        let index = self.records.len() as u64;
        let previous_hash = if let Some(last) = self.records.last() {
            last.entry_hash.clone()
        } else {
            GENESIS_PREVIOUS_HASH.to_string()
        };

        let entry_hash =
            AuditRecord::compute_entry_hash(index, timestamp, &action, &previous_hash)?;
        let hmac_signature = AuditRecord::compute_hmac_signature(&entry_hash, &details, salt)?;

        let record = AuditRecord {
            index,
            timestamp,
            action,
            details,
            previous_hash,
            entry_hash,
            hmac_signature,
        };

        self.records.push(record);
        Ok(self.records.last().unwrap())
    }

    /// Verifies the cryptographic integrity of the entire audit chain.
    pub fn verify_integrity(&self) -> Result<bool, SentrisError> {
        let salt = get_audit_salt();
        self.verify_integrity_with_salt(&salt)
    }

    /// Verifies the cryptographic integrity using an explicit salt.
    pub fn verify_integrity_with_salt(&self, salt: &[u8]) -> Result<bool, SentrisError> {
        if self.records.is_empty() {
            return Ok(true);
        }

        let mut expected_previous_hash = GENESIS_PREVIOUS_HASH.to_string();

        for (i, record) in self.records.iter().enumerate() {
            // 1. Check monotonic index starting from 0
            if record.index != i as u64 {
                return Ok(false);
            }

            // 2. Check previous_hash chain continuity
            if record.previous_hash != expected_previous_hash {
                return Ok(false);
            }

            // 3. Check entry_hash recalculation
            let computed_entry_hash = AuditRecord::compute_entry_hash(
                record.index,
                record.timestamp,
                &record.action,
                &record.previous_hash,
            )?;
            if record.entry_hash != computed_entry_hash {
                return Ok(false);
            }

            // 4. Check HMAC signature recalculation
            let computed_hmac =
                AuditRecord::compute_hmac_signature(&record.entry_hash, &record.details, salt)?;
            if record.hmac_signature != computed_hmac {
                return Ok(false);
            }

            // Advance expected hash for next record
            expected_previous_hash = record.entry_hash.clone();
        }

        Ok(true)
    }

    /// Saves the ledger to its configured file path.
    pub fn save(&self) -> Result<(), SentrisError> {
        if let Some(parent) = self.file_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        let serialized = serde_json::to_string_pretty(&self.records)?;
        fs::write(&self.file_path, serialized)?;
        Ok(())
    }
}
