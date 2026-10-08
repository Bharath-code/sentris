#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SentrisError;

/// Genesis previous hash for the first record in the cryptographic chain (64 zeros).
pub const GENESIS_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Standard HMAC-SHA256 implementation (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hashed_key = hasher.finalize();
        key_block[..32].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    outer_hash.into()
}

/// Retrieves a persistent or deterministic salt for HMAC signature verification.
/// Prioritizes `SENTRIS_AUDIT_SALT` environment variable, then repository or machine salt.
pub fn get_audit_salt() -> Vec<u8> {
    if let Ok(salt) = std::env::var("SENTRIS_AUDIT_SALT") {
        if !salt.is_empty() {
            return salt.into_bytes();
        }
    }

    let mut material = String::new();
    if let Ok(repo_root) = crate::git::GitManager::find_git_root() {
        material.push_str(&repo_root.to_string_lossy());
    } else if let Ok(current_dir) = std::env::current_dir() {
        material.push_str(&current_dir.to_string_lossy());
    }

    material.push(':');
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        material.push_str(&user);
    }
    material.push(':');
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        material.push_str(&hostname);
    }

    if material.trim_matches(':').is_empty() {
        material = "sentris-soc2-audit-chain-default-salt".to_string();
    }

    let mut hasher = Sha256::new();
    hasher.update(b"sentris-audit-salt-v1:");
    hasher.update(material.as_bytes());
    hasher.finalize().to_vec()
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_rfc4231_hmac_sha256() {
        // RFC 4231 Test Case 1
        let key_1 = vec![0x0bu8; 20];
        let data_1 = b"Hi There";
        let hmac_1 = hmac_sha256(&key_1, data_1);
        assert_eq!(
            hex::encode(hmac_1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 Test Case 2
        let key_2 = b"Jefe";
        let data_2 = b"what do ya want for nothing?";
        let hmac_2 = hmac_sha256(key_2, data_2);
        assert_eq!(
            hex::encode(hmac_2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // RFC 4231 Test Case 6 (key larger than block size 64 bytes)
        let key_6 = vec![0xaau8; 131];
        let data_6 = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let hmac_6 = hmac_sha256(&key_6, data_6);
        assert_eq!(
            hex::encode(hmac_6),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn test_audit_action_serialization() {
        let actions = vec![
            AuditAction::ScanCompleted {
                files_scanned: 100,
                findings_count: 5,
                duration_ms: 1250,
            },
            AuditAction::SecretRemediated {
                session_id: "sess-abc".to_string(),
                rule_id: "stripe-secret-key".to_string(),
                backend: "vault".to_string(),
            },
            AuditAction::BaselineRecorded {
                entries_count: 42,
                git_commit: Some("abcdef0123456789".to_string()),
            },
            AuditAction::QuarantineCreated {
                finding_id: "find-99".to_string(),
                branch: "quarantine/find-99".to_string(),
            },
        ];

        for action in actions {
            let serialized = serde_json::to_string(&action).unwrap();
            let deserialized: AuditAction = serde_json::from_str(&serialized).unwrap();
            assert_eq!(action, deserialized);
        }
    }

    #[test]
    fn test_creation_of_multiple_audit_entries() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("audit.json");
        let mut ledger = AuditLedger::load_or_init(&ledger_path).unwrap();

        assert!(ledger.records.is_empty());

        let r1 = ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 50,
                    findings_count: 1,
                    duration_ms: 320,
                },
                serde_json::json!({"initiator": "ci"}),
            )
            .unwrap()
            .clone();

        assert_eq!(r1.index, 0);
        assert_eq!(r1.previous_hash, GENESIS_PREVIOUS_HASH);
        assert_eq!(r1.entry_hash.len(), 64);
        assert_eq!(r1.hmac_signature.len(), 64);

        let r2 = ledger
            .record_event(
                AuditAction::SecretRemediated {
                    session_id: "sess-1".to_string(),
                    rule_id: "aws-access-key".to_string(),
                    backend: "env".to_string(),
                },
                serde_json::json!({"actor": "alice"}),
            )
            .unwrap()
            .clone();

        assert_eq!(r2.index, 1);
        assert_eq!(r2.previous_hash, r1.entry_hash);

        let r3 = ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 12,
                    git_commit: Some("12345678".to_string()),
                },
                serde_json::json!({"baseline": "v1.0"}),
            )
            .unwrap()
            .clone();

        assert_eq!(r3.index, 2);
        assert_eq!(r3.previous_hash, r2.entry_hash);

        let r4 = ledger
            .record_event(
                AuditAction::QuarantineCreated {
                    finding_id: "fid-4".to_string(),
                    branch: "quarantine/fid-4".to_string(),
                },
                serde_json::json!({"branch": "quarantine/fid-4"}),
            )
            .unwrap()
            .clone();

        assert_eq!(r4.index, 3);
        assert_eq!(r4.previous_hash, r3.entry_hash);

        assert_eq!(ledger.records.len(), 4);
    }

    #[test]
    fn test_verification_of_hash_chain_integrity() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("audit.json");
        let mut ledger = AuditLedger::load_or_init(&ledger_path).unwrap();

        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 10,
                    findings_count: 0,
                    duration_ms: 100,
                },
                serde_json::json!({"clean": true}),
            )
            .unwrap();

        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 5,
                    git_commit: None,
                },
                serde_json::json!({"scope": "all"}),
            )
            .unwrap();

        ledger
            .record_event(
                AuditAction::SecretRemediated {
                    session_id: "sess-x".to_string(),
                    rule_id: "github-pat".to_string(),
                    backend: "vault".to_string(),
                },
                serde_json::json!({"status": "rotated"}),
            )
            .unwrap();

        // Verify valid chain
        assert!(ledger.verify_integrity().unwrap());

        // Save and reload from disk
        ledger.save().unwrap();
        let loaded = AuditLedger::load_or_init(&ledger_path).unwrap();
        assert_eq!(loaded.records.len(), 3);
        assert!(loaded.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_index() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with index of earlier record
        ledger.records[0].index = 999;
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_timestamp() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with timestamp of earlier record
        ledger.records[0].timestamp += 1000;
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_action() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 10,
                    findings_count: 2,
                    duration_ms: 50,
                },
                serde_json::json!({}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with action of earlier record (reduce findings count)
        ledger.records[0].action = AuditAction::ScanCompleted {
            files_scanned: 10,
            findings_count: 0, // tampered!
            duration_ms: 50,
        };
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_details() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({"approved_by": "sec_team"}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with details of earlier record
        ledger.records[0].details = serde_json::json!({"approved_by": "attacker"});
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_previous_hash() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with previous_hash of earlier record
        ledger.records[0].previous_hash =
            "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_entry_hash() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with entry_hash of earlier record
        ledger.records[0].entry_hash =
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string();
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_hmac_signature() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Tamper with HMAC signature of earlier record
        ledger.records[0].hmac_signature =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        assert!(!ledger.verify_integrity().unwrap());
    }

    #[test]
    fn test_tamper_detection_deletion_and_reordering() {
        let mut ledger = AuditLedger::default();
        ledger
            .record_event(
                AuditAction::ScanCompleted {
                    files_scanned: 1,
                    findings_count: 0,
                    duration_ms: 10,
                },
                serde_json::json!({"entry": 0}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::BaselineRecorded {
                    entries_count: 1,
                    git_commit: None,
                },
                serde_json::json!({"entry": 1}),
            )
            .unwrap();
        ledger
            .record_event(
                AuditAction::SecretRemediated {
                    session_id: "s1".to_string(),
                    rule_id: "r1".to_string(),
                    backend: "b1".to_string(),
                },
                serde_json::json!({"entry": 2}),
            )
            .unwrap();

        assert!(ledger.verify_integrity().unwrap());

        // Deleting record 1 breaks the chain between 0 and 2
        let mut tampered = ledger.clone();
        tampered.records.remove(1);
        assert!(!tampered.verify_integrity().unwrap());

        // Swapping record 0 and 1 breaks genesis and order
        let mut swapped = ledger.clone();
        swapped.records.swap(0, 1);
        assert!(!swapped.verify_integrity().unwrap());
    }

    #[test]
    fn test_empty_ledger_integrity() {
        let ledger = AuditLedger::default();
        assert!(ledger.verify_integrity().unwrap());
    }
}
