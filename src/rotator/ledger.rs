use super::{RotationRecord, RotationState};
use crate::error::SentrisError;
use crate::keystore;
use crate::remediator::backend::write_private;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RotationLedger {
    pub records: Vec<RotationRecord>,
    /// HMAC over `records` with a per-user key kept outside the repo, same scheme as the rollback ledger.
    #[serde(default)]
    pub mac: String,
}

impl RotationLedger {
    pub fn path() -> PathBuf {
        Path::new(".sentris").join("rotation_ledger.json")
    }

    fn compute_mac(&self) -> Result<String, SentrisError> {
        keystore::mac_hex("rotation", &serde_json::to_vec(&self.records)?)
    }

    pub fn load() -> Result<Self, SentrisError> {
        Self::load_from(&Self::path())
    }

    pub fn load_from(path: &Path) -> Result<Self, SentrisError> {
        crate::fsutil::reject_symlinks(path)?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let ledger: Self = serde_json::from_str(&fs::read_to_string(path)?).map_err(|e| {
            SentrisError::Scan(format!(
                "Rotation ledger {} is unreadable ({e}); not overwriting it",
                path.display()
            ))
        })?;
        if !keystore::ct_eq(&ledger.mac, &ledger.compute_mac()?) {
            return Err(SentrisError::Scan(format!(
                "Rotation ledger {} failed authentication (edited, or created on another machine); refusing to act on it",
                path.display()
            )));
        }
        Ok(ledger)
    }

    pub fn save(&mut self) -> Result<(), SentrisError> {
        self.save_to(&Self::path())
    }

    pub fn save_to(&mut self, path: &Path) -> Result<(), SentrisError> {
        self.mac = self.compute_mac()?;
        write_private(path, &serde_json::to_string_pretty(self)?)
    }

    pub fn get(&self, id: &str) -> Option<&RotationRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    pub fn insert(&mut self, record: RotationRecord) -> Result<(), SentrisError> {
        if self.get(&record.id).is_some() {
            return Err(SentrisError::Scan(format!(
                "Rotation '{}' already exists in the ledger",
                record.id
            )));
        }
        self.records.push(record);
        Ok(())
    }

    /// The unfinished rotation for a leaked secret's fingerprint, if any.
    pub fn active_for(&self, fingerprint: &str) -> Option<&RotationRecord> {
        self.records.iter().find(|r| {
            r.old_fingerprint == fingerprint
                && !matches!(
                    r.state,
                    RotationState::RolledBack | RotationState::OldDeleted
                )
        })
    }

    pub fn record_new_key(&mut self, id: &str, key_id: &str) -> Result<(), SentrisError> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| SentrisError::Scan(format!("Rotation '{id}' not found in ledger")))?;
        record.new_key_id = Some(key_id.to_string());
        Ok(())
    }

    /// Moves a rotation to `to`; callers persist with `save` before the matching provider side effect.
    pub fn advance(&mut self, id: &str, to: RotationState) -> Result<(), SentrisError> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| SentrisError::Scan(format!("Rotation '{id}' not found in ledger")))?;
        if !record.state.can_advance_to(to) {
            return Err(SentrisError::Scan(format!(
                "Rotation '{id}' cannot go from {:?} to {to:?}",
                record.state
            )));
        }
        record.state = to;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use std::fs;

    const OLD_SECRET: &str = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI-OLD-SECRET";

    fn plan() -> RotationPlan {
        RotationPlan {
            provider: "AWS".into(),
            rule_id: "aws-access-key-id".into(),
            principal: "bob".into(),
            old_key_id: "AKIAOLD".into(),
            old_fingerprint: "fp_0123".into(),
        }
    }

    fn rec(id: &str) -> RotationRecord {
        RotationRecord::new(id, "env", &plan(), 1_000, 86_400)
    }

    fn with_state<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _g = crate::keystore::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let state = tempfile::tempdir().unwrap();
        std::env::set_var("SENTRIS_STATE_DIR", state.path());
        let dir = tempfile::tempdir().unwrap();
        f(&dir.path().join("rotation_ledger.json"))
    }

    #[test]
    fn grace_until_uses_the_injected_clock() {
        let r = rec("r1");
        assert_eq!(r.created_at, 1_000);
        assert_eq!(r.grace_until, 1_000 + 86_400);
        assert_eq!(r.state, RotationState::Planned);
    }

    #[test]
    fn legal_path_advances_and_illegal_is_rejected() {
        let mut l = RotationLedger::default();
        l.insert(rec("r1")).unwrap();
        assert!(l.advance("r1", RotationState::OldDeleted).is_err());
        for s in [
            RotationState::Minted,
            RotationState::Stored,
            RotationState::OldDeactivated,
            RotationState::OldDeleted,
        ] {
            l.advance("r1", s).unwrap();
        }
        assert_eq!(l.get("r1").unwrap().state, RotationState::OldDeleted);
    }

    #[test]
    fn terminal_states_cannot_advance() {
        let mut l = RotationLedger::default();
        l.insert(rec("r1")).unwrap();
        l.advance("r1", RotationState::RolledBack).unwrap();
        assert!(l.advance("r1", RotationState::Minted).is_err());
    }

    #[test]
    fn unknown_id_and_duplicate_id_are_errors() {
        let mut l = RotationLedger::default();
        assert!(l.advance("nope", RotationState::Minted).is_err());
        l.insert(rec("r1")).unwrap();
        assert!(l.insert(rec("r1")).is_err());
    }

    #[test]
    fn save_then_load_round_trips() {
        with_state(|path| {
            let mut l = RotationLedger::default();
            l.insert(rec("r1")).unwrap();
            l.save_to(path).unwrap();
            let back = RotationLedger::load_from(path).unwrap();
            assert_eq!(back.get("r1").unwrap().principal, "bob");
        });
    }

    #[test]
    fn tamper_is_detected_and_file_left_alone() {
        with_state(|path| {
            let mut l = RotationLedger::default();
            l.insert(rec("r1")).unwrap();
            l.save_to(path).unwrap();
            let tampered = fs::read_to_string(path).unwrap().replace("bob", "eve");
            fs::write(path, &tampered).unwrap();
            assert!(RotationLedger::load_from(path).is_err());
            assert_eq!(fs::read_to_string(path).unwrap(), tampered);
        });
    }

    #[test]
    fn ledger_never_contains_secret_material() {
        with_state(|path| {
            let mut l = RotationLedger::default();
            l.insert(rec("r1")).unwrap();
            l.save_to(path).unwrap();
            let disk = fs::read_to_string(path).unwrap();
            assert!(!disk.contains(OLD_SECRET));
            assert!(!disk.contains("wJalrXUtnFEMI"));
        });
    }

    #[test]
    fn minted_credential_debug_hides_the_secret() {
        let m = MintedCredential {
            key_id: "AKIANEW".into(),
            secret: OLD_SECRET.into(),
        };
        let shown = format!("{m:?}");
        assert!(shown.contains("AKIANEW"));
        assert!(!shown.contains("wJalrXUtnFEMI"));
    }

    #[cfg(unix)]
    #[test]
    fn ledger_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_state(|path| {
            let mut l = RotationLedger::default();
            l.insert(rec("r1")).unwrap();
            l.save_to(path).unwrap();
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        });
    }
}
