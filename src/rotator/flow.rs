use super::timefmt::format_utc;
use super::{
    new_rotation_id, LastUse, MintedCredential, RotationLedger, RotationPlan, RotationRecord,
    RotationState, Rotator,
};
use crate::error::SentrisError;
use crate::remediator::backend::SecretStoreBackend;
use crate::remediator::Remediator;
use std::path::Path;

pub const DEFAULT_GRACE_SECS: u64 = 86_400;

pub struct ProvisionRequest<'a> {
    pub old_secret: &'a str,
    pub fingerprint: &'a str,
    pub base_var: &'a str,
    pub backend_label: &'a str,
    pub now: u64,
    pub grace_secs: u64,
}

#[derive(Debug)]
pub struct Provisioned {
    pub id: String,
    pub resumed: bool,
}

fn load_record(ledger: &RotationLedger, id: &str) -> Result<RotationRecord, SentrisError> {
    ledger
        .get(id)
        .cloned()
        .ok_or_else(|| SentrisError::Scan(format!("Rotation '{id}' not found in ledger")))
}

fn persist(
    ledger: &mut RotationLedger,
    path: &Path,
    id: &str,
    to: RotationState,
) -> Result<(), SentrisError> {
    ledger.advance(id, to)?;
    ledger.save_to(path)
}

/// Mints a replacement key and stores it; the old key stays active. Re-running resumes instead of minting twice.
pub fn provision(
    rotator: &dyn Rotator,
    backend: &dyn SecretStoreBackend,
    path: &Path,
    req: &ProvisionRequest,
) -> Result<Provisioned, SentrisError> {
    let mut ledger = RotationLedger::load_from(path)?;
    if let Some(done) = resume_existing(rotator, &mut ledger, path, req.fingerprint)? {
        return Ok(done);
    }
    let mut plan = rotator.plan(req.old_secret)?;
    plan.old_fingerprint = req.fingerprint.to_string();
    let id = new_rotation_id()?;
    ledger.insert(RotationRecord::new(
        &id,
        req.backend_label,
        &plan,
        req.now,
        req.grace_secs,
    ))?;
    ledger.save_to(path)?;

    let mut minted = match rotator.mint(&plan) {
        Ok(m) => m,
        Err(e) => {
            persist(&mut ledger, path, &id, RotationState::RolledBack)?;
            return Err(e);
        }
    };
    ledger.record_new_key(&id, &minted.key_id)?;
    persist(&mut ledger, path, &id, RotationState::Minted)?;

    let stored = store_all(rotator, backend, req.base_var, &minted);
    Remediator::zeroize_secret_string(&mut minted.secret);
    if let Err(e) = stored {
        return Err(discard_after_failure(
            rotator,
            &mut ledger,
            path,
            &plan,
            &id,
            &minted.key_id,
            &e,
        ));
    }
    persist(&mut ledger, path, &id, RotationState::Stored)?;
    Ok(Provisioned { id, resumed: false })
}

fn store_all(
    rotator: &dyn Rotator,
    backend: &dyn SecretStoreBackend,
    base_var: &str,
    minted: &MintedCredential,
) -> Result<(), SentrisError> {
    let mut entries = rotator.env_values(base_var, minted);
    let mut result = Ok(());
    for (name, value) in entries.iter().rev() {
        if let Err(e) = backend.inject_secret(name, value, false) {
            result = Err(e);
            break;
        }
    }
    for (_, value) in entries.iter_mut() {
        Remediator::zeroize_secret_string(value);
    }
    result
}

fn discard_after_failure(
    rotator: &dyn Rotator,
    ledger: &mut RotationLedger,
    path: &Path,
    plan: &RotationPlan,
    id: &str,
    new_key_id: &str,
    cause: &SentrisError,
) -> SentrisError {
    match rotator.discard_new(plan, new_key_id) {
        Ok(()) => {
            let note = persist(ledger, path, id, RotationState::RolledBack)
                .err()
                .map(|e| format!(" (ledger update failed: {e})"))
                .unwrap_or_default();
            SentrisError::Scan(format!(
                "Storing the new credential failed ({cause}); the new key {new_key_id} was deleted again and the old key is untouched{note}"
            ))
        }
        Err(discard) => SentrisError::Scan(format!(
            "Storing the new credential failed ({cause}) and deleting the new key {new_key_id} also failed ({discard}); remove it with `sentris rotate undo {id}` or in the provider console"
        )),
    }
}

fn resume_existing(
    rotator: &dyn Rotator,
    ledger: &mut RotationLedger,
    path: &Path,
    fingerprint: &str,
) -> Result<Option<Provisioned>, SentrisError> {
    let Some(rec) = ledger.active_for(fingerprint).cloned() else {
        return Ok(None);
    };
    match rec.state {
        RotationState::Stored => Ok(Some(Provisioned {
            id: rec.id,
            resumed: true,
        })),
        RotationState::Minted => {
            let orphan = rec.new_key_id.clone().ok_or_else(|| {
                SentrisError::Scan(format!("Rotation {} is Minted without a key id", rec.id))
            })?;
            rotator.discard_new(&rec.plan(), &orphan)?;
            persist(ledger, path, &rec.id, RotationState::RolledBack)?;
            Ok(None)
        }
        RotationState::Planned => Err(SentrisError::Refused(format!(
            "Rotation {} was interrupted before its outcome was recorded; a new key may already exist at the provider. Check there, then run `sentris rotate undo {}`",
            rec.id, rec.id
        ))),
        _ => Err(SentrisError::Refused(format!(
            "Rotation {} already deactivated the old key; remediate any remaining findings without --rotate",
            rec.id
        ))),
    }
}

/// Deactivates the old key once the grace window has passed and the provider shows no use since the rotation began.
pub fn finish(
    rotator: &dyn Rotator,
    path: &Path,
    id: &str,
    now: u64,
    force: bool,
) -> Result<(), SentrisError> {
    let mut ledger = RotationLedger::load_from(path)?;
    let rec = load_record(&ledger, id)?;
    if rec.state != RotationState::Stored {
        return Err(SentrisError::Refused(format!(
            "Rotation {id} is {:?}; only a Stored rotation can be finished",
            rec.state
        )));
    }
    let plan = rec.plan();
    if !force {
        if now < rec.grace_until {
            return Err(SentrisError::Refused(format!(
                "Grace window ends {}; wait, or pass --force to deactivate the old key now",
                format_utc(rec.grace_until)
            )));
        }
        if let Some(LastUse {
            at,
            service,
            region,
        }) = rotator.last_used(&plan)?
        {
            if at > rec.created_at {
                return Err(SentrisError::Refused(format!(
                    "The old key was last used {} via {service} in {region}, after this rotation began: either your app has not switched to the new key or someone else is using the leaked one. Provider last-used data can lag; pass --force to deactivate anyway",
                    format_utc(at)
                )));
            }
        }
    }
    rotator.deactivate_old(&plan)?;
    persist(&mut ledger, path, id, RotationState::OldDeactivated)
}

/// Permanently removes the old key; only allowed after it has been deactivated.
pub fn delete_old(rotator: &dyn Rotator, path: &Path, id: &str) -> Result<(), SentrisError> {
    let mut ledger = RotationLedger::load_from(path)?;
    let rec = load_record(&ledger, id)?;
    if rec.state != RotationState::OldDeactivated {
        return Err(SentrisError::Refused(format!(
            "Rotation {id} is {:?}; the old key can only be deleted after `rotate finish`",
            rec.state
        )));
    }
    rotator.delete_old(&rec.plan())?;
    persist(&mut ledger, path, id, RotationState::OldDeleted)
}

/// Reverses a rotation: reactivates the old key (if deactivated) and deletes the new one.
pub fn undo(rotator: &dyn Rotator, path: &Path, id: &str) -> Result<(), SentrisError> {
    let mut ledger = RotationLedger::load_from(path)?;
    let rec = load_record(&ledger, id)?;
    let plan = rec.plan();
    match rec.state {
        RotationState::Planned => {}
        RotationState::Minted | RotationState::Stored => discard(rotator, &plan, &rec)?,
        RotationState::OldDeactivated => {
            rotator.reactivate_old(&plan)?;
            discard(rotator, &plan, &rec)?;
        }
        RotationState::OldDeleted | RotationState::RolledBack => {
            return Err(SentrisError::Refused(format!(
                "Rotation {id} is {:?} and cannot be undone",
                rec.state
            )))
        }
    }
    persist(&mut ledger, path, id, RotationState::RolledBack)
}

fn discard(
    rotator: &dyn Rotator,
    plan: &RotationPlan,
    rec: &RotationRecord,
) -> Result<(), SentrisError> {
    match &rec.new_key_id {
        Some(k) => rotator.discard_new(plan, k),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediator::backend::SecretStoreBackend;
    use std::path::Path;
    use std::sync::Mutex;

    const NEW_SECRET: &str = "NEWSECRETVALUE-do-not-leak";

    struct FakeRotator {
        calls: Mutex<Vec<String>>,
        fail_discard: bool,
        last_use: Option<LastUse>,
        ledger_path: std::path::PathBuf,
    }

    impl FakeRotator {
        fn new(ledger_path: &Path) -> Self {
            Self {
                calls: Mutex::new(vec![]),
                fail_discard: false,
                last_use: None,
                ledger_path: ledger_path.to_path_buf(),
            }
        }
        fn log(&self, s: &str) {
            self.calls.lock().unwrap().push(s.to_string());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn count(&self, prefix: &str) -> usize {
            self.calls()
                .iter()
                .filter(|c| c.starts_with(prefix))
                .count()
        }
    }

    impl Rotator for FakeRotator {
        fn provider_name(&self) -> &'static str {
            "Fake"
        }
        fn plan(&self, _old: &str) -> Result<RotationPlan, SentrisError> {
            self.log("plan");
            Ok(RotationPlan {
                provider: "Fake".into(),
                rule_id: "fake-key".into(),
                principal: "bob".into(),
                old_key_id: "OLDKEY".into(),
                old_fingerprint: "ignored".into(),
            })
        }
        fn mint(&self, _p: &RotationPlan) -> Result<MintedCredential, SentrisError> {
            let on_disk = std::fs::read_to_string(&self.ledger_path).unwrap_or_default();
            assert!(
                on_disk.contains("Planned"),
                "ledger must be saved before mint"
            );
            self.log("mint");
            Ok(MintedCredential {
                key_id: "NEWKEY".into(),
                secret: NEW_SECRET.into(),
            })
        }
        fn deactivate_old(&self, _p: &RotationPlan) -> Result<(), SentrisError> {
            self.log("deactivate_old");
            Ok(())
        }
        fn reactivate_old(&self, _p: &RotationPlan) -> Result<(), SentrisError> {
            self.log("reactivate_old");
            Ok(())
        }
        fn discard_new(&self, _p: &RotationPlan, id: &str) -> Result<(), SentrisError> {
            self.log(&format!("discard_new {id}"));
            if self.fail_discard {
                return Err(SentrisError::Scan("iam down".into()));
            }
            Ok(())
        }
        fn delete_old(&self, _p: &RotationPlan) -> Result<(), SentrisError> {
            self.log("delete_old");
            Ok(())
        }
        fn last_used(&self, _p: &RotationPlan) -> Result<Option<LastUse>, SentrisError> {
            Ok(self.last_use.clone())
        }
        fn env_values(&self, base_var: &str, m: &MintedCredential) -> Vec<(String, String)> {
            vec![
                (base_var.to_string(), m.key_id.clone()),
                (format!("{base_var}_SECRET"), m.secret.clone()),
            ]
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        stored: Mutex<Vec<(String, String)>>,
        fail_on: Option<String>,
    }

    impl SecretStoreBackend for FakeBackend {
        fn backend_name(&self) -> &'static str {
            "Fake"
        }
        fn inject_secret(
            &self,
            key: &str,
            secret: &str,
            _dry: bool,
        ) -> Result<String, SentrisError> {
            if self.fail_on.as_deref() == Some(key) {
                return Err(SentrisError::Scan("vault sealed".into()));
            }
            self.stored
                .lock()
                .unwrap()
                .push((key.into(), secret.into()));
            Ok("ok".into())
        }
    }

    fn req() -> ProvisionRequest<'static> {
        ProvisionRequest {
            old_secret: "OLDKEY",
            fingerprint: "fp_abc",
            base_var: "SVC_KEY",
            backend_label: "fake",
            now: 1_000,
            grace_secs: 100,
        }
    }

    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotation_ledger.json");
        (dir, path)
    }

    fn state_of(path: &Path, id: &str) -> RotationState {
        RotationLedger::load_from(path)
            .unwrap()
            .get(id)
            .unwrap()
            .state
    }

    fn with_env<T>(f: impl FnOnce() -> T) -> T {
        let _g = crate::keystore::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let state = tempfile::tempdir().unwrap();
        std::env::set_var("SENTRIS_STATE_DIR", state.path());
        f()
    }

    #[test]
    fn provision_mints_stores_and_leaves_old_key_active() {
        with_env(|| {
            let (_d, path) = setup();
            let (rot, be) = (FakeRotator::new(&path), FakeBackend::default());
            let out = provision(&rot, &be, &path, &req()).unwrap();
            assert!(!out.resumed);
            assert_eq!(state_of(&path, &out.id), RotationState::Stored);
            assert_eq!(rot.count("deactivate_old"), 0);
            let stored = be.stored.lock().unwrap().clone();
            assert!(stored.contains(&("SVC_KEY".into(), "NEWKEY".into())));
            assert!(stored.contains(&("SVC_KEY_SECRET".into(), NEW_SECRET.into())));
            let disk = std::fs::read_to_string(&path).unwrap();
            assert!(!disk.contains(NEW_SECRET));
            let rec = RotationLedger::load_from(&path).unwrap();
            let r = rec.get(&out.id).unwrap();
            assert_eq!(r.new_key_id.as_deref(), Some("NEWKEY"));
            assert_eq!(r.old_fingerprint, "fp_abc");
        });
    }

    #[test]
    fn store_failure_discards_the_new_key() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let be = FakeBackend {
                fail_on: Some("SVC_KEY".into()),
                ..Default::default()
            };
            let err = provision(&rot, &be, &path, &req()).unwrap_err().to_string();
            assert!(err.contains("vault sealed"), "{err}");
            assert_eq!(rot.count("discard_new NEWKEY"), 1);
            let ledger = RotationLedger::load_from(&path).unwrap();
            assert_eq!(ledger.records[0].state, RotationState::RolledBack);
        });
    }

    #[test]
    fn store_failure_with_failed_discard_names_the_orphan_key() {
        with_env(|| {
            let (_d, path) = setup();
            let mut rot = FakeRotator::new(&path);
            rot.fail_discard = true;
            let be = FakeBackend {
                fail_on: Some("SVC_KEY".into()),
                ..Default::default()
            };
            let err = provision(&rot, &be, &path, &req()).unwrap_err().to_string();
            assert!(
                err.contains("NEWKEY") && err.contains("rotate undo"),
                "{err}"
            );
            assert_eq!(
                RotationLedger::load_from(&path).unwrap().records[0].state,
                RotationState::Minted
            );
        });
    }

    #[test]
    fn rerun_after_stored_does_not_mint_again() {
        with_env(|| {
            let (_d, path) = setup();
            let (rot, be) = (FakeRotator::new(&path), FakeBackend::default());
            let first = provision(&rot, &be, &path, &req()).unwrap();
            let second = provision(&rot, &be, &path, &req()).unwrap();
            assert_eq!(first.id, second.id);
            assert!(second.resumed);
            assert_eq!(rot.count("mint"), 1);
        });
    }

    #[test]
    fn rerun_after_crash_in_minted_discards_orphan_then_mints_once() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let mut ledger = RotationLedger::default();
            let plan = rot.plan("OLDKEY").unwrap();
            let mut rec = RotationRecord::new("rot_old", "fake", &plan, 1, 1);
            rec.old_fingerprint = "fp_abc".into();
            ledger.insert(rec).unwrap();
            ledger.record_new_key("rot_old", "ORPHAN").unwrap();
            ledger.advance("rot_old", RotationState::Minted).unwrap();
            ledger.save_to(&path).unwrap();

            let be = FakeBackend::default();
            let out = provision(&rot, &be, &path, &req()).unwrap();
            assert_ne!(out.id, "rot_old");
            assert_eq!(rot.count("discard_new ORPHAN"), 1);
            assert_eq!(rot.count("mint"), 1);
            assert_eq!(state_of(&path, "rot_old"), RotationState::RolledBack);
        });
    }

    #[test]
    fn rerun_after_crash_in_planned_refuses_instead_of_minting_blind() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let mut ledger = RotationLedger::default();
            let plan = rot.plan("OLDKEY").unwrap();
            let mut rec = RotationRecord::new("rot_stuck", "fake", &plan, 1, 1);
            rec.old_fingerprint = "fp_abc".into();
            ledger.insert(rec).unwrap();
            ledger.save_to(&path).unwrap();
            let err = provision(&rot, &FakeBackend::default(), &path, &req())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("rot_stuck") && err.contains("rotate undo"),
                "{err}"
            );
            assert_eq!(rot.count("mint"), 0);
        });
    }

    fn stored_rotation(rot: &FakeRotator, path: &Path) -> String {
        provision(rot, &FakeBackend::default(), path, &req())
            .unwrap()
            .id
    }

    #[test]
    fn finish_refuses_before_grace_ends_unless_forced() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let id = stored_rotation(&rot, &path);
            let err = finish(&rot, &path, &id, 1_050, false).unwrap_err();
            assert!(matches!(err, SentrisError::Refused(_)), "{err}");
            assert_eq!(rot.count("deactivate_old"), 0);
            finish(&rot, &path, &id, 1_050, true).unwrap();
            assert_eq!(rot.count("deactivate_old"), 1);
            assert_eq!(state_of(&path, &id), RotationState::OldDeactivated);
        });
    }

    #[test]
    fn finish_refuses_when_old_key_was_used_since_rotation_began() {
        with_env(|| {
            let (_d, path) = setup();
            let mut rot = FakeRotator::new(&path);
            let id = stored_rotation(&rot, &path);
            rot.last_use = Some(LastUse {
                at: 1_080,
                service: "s3".into(),
                region: "us-east-1".into(),
            });
            let err = finish(&rot, &path, &id, 2_000, false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("s3") && err.contains("us-east-1"), "{err}");
            assert_eq!(rot.count("deactivate_old"), 0);
        });
    }

    #[test]
    fn finish_after_grace_with_idle_old_key_deactivates_it() {
        with_env(|| {
            let (_d, path) = setup();
            let mut rot = FakeRotator::new(&path);
            let id = stored_rotation(&rot, &path);
            rot.last_use = Some(LastUse {
                at: 500,
                service: "s3".into(),
                region: "us-east-1".into(),
            });
            finish(&rot, &path, &id, 2_000, false).unwrap();
            assert_eq!(state_of(&path, &id), RotationState::OldDeactivated);
        });
    }

    #[test]
    fn delete_old_only_from_deactivated() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let id = stored_rotation(&rot, &path);
            assert!(delete_old(&rot, &path, &id).is_err());
            finish(&rot, &path, &id, 2_000, false).unwrap();
            delete_old(&rot, &path, &id).unwrap();
            assert_eq!(state_of(&path, &id), RotationState::OldDeleted);
        });
    }

    #[test]
    fn undo_after_finish_reactivates_old_and_discards_new() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let id = stored_rotation(&rot, &path);
            finish(&rot, &path, &id, 2_000, false).unwrap();
            undo(&rot, &path, &id).unwrap();
            assert_eq!(rot.count("reactivate_old"), 1);
            assert_eq!(rot.count("discard_new NEWKEY"), 1);
            assert_eq!(state_of(&path, &id), RotationState::RolledBack);
        });
    }

    #[test]
    fn undo_of_a_planned_rotation_touches_nothing() {
        with_env(|| {
            let (_d, path) = setup();
            let rot = FakeRotator::new(&path);
            let mut ledger = RotationLedger::default();
            let plan = rot.plan("OLDKEY").unwrap();
            ledger
                .insert(RotationRecord::new("rot_p", "fake", &plan, 1, 1))
                .unwrap();
            ledger.save_to(&path).unwrap();
            undo(&rot, &path, "rot_p").unwrap();
            assert_eq!(rot.count("discard_new"), 0);
            assert_eq!(state_of(&path, "rot_p"), RotationState::RolledBack);
        });
    }
}
