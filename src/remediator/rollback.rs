use crate::error::SentrisError;
use crate::fsutil::{split_eol, write_atomic};
use crate::keystore;
use crate::remediator::backend::write_private;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackEntry {
    pub session_id: String,
    pub timestamp: String,
    pub file_path: String,
    pub line_number: usize,
    pub original_line: String,
    pub replacement_line: String,
    pub backup_branch: String,
    pub provider: String,
    pub secret_fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RollbackLedger {
    pub transactions: Vec<RollbackEntry>,
    /// HMAC over `transactions` with a per-user key kept outside the repo; a ledger shipped inside a cloned repo cannot forge it.
    #[serde(default)]
    pub mac: String,
}

impl RollbackLedger {
    pub fn ledger_path() -> PathBuf {
        Path::new(".sentris").join("rollback_ledger.json")
    }

    fn compute_mac(&self) -> Result<String, SentrisError> {
        keystore::mac_hex("rollback", &serde_json::to_vec(&self.transactions)?)
    }

    /// Loads and authenticates the rollback ledger from `.sentris/rollback_ledger.json`
    pub fn load() -> Result<Self, SentrisError> {
        Self::load_from(&Self::ledger_path())
    }

    pub fn load_from(path: &Path) -> Result<Self, SentrisError> {
        crate::fsutil::reject_symlinks(path)?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let ledger: Self = serde_json::from_str(&fs::read_to_string(path)?).map_err(|e| {
            SentrisError::Scan(format!(
                "Rollback ledger {} is unreadable ({e}); not overwriting it",
                path.display()
            ))
        })?;
        if !keystore::ct_eq(&ledger.mac, &ledger.compute_mac()?) {
            return Err(SentrisError::Scan(format!(
                "Rollback ledger {} failed authentication (edited, or created on another machine); refusing to act on it",
                path.display()
            )));
        }
        Ok(ledger)
    }

    fn save_to(&mut self, path: &Path) -> Result<(), SentrisError> {
        self.mac = self.compute_mac()?;
        write_private(path, &serde_json::to_string_pretty(self)?)
    }

    /// Saves a new rollback transaction entry
    pub fn record_transaction(&mut self, entry: RollbackEntry) -> Result<(), SentrisError> {
        self.transactions.push(entry);
        self.save_to(&Self::ledger_path())
    }

    /// Reverts a specific remediation session using the saved transaction entry
    pub fn revert(&mut self, session_id: &str) -> Result<String, SentrisError> {
        self.revert_at(session_id, &Self::ledger_path(), &std::env::current_dir()?)
    }

    pub fn revert_at(
        &mut self,
        session_id: &str,
        ledger_path: &Path,
        workspace: &Path,
    ) -> Result<String, SentrisError> {
        let entry_idx = self
            .transactions
            .iter()
            .position(|t| t.session_id == session_id)
            .ok_or_else(|| {
                SentrisError::Scan(format!(
                    "Remediation session '{session_id}' not found in rollback ledger."
                ))
            })?;
        let entry = self.transactions[entry_idx].clone();
        crate::fsutil::reject_symlinks(ledger_path)?;

        let workspace = workspace.canonicalize()?;
        let canonical = workspace
            .join(&entry.file_path)
            .canonicalize()
            .map_err(|_| {
                SentrisError::Scan(format!(
                    "Target file '{}' no longer exists on disk.",
                    entry.file_path
                ))
            })?;
        if !canonical.starts_with(&workspace) {
            return Err(SentrisError::Scan(format!(
                "Refusing to touch '{}': outside the current workspace",
                entry.file_path
            )));
        }

        let content = fs::read_to_string(&canonical)?;
        let segs: Vec<&str> = content.split_inclusive('\n').collect();
        let line_at = |i: usize| segs.get(i).map(|s| split_eol(s).0);

        // The remediated line must still be there unmodified; never overwrite a user's later edits
        let hint = entry.line_number.saturating_sub(1);
        let idx = if line_at(hint) == Some(entry.replacement_line.as_str()) {
            hint
        } else {
            let matches: Vec<usize> = (0..segs.len())
                .filter(|&i| line_at(i) == Some(entry.replacement_line.as_str()))
                .collect();
            match matches.as_slice() {
                [only] => *only,
                [] => {
                    return Err(SentrisError::Scan(format!(
                        "Line {} of '{}' no longer matches what Sentris wrote; not restoring over your edits",
                        entry.line_number, entry.file_path
                    )))
                }
                _ => {
                    return Err(SentrisError::Scan(format!(
                        "Ambiguous: remediated line appears {} times in '{}'; restore it manually",
                        matches.len(),
                        entry.file_path
                    )))
                }
            }
        };

        let eol = split_eol(segs[idx]).1;
        let restored = format!(
            "{}{}{eol}{}",
            segs[..idx].concat(),
            entry.original_line,
            segs[idx + 1..].concat()
        );
        write_atomic(&canonical, &restored)?;

        self.transactions.remove(entry_idx);
        self.save_to(ledger_path)?;

        Ok(format!(
            "✔ Successfully rolled back session '{session_id}'. Restored '{}' to original state.",
            entry.file_path
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(file: &str, line: usize, orig: &str, repl: &str) -> RollbackEntry {
        RollbackEntry {
            session_id: "rm_test".into(),
            timestamp: "0".into(),
            file_path: file.into(),
            line_number: line,
            original_line: orig.into(),
            replacement_line: repl.into(),
            backup_branch: "b".into(),
            provider: "p".into(),
            secret_fingerprint: "f".into(),
        }
    }

    // Tests share process-global cwd/env, so run the scenarios sequentially in one test
    #[test]
    fn rollback_scenarios() {
        let state = tempfile::tempdir().unwrap();
        std::env::set_var("SENTRIS_STATE_DIR", state.path());
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let p = |n: &str| ws.join(n).to_string_lossy().into_owned();
        let ledger = dir.path().join("ledger.json");

        // CRLF round trip is byte-identical
        let src = "a = 1\r\nkey = \"sk_live_1\"\r\nb = 2\r\n";
        fs::write(
            p("f.py"),
            "a = 1\r\nkey = os.environ.get(\"K\")\r\nb = 2\r\n",
        )
        .unwrap();
        let mut l = RollbackLedger::default();
        l.transactions.push(entry(
            "f.py",
            2,
            "key = \"sk_live_1\"",
            "key = os.environ.get(\"K\")",
        ));
        l.save_to(&ledger).unwrap();
        let mut l = RollbackLedger::load_from(&ledger).unwrap();
        l.revert_at("rm_test", &ledger, ws).unwrap();
        assert_eq!(fs::read_to_string(p("f.py")).unwrap(), src);

        // Multi-line original block restores byte-identically
        let block = "k = `-----BEGIN X-----\nAAA\n-----END X-----`";
        fs::write(p("g.ts"), "k = process.env.K;\nnext();\n").unwrap();
        let mut l = RollbackLedger::default();
        l.transactions
            .push(entry(&p("g.ts"), 1, block, "k = process.env.K;"));
        l.save_to(&ledger).unwrap();
        let mut l = RollbackLedger::load_from(&ledger).unwrap();
        l.revert_at("rm_test", &ledger, ws).unwrap();
        assert_eq!(
            fs::read_to_string(p("g.ts")).unwrap(),
            format!("{block}\nnext();\n")
        );

        // User edited the line afterwards: refuse, file untouched
        fs::write(p("h.py"), "key = changed_by_user\n").unwrap();
        let mut l = RollbackLedger::default();
        l.transactions.push(entry(
            "h.py",
            1,
            "key = \"s\"",
            "key = os.environ.get(\"K\")",
        ));
        l.save_to(&ledger).unwrap();
        let mut l = RollbackLedger::load_from(&ledger).unwrap();
        assert!(l.revert_at("rm_test", &ledger, ws).is_err());
        assert_eq!(
            fs::read_to_string(p("h.py")).unwrap(),
            "key = changed_by_user\n"
        );

        // Tampered ledger is rejected
        let tampered = fs::read_to_string(&ledger)
            .unwrap()
            .replace("h.py", "../../etc/hosts");
        fs::write(&ledger, tampered).unwrap();
        assert!(RollbackLedger::load_from(&ledger).is_err());

        // A forged-but-consistently-shaped ledger without our key is rejected
        fs::write(
            &ledger,
            r#"{"transactions":[{"session_id":"x","timestamp":"0","file_path":"/etc/hosts","line_number":1,"original_line":"pwn","replacement_line":"a","backup_branch":"b","provider":"p","secret_fingerprint":"f"}],"mac":""}"#,
        )
        .unwrap();
        assert!(RollbackLedger::load_from(&ledger).is_err());

        // A symlinked .sentris dir or ledger file is never followed
        #[cfg(unix)]
        {
            let elsewhere = tempfile::tempdir().unwrap();
            let victim = elsewhere.path().join("victim.txt");
            fs::write(&victim, "precious").unwrap();
            let link = ws.join("planted.json");
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            let mut l = RollbackLedger::default();
            assert!(l.save_to(&link).is_err());
            assert!(RollbackLedger::load_from(&link).is_err());
            assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        }

        // Even a validly signed entry outside the workspace is refused
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("rc");
        fs::write(&target, "evil\n").unwrap();
        let mut l = RollbackLedger::default();
        l.transactions
            .push(entry(target.to_str().unwrap(), 1, "pwn", "evil"));
        l.save_to(&ledger).unwrap();
        let mut l = RollbackLedger::load_from(&ledger).unwrap();
        assert!(l.revert_at("rm_test", &ledger, ws).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "evil\n");
    }
}
