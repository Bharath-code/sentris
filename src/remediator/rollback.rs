use crate::error::SentrisError;
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
}

impl RollbackLedger {
    pub fn ledger_path() -> PathBuf {
        Path::new(".sentris").join("rollback_ledger.json")
    }

    /// Loads the rollback ledger from `.sentris/rollback_ledger.json`
    pub fn load() -> Result<Self, SentrisError> {
        let path = Self::ledger_path();
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)?;
        let ledger: Self = serde_json::from_str(&content).unwrap_or_default();
        Ok(ledger)
    }

    /// Saves a new rollback transaction entry
    pub fn record_transaction(&mut self, entry: RollbackEntry) -> Result<(), SentrisError> {
        let sentris_dir = Path::new(".sentris");
        if !sentris_dir.exists() {
            fs::create_dir_all(sentris_dir)?;
        }

        self.transactions.push(entry);
        let serialized = serde_json::to_string_pretty(self)?;
        fs::write(Self::ledger_path(), serialized)?;
        Ok(())
    }

    /// Reverts a specific remediation session using the saved transaction entry
    pub fn revert(&mut self, session_id: &str) -> Result<String, SentrisError> {
        let entry_idx = self
            .transactions
            .iter()
            .position(|t| t.session_id == session_id)
            .ok_or_else(|| {
                SentrisError::Scan(format!(
                    "Remediation session '{}' not found in rollback ledger.",
                    session_id
                ))
            })?;

        let entry = &self.transactions[entry_idx];
        let file_path = Path::new(&entry.file_path);

        if !file_path.exists() {
            return Err(SentrisError::Scan(format!(
                "Target file '{}' no longer exists on disk.",
                entry.file_path
            )));
        }

        // Restore original line in file
        let content = fs::read_to_string(file_path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        if entry.line_number > 0 && entry.line_number <= lines.len() {
            lines[entry.line_number - 1] = entry.original_line.clone();
            let restored = lines.join("\n") + "\n";
            fs::write(file_path, restored)?;
        } else {
            // Line index shifted: perform string replacement fallback
            let restored = content.replace(&entry.replacement_line, &entry.original_line);
            fs::write(file_path, restored)?;
        }

        let msg = format!(
            "✔ Successfully rolled back session '{}'. Restored '{}' to original state.",
            session_id, entry.file_path
        );

        // Remove from ledger after revert
        self.transactions.remove(entry_idx);
        let serialized = serde_json::to_string_pretty(self)?;
        fs::write(Self::ledger_path(), serialized)?;

        Ok(msg)
    }
}
