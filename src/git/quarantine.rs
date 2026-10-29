use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::error::SentrisError;
use crate::model::Finding;

#[derive(Debug, Clone)]
pub struct QuarantineReport {
    pub session_id: String,
    pub rule_id: String,
    pub target_file: String,
    pub line_number: usize,
    pub commit_hash: Option<String>,
    pub branch_name: String,
    pub playbook_path: PathBuf,
}

pub struct QuarantineManager;

impl QuarantineManager {
    /// Creates a Zone 3 isolated quarantine branch and generates an actionable history scrub playbook
    #[allow(clippy::too_many_lines)]
    pub fn quarantine_finding(
        finding: &Finding,
        custom_branch: Option<&str>,
        base_dir: Option<&Path>,
    ) -> Result<QuarantineReport, SentrisError> {
        let base = base_dir.unwrap_or_else(|| Path::new("."));
        let short_id = if finding.fingerprint.len() >= 8 {
            &finding.fingerprint[..8]
        } else {
            &finding.fingerprint
        };
        let session_id = format!("qz_{short_id}");

        if custom_branch.is_some_and(|b| b.starts_with('-')) {
            return Err(SentrisError::Scan(
                "Invalid branch name: must not start with '-'".to_string(),
            ));
        }
        let branch_name = match custom_branch {
            Some(b) => b.to_string(),
            None => format!("sentris/quarantine-{short_id}"),
        };

        // Create the quarantine branch using git branch
        let branch_status = Command::new("git")
            .current_dir(base)
            .args(["branch", &branch_name])
            .output();

        let _branch_created = match branch_status {
            Ok(output) => output.status.success(),
            Err(_) => false,
        };

        // Create .sentris directory for artifacts
        let sentris_dir = base.join(".sentris");
        if !sentris_dir.exists() {
            fs::create_dir_all(&sentris_dir)?;
        }

        let playbook_path = sentris_dir.join(format!("quarantine_{session_id}_playbook.md"));

        let commit_section = if let Some(hash) = &finding.commit_hash {
            format!("* **Offending Commit Hash:** `{hash}`\n")
        } else {
            "* **Scope:** Working Tree / Local Staging\n".to_string()
        };

        let now_str = {
            let now = SystemTime::now();
            let duration = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}", duration.as_secs())
        };

        let playbook_content = format!(
            r#"# 🛡️ Sentris Zone 3 Quarantine & Scrub Playbook
**Session ID:** `{session_id}`  
**Generated At (Epoch):** `{now_str}`  
**Target Rule:** `{rule_id}`  
**File Location:** `{file_path}:{line_number}`  
{commit_section}**Quarantine Branch:** `{branch_name}`  

---

## ⚠️ CRITICAL SAFETY NOTICE: NO BLIND FORCE-PUSH
> **Rule 3 Invariant:** Never run blind `git push --force` against remote shared branches.
> Blind force-pushes overwrite colleagues' work, destroy branch histories, and trigger high-severity team outages.

---

## Step-by-Step Remediation Protocol

### Step 1: Invalidate & Rotate Live Credential
Regardless of git history cleaning, once a secret is committed, **assume it has already been scraped**.
1. Invalidate or rotate the credential immediately at the provider dashboard (e.g. Stripe, AWS, GitHub).
2. If this is a supported provider, use automated dual-key rotation:
   ```bash
   sentris remediate {file_path}
   ```

### Step 2: History Scrubbing Protocol (Team Window Required)
Schedule a planned maintenance window with all active repository contributors.
To cleanly purge this credential across all commits, use `git-filter-repo` (recommended by Git):

```bash
# 1. Install git-filter-repo (if not already installed)
pip install git-filter-repo

# 2. Scrub specific literal or file pattern from history:
# (Replace SECRET_PREVIEW with the exact leaked token)
git filter-repo --replace-text <(echo "{preview}==>[REDACTED_BY_SENTRIS]")

# 3. Verify clean status locally:
sentris scan --git-history --fail-on-secret
```

### Step 3: Collaborative Remote Synchronization
After history has been rewritten locally:
1. Notify your team to commit or stash any pending local work.
2. Push using lease protection rather than unconditional force:
   ```bash
   git push origin <branch-name> --force-with-lease
   ```
3. Instruct team members to re-sync cleanly:
   ```bash
   git fetch origin
   git rebase origin/<branch-name>
   ```

### Step 4: Verification & Sign-Off
Confirm complete eradication of the secret:
```bash
sentris scan --git-history
```
"#,
            session_id = session_id,
            now_str = now_str,
            rule_id = finding.rule_id,
            file_path = finding.file_path,
            line_number = finding.line_number,
            commit_section = commit_section,
            branch_name = branch_name,
            preview = finding.redacted_match,
        );

        fs::write(&playbook_path, playbook_content)?;

        Ok(QuarantineReport {
            session_id,
            rule_id: finding.rule_id.clone(),
            target_file: finding.file_path.clone(),
            line_number: finding.line_number,
            commit_hash: finding.commit_hash.clone(),
            branch_name,
            playbook_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use tempfile::tempdir;

    #[test]
    fn test_quarantine_playbook_generation() {
        let dir = tempdir().unwrap();
        let finding = Finding {
            rule_id: "stripe-secret-key".to_string(),
            description: "Stripe Secret Key".to_string(),
            severity: Severity::Critical,
            file_path: "src/billing.ts".to_string(),
            line_number: 10,
            column: 5,
            redacted_match: "sk_live_...1234".to_string(),
            entropy: 4.8,
            fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            commit_hash: Some("abcdef1234567890".to_string()),
            commit_author: None,
            commit_date: None,
        };

        let report =
            QuarantineManager::quarantine_finding(&finding, None, Some(dir.path())).unwrap();
        assert_eq!(report.branch_name, "sentris/quarantine-01234567");
        assert!(report.playbook_path.exists());

        let content = fs::read_to_string(&report.playbook_path).unwrap();
        assert!(content.contains("CRITICAL SAFETY NOTICE"));
        assert!(content.contains("abcdef1234567890"));
        assert!(content.contains("sentris/quarantine-01234567"));
    }
}
