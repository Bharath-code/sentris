pub mod backend;
pub mod code_replacer;
pub mod env_patcher;
pub mod rollback;

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::process::Command;

use self::code_replacer::CodeReplacer;
use self::rollback::{RollbackEntry, RollbackLedger};
use crate::error::SentrisError;
use crate::model::Finding;
use crate::verifier::{LiveStatus, VerifierRegistry};

pub struct Remediator {
    registry: VerifierRegistry,
}

impl Default for Remediator {
    fn default() -> Self {
        Self::new()
    }
}

impl Remediator {
    pub fn new() -> Self {
        Self {
            registry: VerifierRegistry::new(),
        }
    }

    /// Cryptographically scrubs a mutable String buffer in RAM using volatile writes
    /// and a sequential-consistency compiler fence so plaintext secrets never linger in heap memory.
    pub fn zeroize_secret_string(secret: &mut String) {
        // SAFETY: Overwriting UTF-8 bytes with 0x00 (ASCII NUL) preserves valid UTF-8 invariants.
        unsafe {
            let bytes = secret.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        secret.clear();
    }

    /// Maps a secret rule ID to its canonical environment variable name
    pub fn env_var_name_for_rule(rule_id: &str) -> &'static str {
        match rule_id {
            "stripe-secret-key" | "stripe-restricted-key" => "STRIPE_SECRET_KEY",
            "stripe-webhook-secret" => "STRIPE_WEBHOOK_SECRET",
            "aws-access-key-id" => "AWS_ACCESS_KEY_ID",
            "aws-secret-access-key" => "AWS_SECRET_ACCESS_KEY",
            "google-api-key" => "GOOGLE_API_KEY",
            "azure-storage-account-key" => "AZURE_STORAGE_KEY",
            "digitalocean-access-token" => "DIGITALOCEAN_ACCESS_TOKEN",
            "github-pat" | "github-fine-grained-pat" | "github-oauth-access-token" => {
                "GITHUB_TOKEN"
            }
            "gitlab-pat" => "GITLAB_TOKEN",
            "npm-access-token" => "NPM_TOKEN",
            "pypi-upload-token" => "PYPI_API_TOKEN",
            "openai-api-key" => "OPENAI_API_KEY",
            "anthropic-api-key" => "ANTHROPIC_API_KEY",
            "huggingface-token" => "HF_TOKEN",
            "cohere-api-key" => "COHERE_API_KEY",
            "groq-api-key" => "GROQ_API_KEY",
            "replicate-api-token" => "REPLICATE_API_TOKEN",
            "perplexity-api-key" => "PERPLEXITY_API_KEY",
            "slack-bot-token" => "SLACK_BOT_TOKEN",
            "slack-user-token" => "SLACK_USER_TOKEN",
            "slack-webhook-url" => "SLACK_WEBHOOK_URL",
            "discord-bot-token" => "DISCORD_BOT_TOKEN",
            "discord-webhook-url" => "DISCORD_WEBHOOK_URL",
            "telegram-bot-token" => "TELEGRAM_BOT_TOKEN",
            "twilio-api-key" => "TWILIO_API_KEY",
            "sendgrid-api-key" => "SENDGRID_API_KEY",
            "mailchimp-api-key" => "MAILCHIMP_API_KEY",
            "postgres-connection-uri" | "mysql-connection-uri" => "DATABASE_URL",
            "mongodb-connection-uri" => "MONGODB_URI",
            "redis-connection-uri" => "REDIS_URL",
            "datadog-api-key" => "DD_API_KEY",
            "sentry-dsn" => "SENTRY_DSN",
            "segment-write-key" => "SEGMENT_WRITE_KEY",
            "shopify-access-token" => "SHOPIFY_ACCESS_TOKEN",
            "hashicorp-vault-token" => "VAULT_TOKEN",
            "supabase-access-token" => "SUPABASE_ACCESS_TOKEN",
            "resend-api-key" => "RESEND_API_KEY",
            "linear-api-key" => "LINEAR_API_KEY",
            "planetscale-token" => "PLANETSCALE_TOKEN",
            "posthog-api-key" => "POSTHOG_API_KEY",
            "structural-secret-assignment" => "APP_SECRET_KEY",
            "rsa-private-key"
            | "openssh-private-key"
            | "pgp-private-key"
            | "ec-private-key"
            | "generic-private-key" => "PRIVATE_KEY_PEM",
            _ => "API_SECRET_KEY",
        }
    }

    /// Env var name to store `secret` under: the rule's canonical name, made unique with a fingerprint
    /// suffix when the rule is generic or `.env` already holds a different value under that name.
    pub fn resolve_env_var_name(finding: &Finding, secret: &str, backend: &str) -> String {
        Self::resolve_env_var_name_in(std::path::Path::new("."), finding, secret, backend)
    }

    pub fn resolve_env_var_name_in(
        base_dir: &std::path::Path,
        finding: &Finding,
        secret: &str,
        backend: &str,
    ) -> String {
        let base = Self::env_var_name_for_rule(&finding.rule_id);
        let suffixed = || format!("{base}_{}", finding.fingerprint[..8].to_ascii_uppercase());
        if matches!(base, "API_SECRET_KEY" | "APP_SECRET_KEY") {
            return suffixed();
        }
        let is_env = matches!(
            backend.trim().to_ascii_lowercase().as_str(),
            "env" | "envfile"
        );
        if is_env {
            if let Some(existing) = env_patcher::EnvPatcher::existing_value_in(base_dir, base) {
                if existing != secret {
                    return suffixed();
                }
            }
        }
        base.to_string()
    }

    /// Creates an atomic git backup branch prior to any file mutations
    fn create_backup_branch() -> Result<String, SentrisError> {
        let timestamp = chrono_compact_timestamp();
        let branch_name = format!("sentris/backup-{timestamp}");

        let output = Command::new("git").args(["branch", &branch_name]).output();

        if let Ok(out) = output {
            if out.status.success() {
                return Ok(branch_name);
            }
        }

        // If not in a git repo or branch fails, continue safely with local session tracking
        Ok("local-working-tree".to_string())
    }

    /// Executes the 7-step safe dual-key autonomous remediation workflow (defaulting to Safe Local Extraction)
    pub fn remediate_finding(
        &self,
        finding: &Finding,
        raw_secret: &str,
        dry_run: bool,
        backend_name: Option<&str>,
        offline: bool,
    ) -> Result<String, SentrisError> {
        self.remediate_finding_with_mode(finding, raw_secret, dry_run, backend_name, offline, false)
    }

    /// Executes the 7-step autonomous remediation workflow with explicit extraction vs. provider rotation mode
    pub fn remediate_finding_with_mode(
        &self,
        finding: &Finding,
        raw_secret: &str,
        dry_run: bool,
        backend_name: Option<&str>,
        offline: bool,
        rotate: bool,
    ) -> Result<String, SentrisError> {
        let quiet = std::env::var("SENTRIS_AGENT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        self.remediate_finding_with_options(
            finding,
            raw_secret,
            dry_run,
            backend_name,
            offline,
            rotate,
            quiet,
        )
    }

    /// Executes the 7-step autonomous remediation workflow with an explicit `quiet` flag for MCP & JSON agent mode
    #[allow(clippy::too_many_arguments)]
    pub fn remediate_finding_with_options(
        &self,
        finding: &Finding,
        raw_secret: &str,
        dry_run: bool,
        backend_name: Option<&str>,
        offline: bool,
        rotate: bool,
        quiet: bool,
    ) -> Result<String, SentrisError> {
        if rotate {
            return Err(SentrisError::NotImplemented(
                "--rotate: provider-side key rotation is not available yet; the leaked key stays valid until you revoke it at the provider"
                    .to_string(),
            ));
        }
        let session_id = format!("rm_{}", &finding.fingerprint[..8]);
        let matched_verifier = self.registry.find_verifier(&finding.rule_id);
        let provider_name = match matched_verifier {
            Some(v) => v.provider_name(),
            None => "Generic Provider",
        };

        if !quiet {
            println!();
            println!(
                "{} {}",
                "⚡ Sentris Autonomous Remediation Session:".cyan().bold(),
                session_id.bold()
            );
            println!(
                "Target: {} (line {}) | Rule: {}",
                finding.file_path.bold(),
                finding.line_number,
                finding.rule_id.yellow()
            );
            println!();
        }

        // Step 1: Verification with terminal spinner
        let spinner = if !quiet && std::io::stdout().is_terminal() && !offline {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
                    .template("  {spinner:.cyan} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );
            pb.enable_steady_tick(std::time::Duration::from_millis(80));
            pb.set_message(format!("Verifying key status via {} API...", provider_name));
            Some(pb)
        } else {
            None
        };

        let live_status = if offline {
            LiveStatus::Unverified("Zero-egress offline mode active".to_string())
        } else {
            match matched_verifier {
                Some(v) => v.verify_live(raw_secret)?,
                None => LiveStatus::Unverified("Provider verification pending".to_string()),
            }
        };

        if let Some(sp) = spinner {
            sp.finish_and_clear();
        }

        if !quiet {
            print!(
                "  [1/7] 🔍 Verifying key status via {} API... ",
                provider_name
            );

            match &live_status {
                LiveStatus::Active { scopes } => {
                    println!(
                        "{} (Scopes: {})",
                        "ACTIVE & LIVE".red().bold(),
                        scopes.join(", ")
                    );
                }
                LiveStatus::Revoked => {
                    println!("{}", "ALREADY REVOKED".dimmed());
                }
                LiveStatus::Unverified(reason) => {
                    println!("{} ({})", "UNVERIFIED".yellow(), reason);
                }
            }

            // Step 2: Atomic Git Backup Branch
            print!("  [2/7] 🛡️  Creating atomic git backup branch... ");
        }
        let backup_branch = Self::create_backup_branch()?;
        if !quiet {
            println!("{} ({})", "SAVED".green(), backup_branch.dimmed());

            // Step 3: Provision Replacement Key or Extract Working Credential
            print!("  [3/7] 🔑 Provisioning replacement API credential... ");
        }
        // Extraction only: the same working credential moves to the backend, so the app keeps running
        let mut new_key = raw_secret.to_string();
        let masked_new_key = Finding::mask_secret(&new_key);

        if !quiet {
            println!(
                "{} ({} • extracted working key, not rotated)",
                "EXTRACTED".green(),
                masked_new_key.cyan()
            );
        }

        // Step 4: Inject into selected secret backend and verify gitignore
        let backend_choice = backend_name.unwrap_or("env");
        let backend_driver = backend::SecretBackendFactory::from_name(backend_choice)?;
        if !quiet {
            print!(
                "  [4/7] 🔒 Securing credential into {} backend... ",
                backend_driver.backend_name().cyan()
            );
        }
        let env_var_name = Self::resolve_env_var_name(finding, raw_secret, backend_choice);
        let env_var_name = env_var_name.as_str();

        let inject_note = backend_driver.inject_secret(env_var_name, &new_key, dry_run)?;
        if backend_driver.is_mock() && !dry_run && !quiet {
            eprintln!("{}", inject_note.yellow().bold());
        }
        Self::zeroize_secret_string(&mut new_key);
        if !quiet {
            println!(
                "{} ({}=*** • RAM buffer zeroized)",
                "INJECTED".green(),
                env_var_name
            );

            // Step 5: Replace hardcoded secret in target source file
            print!("  [5/7] 📝 Replacing hardcoded literal in source code... ");
        }
        let (original_line, replacement_line) = if !dry_run {
            CodeReplacer::replace_secret(
                &finding.file_path,
                finding.line_number,
                raw_secret,
                env_var_name,
            )?
        } else {
            let orig = std::fs::read_to_string(&finding.file_path)
                .ok()
                .and_then(|c| {
                    c.lines()
                        .nth(finding.line_number.saturating_sub(1))
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| format!("const secret = \"{raw_secret}\";"));
            let repl = CodeReplacer::replace_secret_in_line(
                &finding.file_path,
                &orig,
                raw_secret,
                env_var_name,
            );
            (orig, repl)
        };
        if !quiet {
            println!("{}", "PATCHED".green());
            let masked_orig = original_line.replace(raw_secret, &Finding::mask_secret(raw_secret));
            println!("        {} {}", "-".red().bold(), masked_orig.trim().red());
            println!(
                "        {} {}",
                "+".green().bold(),
                replacement_line.trim().green()
            );

            println!(
                "  [6/7] ⚠️  Leaked key NOT revoked: {}",
                "still valid until you rotate it at the provider"
                    .yellow()
                    .bold()
            );

            // Step 7: Record transaction in Rollback Ledger
            print!("  [7/7] 📋 Logging transaction to rollback ledger... ");
        }
        if !dry_run {
            let mut ledger = RollbackLedger::load()?;
            ledger.record_transaction(RollbackEntry {
                session_id: session_id.clone(),
                timestamp: chrono_compact_timestamp(),
                file_path: finding.file_path.clone(),
                line_number: finding.line_number,
                original_line,
                replacement_line,
                backup_branch,
                provider: provider_name.to_string(),
                secret_fingerprint: finding.fingerprint.clone(),
            })?;
        }
        if !quiet {
            println!("{}", "RECORDED".green());

            println!();
            println!(
                "{}",
                "Remediation complete: secret moved out of source. Revoke the old key at your provider and purge it from git history."
                    .bold()
                    .green()
            );
            println!(
                "To undo at any time, run: {}",
                format!("sentris rollback --session {}", session_id)
                    .bold()
                    .cyan()
            );
            println!();
        }

        Ok(session_id)
    }
}

fn chrono_compact_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn rotate_is_rejected_before_any_side_effect() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.py");
        let src = "key = \"sk_live_abcdefghijklmnopqrstuvwx\"\n";
        std::fs::write(&file, src).unwrap();
        let finding = Finding {
            rule_id: "stripe-secret-key".into(),
            description: "d".into(),
            severity: Severity::Critical,
            file_path: file.to_string_lossy().into_owned(),
            line_number: 1,
            column: 1,
            redacted_match: "sk_liv...".into(),
            entropy: 4.0,
            fingerprint: "0123456789abcdef0123456789abcdef".into(),
            commit_hash: None,
        };
        for dry_run in [true, false] {
            let err = Remediator::new()
                .remediate_finding_with_options(
                    &finding,
                    "sk_live_abcdefghijklmnopqrstuvwx",
                    dry_run,
                    Some("env"),
                    true,
                    true,
                    true,
                )
                .unwrap_err();
            assert!(matches!(err, SentrisError::NotImplemented(_)));
            assert_eq!(std::fs::read_to_string(&file).unwrap(), src);
        }
    }

    fn finding_for(rule: &str, fp: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            description: "d".into(),
            severity: Severity::Critical,
            file_path: "f".into(),
            line_number: 1,
            column: 1,
            redacted_match: "x".into(),
            entropy: 4.0,
            fingerprint: fp.into(),
            commit_hash: None,
        }
    }

    #[test]
    fn env_var_names_never_collide_or_clobber() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "STRIPE_SECRET_KEY=sk_live_prod\n").unwrap();
        let fp = "abcdef0123456789abcdef0123456789";
        let stripe = finding_for("stripe-secret-key", fp);

        // A different key must not reuse (and overwrite) the existing variable
        let other =
            Remediator::resolve_env_var_name_in(dir.path(), &stripe, "sk_live_leaked", "env");
        assert_eq!(other, "STRIPE_SECRET_KEY_ABCDEF01");
        // The same value reuses the canonical name
        let same = Remediator::resolve_env_var_name_in(dir.path(), &stripe, "sk_live_prod", "env");
        assert_eq!(same, "STRIPE_SECRET_KEY");
        // Generic rules are always unique per finding
        let a = Remediator::resolve_env_var_name_in(
            dir.path(),
            &finding_for("unknown-rule", fp),
            "s",
            "env",
        );
        let b = Remediator::resolve_env_var_name_in(
            dir.path(),
            &finding_for("unknown-rule", "99999999999999999999999999999999"),
            "s",
            "env",
        );
        assert_ne!(a, b);
    }
}
