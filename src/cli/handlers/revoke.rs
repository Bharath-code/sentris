use owo_colors::OwoColorize;
use std::time::Duration;

use super::{die, fail, fail_with_hint, print_json, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::Cli;
use crate::error::SentrisError;
use crate::model::Finding;
use crate::remediator::Remediator;
use crate::scanner::Scanner;
use crate::verifier::{LiveStatus, VerifierRegistry};

/// Returns the provider dashboard URL where a leaked credential can be revoked or rotated.
pub fn revocation_url_for_rule(rule_id: &str) -> &'static str {
    match rule_id {
        "github-pat" | "github-fine-grained-pat" | "github-oauth-access-token" => {
            "https://github.com/settings/tokens"
        }
        "stripe-secret-key" | "stripe-restricted-key" | "stripe-webhook-secret" => {
            "https://dashboard.stripe.com/apikeys"
        }
        "anthropic-api-key" => "https://console.anthropic.com/settings/keys",
        "openai-api-key" => "https://platform.openai.com/api-keys",
        "aws-access-key-id" | "aws-secret-access-key" => {
            "https://console.aws.amazon.com/iam/home#/users"
        }
        "slack-bot-token" | "slack-user-token" | "slack-webhook-url" => {
            "https://api.slack.com/apps"
        }
        "huggingface-token" => "https://huggingface.co/settings/tokens",
        "gitlab-pat" => "https://gitlab.com/-/user_settings/personal_access_tokens",
        "groq-api-key" => "https://console.groq.com/keys",
        "sendgrid-api-key" => "https://app.sendgrid.com/settings/api_keys",
        "digitalocean-access-token" => "https://cloud.digitalocean.com/account/api/tokens",
        "npm-access-token" => "https://www.npmjs.com/settings/~/tokens",
        "pypi-upload-token" => "https://pypi.org/manage/account/token/",
        "linear-api-key" => "https://linear.app/settings/api",
        "resend-api-key" => "https://resend.com/api-keys",
        "supabase-access-token" => "https://supabase.com/dashboard/account/tokens",
        "cloudflare-api-token" | "cloudflare-origin-ca-key" => {
            "https://dash.cloudflare.com/profile/api-tokens"
        }
        "tavily-api-key" => "https://app.tavily.com/home",
        "pinecone-api-key" => "https://app.pinecone.io/organizations/-/projects/-/keys",
        "firecrawl-api-key" => "https://www.firecrawl.dev/app/api-keys",
        _ => "https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning",
    }
}

/// Calls GitHub's unauthenticated `POST /credentials/revoke` endpoint to permanently revoke a leaked GitHub token.
pub fn revoke_github_credential_via_api(
    endpoint_url: &str,
    secret: &str,
) -> Result<(), SentrisError> {
    let payload = serde_json::json!({
        "credentials": [secret]
    });
    let res = ureq::post(endpoint_url)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .set("User-Agent", "sentris-security-scanner")
        .timeout(Duration::from_secs(5))
        .send_json(payload);
    match res {
        Ok(resp) if resp.status() == 202 || resp.status() == 200 || resp.status() == 204 => Ok(()),
        Ok(resp) => Err(SentrisError::Scan(format!(
            "GitHub /credentials/revoke returned HTTP {}",
            resp.status()
        ))),
        Err(ureq::Error::Status(code, _)) => Err(SentrisError::Scan(format!(
            "GitHub /credentials/revoke rejected request with HTTP {code}"
        ))),
        Err(e) => Err(SentrisError::Scan(format!(
            "Failed to call GitHub /credentials/revoke: {e}"
        ))),
    }
}

fn find_target<'a>(findings: &'a [Finding], id: Option<&str>) -> Option<&'a Finding> {
    match id {
        Some(target) => findings.iter().find(|f| {
            f.rule_id == target
                || f.fingerprint.starts_with(target)
                || f.file_path == target
                || f.file_path.ends_with(target)
        }),
        None => findings.first(),
    }
}

#[allow(clippy::too_many_lines)]
pub fn handle_revoke(cli: &Cli, finding_id: Option<String>, api: bool, wait: bool) {
    let agent_mode = cli.is_agent_mode();
    if cli.offline && (api || wait) {
        fail("`sentris revoke` with `--api` or `--wait` requires network access (cannot run with `--offline`).");
    }

    let scanner = Scanner::new().unwrap_or_else(|e| die("Failed to initialize scanner", e));
    let scan_target = super::remediate::scan_target_for(finding_id.as_deref());
    let mut report = scanner
        .scan_path(&scan_target)
        .unwrap_or_else(|e| die("Failed to scan target", e));
    if find_target(&report.findings, finding_id.as_deref()).is_none() {
        if let Ok(hist) = scanner.scan_git_history() {
            report = hist;
        }
    }
    let Some(finding) = find_target(&report.findings, finding_id.as_deref()) else {
        fail_with_hint(
            "No matching finding found to revoke.",
            "Run 'sentris scan . --git-history' to inspect active and historical finding IDs.",
        );
    };

    let mut secret = crate::investigate::resolve_finding_or_historical_secret(&scanner, finding)
        .unwrap_or_else(|e| fail(&e.to_string()));

    let url = revocation_url_for_rule(&finding.rule_id);
    let registry = VerifierRegistry::new();
    let verifier = registry.find_verifier(&finding.rule_id);
    let provider = verifier.map(|v| v.provider_name()).unwrap_or("Provider");

    let mut api_revoked = false;
    if api {
        if finding.rule_id.starts_with("github-") {
            revoke_github_credential_via_api("https://api.github.com/credentials/revoke", &secret)
                .unwrap_or_else(|e| {
                    Remediator::zeroize_secret_string(&mut secret);
                    die("GitHub API revocation failed", e)
                });
            api_revoked = true;
        } else {
            Remediator::zeroize_secret_string(&mut secret);
            fail(&format!(
                "`--api` revocation is supported for GitHub tokens (`POST /credentials/revoke`). For {}, revoke at: {url} (or use `sentris remediate --rotate` for AWS IAM keys).",
                finding.rule_id
            ));
        }
    }

    let mut status = if cli.offline {
        LiveStatus::Unverified("Zero-egress offline mode active".to_string())
    } else {
        match verifier {
            Some(v) => v
                .verify_live(&secret)
                .unwrap_or_else(|e| LiveStatus::Unverified(e.to_string())),
            None => LiveStatus::Unverified("No live verifier for this rule".to_string()),
        }
    };

    if wait && matches!(status, LiveStatus::Active { .. }) {
        if let Some(v) = verifier {
            if !agent_mode {
                println!(
                    "Revoke the credential at {} — polling {} API every 2s until revoked...",
                    url.cyan().bold(),
                    provider
                );
            }
            for _ in 0..30 {
                std::thread::sleep(Duration::from_secs(2));
                if let Ok(next) = v.verify_live(&secret) {
                    status = next;
                    if matches!(status, LiveStatus::Revoked) {
                        break;
                    }
                }
            }
        }
    }
    Remediator::zeroize_secret_string(&mut secret);

    let is_revoked = api_revoked || matches!(status, LiveStatus::Revoked);
    if is_revoked {
        let rev_id = format!("rev_{}", crate::model::short(&finding.fingerprint, 8));
        record_audit_event(
            AuditAction::KeyDeactivated {
                rotation_id: rev_id,
                provider: provider.to_string(),
            },
            serde_json::json!({
                "rule_id": finding.rule_id,
                "fingerprint_prefix": crate::model::short(&finding.fingerprint, 12),
                "api_revoked": api_revoked,
                "revocation_url": url,
            }),
        );
    }

    if agent_mode {
        print_json(serde_json::json!({
            "ok": true,
            "command": "revoke",
            "rule_id": finding.rule_id,
            "provider": provider,
            "revocation_url": url,
            "api_revoked": api_revoked,
            "live_status": status,
            "confirmed_revoked": is_revoked,
        }));
    } else if is_revoked {
        println!(
            "{} Credential ({}) is confirmed {} and recorded in the audit ledger.",
            "✔".green().bold(),
            finding.rule_id.cyan(),
            "REVOKED".green().bold()
        );
    } else {
        println!(
            "{} Credential ({}) is not yet confirmed revoked (status: {:?}).\n  Revoke it at: {}\n  Re-run with {} to poll until revocation completes.",
            "⚠️ ".yellow().bold(),
            finding.rule_id.cyan(),
            status,
            url.cyan(). underline(),
            "`sentris revoke --wait`".bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_rules_to_provider_revocation_urls() {
        assert_eq!(
            revocation_url_for_rule("github-pat"),
            "https://github.com/settings/tokens"
        );
        assert_eq!(
            revocation_url_for_rule("stripe-secret-key"),
            "https://dashboard.stripe.com/apikeys"
        );
        assert_eq!(
            revocation_url_for_rule("anthropic-api-key"),
            "https://console.anthropic.com/settings/keys"
        );
        assert_eq!(
            revocation_url_for_rule("huggingface-token"),
            "https://huggingface.co/settings/tokens"
        );
    }
}
