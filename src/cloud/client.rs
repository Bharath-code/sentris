use crate::cloud::auth::Credentials;
use crate::error::SentrisError;
use crate::model::ScanReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Uploaded in place of `redacted_match`: even a prefix + last 4 chars is partial key material.
pub const CLOUD_PREVIEW_MASK: &str = "[redacted]";

/// Zero-knowledge finding payload transmitted to Sentris Pro Cloud
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudFindingPayload {
    /// HMAC-SHA256(team secret, secret hash). The server never holds the key, so it
    /// cannot test a guessed secret against this value.
    pub fingerprint: String,
    pub rule_id: String,
    pub description: String,
    pub severity: String,
    pub file_path: String,
    pub line_number: usize,
    pub entropy: f64,
    pub redacted_preview: String,
    pub zone: String,
}

/// Batch scan ingestion payload for Sentris Pro Cloud
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudScanPayload {
    pub scan_id: String,
    pub org_id: String,
    pub repo_name: String,
    pub branch: String,
    pub commit_hash: Option<String>,
    pub timestamp: String,
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub findings: Vec<CloudFindingPayload>,
}

/// Zero-knowledge cross-repository credential reuse & blast-radius insight.
/// Correlates identical salted HMAC-SHA256 fingerprints (`zk_<hash>`) across
/// multiple repositories without ever ingesting source code or raw secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiRepoBlastRadiusInsight {
    pub zk_fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub redacted_preview: String,
    pub affected_repos: Vec<String>,
    pub total_occurrences: usize,
}

/// Response returned by Sentris Pro Cloud upon successful ingestion
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudUploadResponse {
    pub success: bool,
    pub scan_id: String,
    pub dashboard_url: String,
    pub new_findings_count: usize,
    pub message: String,
    #[serde(default)]
    pub blast_radius_insights: Vec<MultiRepoBlastRadiusInsight>,
}

/// Correlates zero-knowledge scan payloads across multiple repositories to detect
/// duplicate leaked credentials (shared blast radius) without plaintext access.
pub fn correlate_multi_repo_blast_radius(
    payloads: &[CloudScanPayload],
) -> Vec<MultiRepoBlastRadiusInsight> {
    use std::collections::BTreeMap;

    // Map zk_fingerprint -> (rule_id, severity, preview, sorted unique repos, total count)
    let mut map: BTreeMap<String, (String, String, String, Vec<String>, usize)> = BTreeMap::new();

    for payload in payloads {
        for finding in &payload.findings {
            let entry = map.entry(finding.fingerprint.clone()).or_insert_with(|| {
                (
                    finding.rule_id.clone(),
                    finding.severity.clone(),
                    finding.redacted_preview.clone(),
                    Vec::new(),
                    0,
                )
            });
            if !entry.3.contains(&payload.repo_name) {
                entry.3.push(payload.repo_name.clone());
            }
            entry.4 += 1;
        }
    }

    let mut insights: Vec<MultiRepoBlastRadiusInsight> = map
        .into_iter()
        .map(
            |(zk_fingerprint, (rule_id, severity, redacted_preview, affected_repos, total))| {
                MultiRepoBlastRadiusInsight {
                    zk_fingerprint,
                    rule_id,
                    severity,
                    redacted_preview,
                    affected_repos,
                    total_occurrences: total,
                }
            },
        )
        .collect();

    // Sort by number of affected repositories descending
    insights.sort_by(|a, b| {
        b.affected_repos
            .len()
            .cmp(&a.affected_repos.len())
            .then_with(|| b.total_occurrences.cmp(&a.total_occurrences))
    });

    insights
}

/// Records a scan payload into the local zero-knowledge multi-repo correlation ledger
/// (`.sentris/multi_repo_blast_radius.json`) and returns cross-repo blast radius insights.
pub fn record_and_correlate_local_blast_radius(
    payload: &CloudScanPayload,
) -> Vec<MultiRepoBlastRadiusInsight> {
    let ledger_path = std::path::Path::new(".sentris").join("multi_repo_blast_radius.json");
    if let Some(parent) = ledger_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut payloads: Vec<CloudScanPayload> = if ledger_path.exists() {
        std::fs::read_to_string(&ledger_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Replace existing entry for same repo_name or push new
    if let Some(existing) = payloads
        .iter_mut()
        .find(|p| p.repo_name == payload.repo_name)
    {
        *existing = payload.clone();
    } else {
        payloads.push(payload.clone());
    }

    if let Ok(serialized) = serde_json::to_string_pretty(&payloads) {
        let _ = std::fs::write(&ledger_path, serialized);
    }

    correlate_multi_repo_blast_radius(&payloads)
}

/// Keyed zero-knowledge fingerprint: `zk_` + HMAC-SHA256(team_secret, base_fp).
/// `team_secret` is the 64-hex team secret; teammates sharing it get identical fingerprints.
pub fn compute_zero_knowledge_fingerprint(base_fp: &str, team_secret: &str) -> String {
    let key = hex::decode(team_secret).unwrap_or_else(|_| team_secret.as_bytes().to_vec());
    format!(
        "zk_{}",
        hex::encode(crate::audit::hmac_sha256(&key, base_fp.as_bytes()))
    )
}

/// Build a zero-knowledge cloud scan payload from a local ScanReport
pub fn build_cloud_payload(
    report: &ScanReport,
    creds: &Credentials,
    repo_name: Option<&str>,
    branch: Option<&str>,
    commit_hash: Option<String>,
) -> Result<CloudScanPayload, SentrisError> {
    let team_secret = creds.team_secret.as_deref().ok_or_else(|| {
        SentrisError::Cloud(
            "No team secret configured. Re-run `sentris auth login --token <KEY>` (add `--team-secret <SECRET>` to join an existing team)."
                .to_string(),
        )
    })?;
    let stats_hash = Sha256::digest(format!("{:?}", report.stats).as_bytes());
    let hex_hash = hex::encode(stats_hash);
    let scan_id = format!("scn_{}", &hex_hash[..8]);
    let effective_repo = repo_name.unwrap_or("local-workspace").to_string();
    let effective_branch = branch.unwrap_or("main").to_string();

    let findings: Vec<CloudFindingPayload> = report
        .findings
        .iter()
        .map(|f| CloudFindingPayload {
            fingerprint: compute_zero_knowledge_fingerprint(&f.fingerprint, team_secret),
            rule_id: f.rule_id.clone(),
            description: f.description.clone(),
            severity: f.severity.to_string(),
            file_path: f.file_path.clone(),
            line_number: f.line_number,
            entropy: f.entropy,
            redacted_preview: CLOUD_PREVIEW_MASK.to_string(),
            zone: "Zone 1 (Staged / Working Tree)".to_string(),
        })
        .collect();

    Ok(CloudScanPayload {
        scan_id,
        org_id: creds.org_id.clone(),
        repo_name: effective_repo,
        branch: effective_branch,
        commit_hash,
        timestamp: report.timestamp.clone(),
        files_scanned: report.stats.files_scanned,
        duration_ms: report.stats.duration_ms,
        findings,
    })
}

/// Production API until a custom domain exists.
pub const DEFAULT_SERVER_URL: &str = "https://sentris-web.kumarbharath63.workers.dev";

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Explicit offline simulation for tests/demos. Never inferred from the server URL.
pub fn mock_mode() -> bool {
    env_flag("SENTRIS_CLOUD_MOCK")
}

/// The bearer API key is sent to this URL, so require https (plain http only for loopback with an explicit opt-in).
pub fn validate_server_url(url: &str) -> Result<(), SentrisError> {
    let bad = |why: &str| SentrisError::Cloud(format!("Refusing server URL '{url}': {why}"));
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| bad("expected https://host"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(bad("missing host or embedded credentials"));
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "::1") => {
            if env_flag("SENTRIS_ALLOW_INSECURE") {
                Ok(())
            } else {
                Err(bad(
                    "http is only allowed for loopback with SENTRIS_ALLOW_INSECURE=1",
                ))
            }
        }
        _ => Err(bad("the API key would travel unencrypted; use https")),
    }
}

/// Upload scan findings to Sentris Pro Cloud API
pub fn upload_scan(
    payload: &CloudScanPayload,
    creds: &Credentials,
    offline: bool,
) -> Result<CloudUploadResponse, SentrisError> {
    if offline {
        return Err(SentrisError::Cloud(
            "Zero-egress offline mode active: Cloud sync suppressed.".to_string(),
        ));
    }

    validate_server_url(&creds.server_url)?;
    let url = format!("{}/api/v1/scans", creds.server_url.trim_end_matches('/'));

    let blast_radius_insights = record_and_correlate_local_blast_radius(payload);

    if mock_mode() {
        return Ok(CloudUploadResponse {
            success: true,
            scan_id: payload.scan_id.clone(),
            dashboard_url: String::new(),
            new_findings_count: payload.findings.len(),
            message: format!(
                "[MOCK] SENTRIS_CLOUD_MOCK is set: nothing was uploaded ({} finding(s) correlated locally only).",
                payload.findings.len()
            ),
            blast_radius_insights,
        });
    }

    // Attempt real HTTP request with ureq
    let response = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", creds.api_key))
        .set("Content-Type", "application/json")
        .set("User-Agent", "Sentris-CLI/0.1.0")
        .timeout(std::time::Duration::from_secs(5))
        .send_json(payload);

    match response {
        Ok(res) => {
            if res.status() == 200 || res.status() == 201 {
                let upload_res: CloudUploadResponse = res.into_json().map_err(|e| {
                    SentrisError::Cloud(format!("Failed to parse cloud response: {e}"))
                })?;
                Ok(upload_res)
            } else {
                Err(SentrisError::Cloud(format!(
                    "Cloud API responded with HTTP status {}",
                    res.status()
                )))
            }
        }
        Err(ureq::Error::Status(status, res)) => {
            let body = res.into_string().unwrap_or_default();
            Err(SentrisError::Cloud(format!(
                "Cloud API rejected sync (HTTP {status}): {body}"
            )))
        }
        Err(ureq::Error::Transport(err)) => Err(SentrisError::Cloud(format!(
            "Could not reach {}: {err}. Nothing was synced.",
            creds.server_url
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, ScanStats, Severity};

    #[test]
    fn test_compute_zero_knowledge_fingerprint_deterministic() {
        let base_fp = "fp_abc123456789";
        let secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fp1 = compute_zero_knowledge_fingerprint(base_fp, secret);
        let fp2 = compute_zero_knowledge_fingerprint(base_fp, secret);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("zk_"));
        assert_eq!(fp1.len(), 3 + 64);
    }

    #[test]
    fn test_compute_zero_knowledge_fingerprint_salt_variance() {
        let base_fp = "fp_abc123456789";
        let fp1 = compute_zero_knowledge_fingerprint(
            base_fp,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let fp2 = compute_zero_knowledge_fingerprint(
            base_fp,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_build_cloud_payload_never_exposes_raw_secret() {
        let finding = Finding {
            rule_id: "stripe-api-key".to_string(),
            description: "Stripe Secret Key".to_string(),
            severity: Severity::Critical,
            file_path: "src/config.ts".to_string(),
            line_number: 14,
            column: 1,
            redacted_match: "sk_live_51...f89a".to_string(),
            entropy: 4.85,
            fingerprint: "hash_a1b2c3d4e5f6".to_string(),
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        };

        let report = ScanReport {
            timestamp: "2026-10-08T12:00:00Z".to_string(),
            version: "0.1.0".to_string(),
            stats: ScanStats {
                files_scanned: 10,
                files_ignored: 2,
                bytes_scanned: 1024,
                duration_ms: 15,
                findings_count: 1,
            },
            findings: vec![finding],
        };

        let creds = Credentials {
            api_key: "sp_live_test".to_string(),
            server_url: "https://api.sentris.dev".to_string(),
            org_id: "org_acme".to_string(),
            org_name: "Acme Corp".to_string(),
            tier: "Pro ($8/seat)".to_string(),
            seat_limit: 20,
            seats_used: 12,
            user_email: "dev@acme.corp".to_string(),
            expires_at: None,
            team_secret: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        };

        let no_secret = Credentials {
            team_secret: None,
            ..creds.clone()
        };
        assert!(build_cloud_payload(&report, &no_secret, None, None, None).is_err());

        let payload = build_cloud_payload(
            &report,
            &creds,
            Some("backend-api"),
            Some("feature-payments"),
            None,
        )
        .unwrap();
        assert_eq!(payload.findings.len(), 1);
        let item = &payload.findings[0];
        assert_eq!(item.rule_id, "stripe-api-key");
        assert!(item.fingerprint.starts_with("zk_"));

        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("sk_live_51...f89a"));
        assert!(!json.contains("f89a"));
        assert_eq!(item.redacted_preview, CLOUD_PREVIEW_MASK);
        assert!(!json.contains("raw_unmasked"));
        // The unsalted secret hash must never leave the machine
        assert!(!json.contains("hash_a1b2c3d4e5f6"));
        assert!(!json.contains("finding_id"));
    }

    #[test]
    fn test_upload_scan_offline_rejection() {
        let payload = CloudScanPayload {
            scan_id: "scn_123".to_string(),
            org_id: "org_acme".to_string(),
            repo_name: "test-repo".to_string(),
            branch: "main".to_string(),
            commit_hash: None,
            timestamp: "2026-10-08T12:00:00Z".to_string(),
            files_scanned: 5,
            duration_ms: 8,
            findings: vec![],
        };

        let creds = Credentials {
            api_key: "sp_live_test".to_string(),
            server_url: "https://mock.sentris.dev".to_string(),
            org_id: "org_acme".to_string(),
            org_name: "Acme Corp".to_string(),
            tier: "Pro ($8/seat)".to_string(),
            seat_limit: 20,
            seats_used: 12,
            user_email: "dev@acme.corp".to_string(),
            expires_at: None,
            team_secret: None,
        };

        let err = upload_scan(&payload, &creds, true).unwrap_err();
        assert!(err.to_string().contains("Zero-egress offline mode active"));
    }

    #[test]
    fn test_zero_knowledge_multi_repo_blast_radius_correlation() {
        let creds = Credentials {
            api_key: "sp_live_test".to_string(),
            server_url: "https://mock.sentris.dev".to_string(),
            org_id: "org_acme_cyber".to_string(),
            org_name: "Acme Cyber".to_string(),
            tier: "Pro ($8/seat)".to_string(),
            seat_limit: 50,
            seats_used: 24,
            user_email: "ciso@acme.corp".to_string(),
            expires_at: None,
            team_secret: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        };

        let shared_pg_finding = Finding {
            rule_id: "postgres-connection-uri".to_string(),
            description: "PostgreSQL URI".to_string(),
            severity: Severity::Critical,
            file_path: "infra/db.go".to_string(),
            line_number: 3,
            column: 1,
            redacted_match: "postgr...prod".to_string(),
            entropy: 4.53,
            fingerprint: "94a3ab2d2b40bf154ebe81310bb8e0f21f511a0d3d54c743a2668f5fd9226ccc"
                .to_string(),
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        };

        let report = ScanReport {
            timestamp: "2026-10-28T12:00:00Z".to_string(),
            version: "0.1.0".to_string(),
            stats: ScanStats {
                files_scanned: 12,
                files_ignored: 0,
                bytes_scanned: 4096,
                duration_ms: 5,
                findings_count: 1,
            },
            findings: vec![shared_pg_finding],
        };

        let repos = ["billing-svc", "auth-worker", "analytics-etl", "admin-api"];
        let payloads: Vec<CloudScanPayload> = repos
            .iter()
            .map(|repo| {
                build_cloud_payload(&report, &creds, Some(repo), Some("main"), None).unwrap()
            })
            .collect();

        let insights = correlate_multi_repo_blast_radius(&payloads);
        assert_eq!(insights.len(), 1);
        assert_eq!(insights[0].rule_id, "postgres-connection-uri");
        assert_eq!(insights[0].affected_repos.len(), 4);
        assert_eq!(
            insights[0].affected_repos,
            vec!["billing-svc", "auth-worker", "analytics-etl", "admin-api"]
        );
        assert!(insights[0].zk_fingerprint.starts_with("zk_"));
    }

    #[test]
    fn server_url_validation() {
        assert!(validate_server_url("https://app.example.com").is_ok());
        assert!(validate_server_url("http://example.com").is_err());
        assert!(validate_server_url("http://localhost:3000").is_err());
        assert!(validate_server_url("ftp://example.com").is_err());
        assert!(validate_server_url("https://user:pw@example.com").is_err());
        assert!(validate_server_url("https://").is_err());
        assert!(validate_server_url("example.com").is_err());
        // A hostile name containing "mock"/"localhost" gets no special treatment
        assert!(validate_server_url("https://mock.evil.tld").is_ok());
        assert!(validate_server_url("http://mock.evil.tld/localhost").is_err());
    }

    #[test]
    fn unreachable_server_is_an_error_not_a_success() {
        let payload = CloudScanPayload {
            scan_id: "s".into(),
            org_id: "o".into(),
            repo_name: "r".into(),
            branch: "b".into(),
            commit_hash: None,
            timestamp: "t".into(),
            files_scanned: 0,
            duration_ms: 0,
            findings: vec![],
        };
        let creds = Credentials {
            api_key: "sp_live_x".into(),
            server_url: "https://127.0.0.1:9".into(),
            org_id: String::new(),
            org_name: String::new(),
            tier: String::new(),
            seat_limit: 0,
            seats_used: 0,
            user_email: String::new(),
            expires_at: None,
            team_secret: None,
        };
        let err = upload_scan(&payload, &creds, false).unwrap_err();
        assert!(err.to_string().contains("Nothing was synced"));
    }
}
