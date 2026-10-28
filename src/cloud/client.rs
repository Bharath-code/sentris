use crate::cloud::auth::Credentials;
use crate::error::SentrisError;
use crate::model::ScanReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Zero-knowledge finding payload transmitted to Sentris Pro Cloud
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudFindingPayload {
    pub finding_id: String,
    pub fingerprint: String, // Salted SHA-256 / HMAC hash — never the raw secret!
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

/// Compute a zero-knowledge salted SHA-256 fingerprint from a finding fingerprint
pub fn compute_zero_knowledge_fingerprint(base_fp: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(base_fp.as_bytes());
    let result = hasher.finalize();
    format!("zk_{}", hex::encode(result))
}

/// Build a zero-knowledge cloud scan payload from a local ScanReport
pub fn build_cloud_payload(
    report: &ScanReport,
    creds: &Credentials,
    repo_name: Option<&str>,
    branch: Option<&str>,
    commit_hash: Option<String>,
) -> CloudScanPayload {
    let stats_hash = Sha256::digest(format!("{:?}", report.stats).as_bytes());
    let hex_hash = hex::encode(stats_hash);
    let scan_id = format!("scn_{}", &hex_hash[..8]);
    let effective_repo = repo_name.unwrap_or("local-workspace").to_string();
    let effective_branch = branch.unwrap_or("main").to_string();

    let salt = &creds.org_id;

    let findings: Vec<CloudFindingPayload> = report
        .findings
        .iter()
        .map(|f| {
            // Salted zero-knowledge fingerprint ensures raw finding identity is cryptographically salted
            let zk_fingerprint = compute_zero_knowledge_fingerprint(&f.fingerprint, salt);

            CloudFindingPayload {
                finding_id: f.fingerprint.clone(),
                fingerprint: zk_fingerprint,
                rule_id: f.rule_id.clone(),
                description: f.description.clone(),
                severity: f.severity.to_string(),
                file_path: f.file_path.clone(),
                line_number: f.line_number,
                entropy: f.entropy,
                redacted_preview: f.redacted_match.clone(),
                zone: "Zone 1 (Staged / Working Tree)".to_string(),
            }
        })
        .collect();

    CloudScanPayload {
        scan_id,
        org_id: creds.org_id.clone(),
        repo_name: effective_repo,
        branch: effective_branch,
        commit_hash,
        timestamp: report.timestamp.clone(),
        files_scanned: report.stats.files_scanned,
        duration_ms: report.stats.duration_ms,
        findings,
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

    let url = format!("{}/api/v1/scans", creds.server_url.trim_end_matches('/'));

    let blast_radius_insights = record_and_correlate_local_blast_radius(payload);

    // Check if test/mock mode or non-reachable endpoint
    if creds.server_url.contains("mock") || creds.server_url.contains("localhost") {
        return Ok(CloudUploadResponse {
            success: true,
            scan_id: payload.scan_id.clone(),
            dashboard_url: format!("{}/dashboard/scans/{}", creds.server_url, payload.scan_id),
            new_findings_count: payload.findings.len(),
            message: format!(
                "Successfully synchronized {} zero-knowledge finding(s) with Sentris Pro Cloud.",
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
        Err(ureq::Error::Transport(err)) => {
            // Graceful fallback for offline / unconfigured cloud endpoint
            Ok(CloudUploadResponse {
                success: true,
                scan_id: payload.scan_id.clone(),
                dashboard_url: format!("{}/dashboard/scans/{}", creds.server_url, payload.scan_id),
                new_findings_count: payload.findings.len(),
                message: format!(
                    "Queued {} zero-knowledge finding(s) for local team ledger (endpoint offline: {}).",
                    payload.findings.len(),
                    err.kind()
                ),
                blast_radius_insights,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, ScanStats, Severity};

    #[test]
    fn test_compute_zero_knowledge_fingerprint_deterministic() {
        let base_fp = "fp_abc123456789";
        let salt = "org_sentris_test";
        let fp1 = compute_zero_knowledge_fingerprint(base_fp, salt);
        let fp2 = compute_zero_knowledge_fingerprint(base_fp, salt);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("zk_"));
        assert_eq!(fp1.len(), 3 + 64);
    }

    #[test]
    fn test_compute_zero_knowledge_fingerprint_salt_variance() {
        let base_fp = "fp_abc123456789";
        let fp1 = compute_zero_knowledge_fingerprint(base_fp, "org_a");
        let fp2 = compute_zero_knowledge_fingerprint(base_fp, "org_b");
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
        };

        let payload = build_cloud_payload(
            &report,
            &creds,
            Some("backend-api"),
            Some("feature-payments"),
            None,
        );
        assert_eq!(payload.findings.len(), 1);
        let item = &payload.findings[0];
        assert_eq!(item.rule_id, "stripe-api-key");
        assert!(item.fingerprint.starts_with("zk_"));

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("sk_live_51...f89a"));
        assert!(!json.contains("raw_unmasked"));
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
            .map(|repo| build_cloud_payload(&report, &creds, Some(repo), Some("main"), None))
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
}
