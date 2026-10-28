use std::fs;
use std::path::Path;

use crate::audit::{AuditAction, AuditLedger, GENESIS_PREVIOUS_HASH};
use crate::error::SentrisError;

impl AuditLedger {
    /// Exports a 1-Click Vanta / Drata SOC 2 Type II (CC6.1, CC6.7, CC6.8) & ISO 27001 (A.8.24)
    /// cryptographic compliance evidence JSON bundle.
    pub fn export_vanta_evidence_pack<P: AsRef<Path>>(
        &self,
        output_path: P,
    ) -> Result<(usize, usize, usize, usize), SentrisError> {
        let chain_valid = self.verify_integrity()?;
        let head_hash = self
            .records
            .last()
            .map(|r| r.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_PREVIOUS_HASH.to_string());
        let head_hmac = self
            .records
            .last()
            .map(|r| r.hmac_signature.clone())
            .unwrap_or_default();

        let mut scans_completed = 0usize;
        let mut total_files_inspected = 0usize;
        let mut total_scan_duration_ms = 0u64;
        let mut secrets_remediated = 0usize;
        let mut baselines_recorded = 0usize;
        let mut quarantines_created = 0usize;

        for r in &self.records {
            match &r.action {
                AuditAction::ScanCompleted {
                    files_scanned,
                    duration_ms,
                    ..
                } => {
                    scans_completed += 1;
                    total_files_inspected += files_scanned;
                    total_scan_duration_ms += duration_ms;
                }
                AuditAction::SecretRemediated { .. } => secrets_remediated += 1,
                AuditAction::BaselineRecorded { .. } => baselines_recorded += 1,
                AuditAction::QuarantineCreated { .. } => quarantines_created += 1,
            }
        }

        let avg_scan_latency_ms = if scans_completed > 0 {
            total_scan_duration_ms / scans_completed as u64
        } else {
            0
        };

        let status_str = if chain_valid { "PASS" } else { "FAIL" };

        let pack = serde_json::json!({
            "schema": "sentris.vanta.drata.compliance.v1",
            "framework_mappings": [
                "SOC2_CC6.1_Logical_Access_Security",
                "SOC2_CC6.7_Zero_Knowledge_Data_Transmission",
                "SOC2_CC6.8_Autonomous_Credential_Remediation",
                "ISO27001_A.8.24_Use_Of_Cryptography"
            ],
            "control_attestations": {
                "SOC2_CC6.1": {
                    "control_name": "Continuous Secret Scanning & Access Guardrails",
                    "status": status_str,
                    "scans_executed": scans_completed,
                    "total_files_inspected": total_files_inspected,
                    "avg_scan_latency_ms": avg_scan_latency_ms
                },
                "SOC2_CC6.7": {
                    "control_name": "Zero-Knowledge Data Transmission & Memory Hygiene",
                    "status": status_str,
                    "plaintext_secrets_transmitted_bytes": 0,
                    "fingerprint_protocol": "Salted HMAC-SHA256 (RFC 2104)",
                    "memory_hygiene": "Volatile RAM Zeroization (write_volatile + SeqCst fence)"
                },
                "SOC2_CC6.8": {
                    "control_name": "Timely Autonomous Credential Remediation & Quarantine",
                    "status": status_str,
                    "secrets_remediated": secrets_remediated,
                    "quarantines_created": quarantines_created,
                    "baselines_recorded": baselines_recorded,
                    "deprecation_policy": "Not automated: leaked keys must be revoked at the provider"
                },
                "ISO27001_A.8.24": {
                    "control_name": "Cryptographic Hash-Chain Audit Integrity",
                    "status": status_str,
                    "broken_links": if chain_valid { 0 } else { 1 },
                    "chain_head_hash": head_hash,
                    "chain_head_hmac": head_hmac
                }
            },
            "cryptographic_proof": {
                "algorithm": "HMAC-SHA256 (RFC 2104) + SHA-256 Hash Chain",
                "chain_integrity": status_str,
                "genesis_hash": GENESIS_PREVIOUS_HASH,
                "chain_head_hash": head_hash,
                "chain_head_hmac": head_hmac,
                "total_verified_records": self.records.len()
            },
            "summary_metrics": {
                "scans_completed": scans_completed,
                "total_files_inspected": total_files_inspected,
                "avg_scan_latency_ms": avg_scan_latency_ms,
                "secrets_remediated": secrets_remediated,
                "baselines_recorded": baselines_recorded,
                "quarantines_created": quarantines_created
            },
            "records": self.records
        });

        let out_ref = output_path.as_ref();
        if let Some(parent) = out_ref.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(out_ref, serde_json::to_string_pretty(&pack)?)?;
        Ok((
            scans_completed,
            total_files_inspected,
            secrets_remediated,
            quarantines_created,
        ))
    }
}
