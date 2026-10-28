use super::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_audit_action_serialization() {
    let actions = vec![
        AuditAction::ScanCompleted {
            files_scanned: 100,
            findings_count: 5,
            duration_ms: 1250,
        },
        AuditAction::SecretRemediated {
            session_id: "sess-abc".to_string(),
            rule_id: "stripe-secret-key".to_string(),
            backend: "vault".to_string(),
        },
        AuditAction::BaselineRecorded {
            entries_count: 42,
            git_commit: Some("abcdef0123456789".to_string()),
        },
        AuditAction::QuarantineCreated {
            finding_id: "find-99".to_string(),
            branch: "quarantine/find-99".to_string(),
        },
    ];

    for action in actions {
        let serialized = serde_json::to_string(&action).unwrap();
        let deserialized: AuditAction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(action, deserialized);
    }
}

#[test]
fn test_creation_of_multiple_audit_entries() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("audit.json");
    let mut ledger = AuditLedger::load_or_init(&ledger_path).unwrap();

    assert!(ledger.records.is_empty());

    let r1 = ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 50,
                findings_count: 1,
                duration_ms: 320,
            },
            serde_json::json!({"initiator": "ci"}),
        )
        .unwrap()
        .clone();

    assert_eq!(r1.index, 0);
    assert_eq!(r1.previous_hash, GENESIS_PREVIOUS_HASH);
    assert_eq!(r1.entry_hash.len(), 64);
    assert_eq!(r1.hmac_signature.len(), 64);

    let r2 = ledger
        .record_event(
            AuditAction::SecretRemediated {
                session_id: "sess-1".to_string(),
                rule_id: "aws-access-key".to_string(),
                backend: "env".to_string(),
            },
            serde_json::json!({"actor": "alice"}),
        )
        .unwrap()
        .clone();

    assert_eq!(r2.index, 1);
    assert_eq!(r2.previous_hash, r1.entry_hash);

    let r3 = ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 12,
                git_commit: Some("12345678".to_string()),
            },
            serde_json::json!({"baseline": "v1.0"}),
        )
        .unwrap()
        .clone();

    assert_eq!(r3.index, 2);
    assert_eq!(r3.previous_hash, r2.entry_hash);

    let r4 = ledger
        .record_event(
            AuditAction::QuarantineCreated {
                finding_id: "fid-4".to_string(),
                branch: "quarantine/fid-4".to_string(),
            },
            serde_json::json!({"branch": "quarantine/fid-4"}),
        )
        .unwrap()
        .clone();

    assert_eq!(r4.index, 3);
    assert_eq!(r4.previous_hash, r3.entry_hash);

    assert_eq!(ledger.records.len(), 4);
}

#[test]
fn test_verification_of_hash_chain_integrity() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("audit.json");
    let mut ledger = AuditLedger::load_or_init(&ledger_path).unwrap();

    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 10,
                findings_count: 0,
                duration_ms: 100,
            },
            serde_json::json!({"clean": true}),
        )
        .unwrap();

    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 5,
                git_commit: None,
            },
            serde_json::json!({"scope": "all"}),
        )
        .unwrap();

    ledger
        .record_event(
            AuditAction::SecretRemediated {
                session_id: "sess-x".to_string(),
                rule_id: "github-pat".to_string(),
                backend: "vault".to_string(),
            },
            serde_json::json!({"status": "rotated"}),
        )
        .unwrap();

    // Verify valid chain
    assert!(ledger.verify_integrity().unwrap());

    // Save and reload from disk
    ledger.save().unwrap();
    let loaded = AuditLedger::load_or_init(&ledger_path).unwrap();
    assert_eq!(loaded.records.len(), 3);
    assert!(loaded.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_index() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with index of earlier record
    ledger.records[0].index = 999;
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_timestamp() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with timestamp of earlier record
    ledger.records[0].timestamp += 1000;
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_action() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 10,
                findings_count: 2,
                duration_ms: 50,
            },
            serde_json::json!({}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with action of earlier record (reduce findings count)
    ledger.records[0].action = AuditAction::ScanCompleted {
        files_scanned: 10,
        findings_count: 0, // tampered!
        duration_ms: 50,
    };
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_details() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({"approved_by": "sec_team"}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with details of earlier record
    ledger.records[0].details = serde_json::json!({"approved_by": "attacker"});
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_previous_hash() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with previous_hash of earlier record
    ledger.records[0].previous_hash =
        "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_entry_hash() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with entry_hash of earlier record
    ledger.records[0].entry_hash =
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string();
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_hmac_signature() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Tamper with HMAC signature of earlier record
    ledger.records[0].hmac_signature =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    assert!(!ledger.verify_integrity().unwrap());
}

#[test]
fn test_tamper_detection_deletion_and_reordering() {
    let mut ledger = AuditLedger::default();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 1,
                findings_count: 0,
                duration_ms: 10,
            },
            serde_json::json!({"entry": 0}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::BaselineRecorded {
                entries_count: 1,
                git_commit: None,
            },
            serde_json::json!({"entry": 1}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::SecretRemediated {
                session_id: "s1".to_string(),
                rule_id: "r1".to_string(),
                backend: "b1".to_string(),
            },
            serde_json::json!({"entry": 2}),
        )
        .unwrap();

    assert!(ledger.verify_integrity().unwrap());

    // Deleting record 1 breaks the chain between 0 and 2
    let mut tampered = ledger.clone();
    tampered.records.remove(1);
    assert!(!tampered.verify_integrity().unwrap());

    // Swapping record 0 and 1 breaks genesis and order
    let mut swapped = ledger.clone();
    swapped.records.swap(0, 1);
    assert!(!swapped.verify_integrity().unwrap());
}

#[test]
fn test_empty_ledger_integrity() {
    let ledger = AuditLedger::default();
    assert!(ledger.verify_integrity().unwrap());
}

#[test]
fn test_export_vanta_evidence_pack_soc2_controls() {
    let dir = tempdir().unwrap();
    let ledger_path = dir.path().join("audit_ledger.json");
    let vanta_path = dir.path().join("vanta-evidence.json");

    let mut ledger = AuditLedger::load_or_init(&ledger_path).unwrap();
    ledger
        .record_event(
            AuditAction::ScanCompleted {
                files_scanned: 42,
                findings_count: 1,
                duration_ms: 16,
            },
            serde_json::json!({"mode": "staged"}),
        )
        .unwrap();
    ledger
        .record_event(
            AuditAction::SecretRemediated {
                session_id: "rm_12345678".to_string(),
                rule_id: "stripe-secret-key".to_string(),
                backend: "env".to_string(),
            },
            serde_json::json!({"file_path": "src/billing.ts"}),
        )
        .unwrap();

    let (scans, files, remediations, quarantines) =
        ledger.export_vanta_evidence_pack(&vanta_path).unwrap();
    assert_eq!(scans, 1);
    assert_eq!(files, 42);
    assert_eq!(remediations, 1);
    assert_eq!(quarantines, 0);

    let raw = fs::read_to_string(&vanta_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed["cryptographic_proof"]["chain_integrity"], "PASS");
    assert_eq!(
        parsed["control_attestations"]["SOC2_CC6.1"]["status"],
        "PASS"
    );
    assert_eq!(
        parsed["control_attestations"]["SOC2_CC6.7"]["plaintext_secrets_transmitted_bytes"],
        0
    );
    assert_eq!(
        parsed["control_attestations"]["SOC2_CC6.8"]["secrets_remediated"],
        1
    );
    assert_eq!(
        parsed["control_attestations"]["ISO27001_A.8.24"]["broken_links"],
        0
    );
}
