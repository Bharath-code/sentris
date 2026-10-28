use super::*;
use crate::model::{Finding, ScanStats};

fn create_test_finding(
    rule_id: &str,
    severity: Severity,
    file: &str,
    line: usize,
    preview: &str,
    entropy: f64,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        description: format!("Identifies {}", rule_id),
        severity,
        file_path: file.to_string(),
        line_number: line,
        column: 15,
        redacted_match: preview.to_string(),
        entropy,
        fingerprint: "test-fingerprint-123".to_string(),
        commit_hash: None,
    }
}

fn create_test_report(findings: Vec<Finding>, duration_ms: u128) -> ScanReport {
    let count = findings.len();
    ScanReport {
        timestamp: "2026-10-07T18:54:21Z".to_string(),
        version: "0.1.0".to_string(),
        stats: ScanStats {
            files_scanned: 15,
            files_ignored: 2,
            bytes_scanned: 10240,
            findings_count: count,
            duration_ms,
        },
        findings,
    }
}

#[test]
fn test_format_slack_card_critical() {
    let findings = vec![create_test_finding(
        "aws-access-key-id",
        Severity::Critical,
        "src/config/aws.rs",
        42,
        "AKIA...7EXA",
        3.84,
    )];
    let report = create_test_report(findings, 45);

    let card = WebhookReporter::format_slack_card(&report);

    let text = card["text"].as_str().expect("text should be string");
    assert!(text.contains("🚨"));
    assert!(text.contains("Critical Red"));
    assert!(text.contains("1 secrets detected"));
    assert!(text.contains("45ms"));

    let color = card["attachments"][0]["color"].as_str().unwrap();
    assert_eq!(color, "#E01E5A");

    let blocks = card["blocks"].as_array().expect("blocks should be array");
    assert!(blocks.len() >= 5);

    let header_text = blocks[0]["text"]["text"].as_str().unwrap();
    assert!(header_text.contains("🚨 Sentris Incident Alert: Secrets Detected"));

    let summary_fields = blocks[1]["fields"].as_array().unwrap();
    let branding_field = summary_fields[0]["text"].as_str().unwrap();
    assert!(branding_field.contains("🔴 Critical Red"));

    let count_field = summary_fields[1]["text"].as_str().unwrap();
    assert!(count_field.contains("1 detected"));

    let duration_field = summary_fields[2]["text"].as_str().unwrap();
    assert!(duration_field.contains("45ms"));

    let finding_block_text = blocks[3]["text"]["text"].as_str().unwrap();
    assert!(finding_block_text.contains("aws-access-key-id"));
    assert!(finding_block_text.contains("src/config/aws.rs:42"));
    assert!(finding_block_text.contains("3.84"));
    assert!(finding_block_text.contains("AKIA...7EXA"));

    let action_block_text = blocks.last().unwrap()["text"]["text"].as_str().unwrap();
    assert!(action_block_text.contains(
        "Run 'sentris remediate' to move the secret out of source (then revoke the old key)"
    ));
}

#[test]
fn test_format_slack_card_high_orange() {
    let findings = vec![create_test_finding(
        "slack-webhook-url",
        Severity::High,
        "deploy/notify.sh",
        12,
        "https://hooks.slack.com/services/...xyz",
        2.95,
    )];
    let report = create_test_report(findings, 28);

    let card = WebhookReporter::format_slack_card(&report);

    let color = card["attachments"][0]["color"].as_str().unwrap();
    assert_eq!(color, "#EC6C00");

    let text = card["text"].as_str().unwrap();
    assert!(text.contains("High Orange"));
    assert!(text.contains("⚠️"));

    let blocks = card["blocks"].as_array().unwrap();
    let summary = blocks[1]["fields"][0]["text"].as_str().unwrap();
    assert!(summary.contains("🟠 High Orange"));

    let finding_text = blocks[3]["text"]["text"].as_str().unwrap();
    assert!(finding_text.contains("slack-webhook-url"));
    assert!(finding_text.contains("deploy/notify.sh:12"));
    assert!(finding_text.contains("2.95"));
}

#[test]
fn test_format_discord_card_critical() {
    let findings = vec![create_test_finding(
        "stripe-secret-key",
        Severity::Critical,
        "backend/payments.rs",
        88,
        "sk_live_...999",
        4.15,
    )];
    let report = create_test_report(findings, 62);

    let card = WebhookReporter::format_discord_card(&report);

    let content = card["content"].as_str().unwrap();
    assert!(content.contains("🚨"));
    assert!(content.contains("Critical Red"));
    assert!(content.contains("1 secrets detected"));

    let embeds = card["embeds"].as_array().expect("embeds must be array");
    assert_eq!(embeds.len(), 1);

    let embed = &embeds[0];
    assert_eq!(embed["color"].as_u64().unwrap(), 15158332);

    let desc = embed["description"].as_str().unwrap();
    assert!(desc.contains(
        "Run 'sentris remediate' to move the secret out of source (then revoke the old key)"
    ));

    let fields = embed["fields"].as_array().unwrap();
    assert_eq!(fields[0]["name"].as_str().unwrap(), "📊 Scan Summary");
    let summary_val = fields[0]["value"].as_str().unwrap();
    assert!(summary_val.contains("🔴 Critical Red"));
    assert!(summary_val.contains("Finding Count:** 1"));
    assert!(summary_val.contains("Scan Duration:** 62ms"));

    let finding_field = &fields[1];
    assert!(finding_field["name"]
        .as_str()
        .unwrap()
        .contains("stripe-secret-key"));
    let val = finding_field["value"].as_str().unwrap();
    assert!(val.contains("backend/payments.rs:88"));
    assert!(val.contains("4.15"));
    assert!(val.contains("sk_live_...999"));

    let action_field = fields.last().unwrap();
    assert_eq!(
        action_field["name"].as_str().unwrap(),
        "🛡️ Recommended Action"
    );
    assert_eq!(
        action_field["value"].as_str().unwrap(),
        "Run 'sentris remediate' to move the secret out of source (then revoke the old key)"
    );
}

#[test]
fn test_format_discord_card_high_orange() {
    let findings = vec![create_test_finding(
        "discord-webhook-url",
        Severity::High,
        "scripts/alert.js",
        5,
        "https://discord.com/api/webhooks/...abc",
        3.10,
    )];
    let report = create_test_report(findings, 19);

    let card = WebhookReporter::format_discord_card(&report);

    let embed = &card["embeds"][0];
    assert_eq!(embed["color"].as_u64().unwrap(), 15105570);

    let summary = embed["fields"][0]["value"].as_str().unwrap();
    assert!(summary.contains("🟠 High Orange"));
    assert!(summary.contains("Scan Duration:** 19ms"));
}

#[test]
fn test_format_cards_clean_repository() {
    let report = create_test_report(Vec::new(), 10);

    let slack = WebhookReporter::format_slack_card(&report);
    assert_eq!(
        slack["attachments"][0]["color"].as_str().unwrap(),
        "#2EB886"
    );
    let slack_text = slack["text"].as_str().unwrap();
    assert!(slack_text.contains("CLEAN"));
    assert!(slack_text.contains("0 secrets detected"));

    let discord = WebhookReporter::format_discord_card(&report);
    let embed = &discord["embeds"][0];
    assert_eq!(embed["color"].as_u64().unwrap(), 3066993);
    let discord_content = discord["content"].as_str().unwrap();
    assert!(discord_content.contains("CLEAN"));
}

#[test]
fn test_post_incident_card_dry_run() {
    let findings = vec![create_test_finding(
        "aws-access-key-id",
        Severity::Critical,
        "test.rs",
        1,
        "AKIA...7EXA",
        3.8,
    )];
    let report = create_test_report(findings, 50);

    let slack_res = WebhookReporter::post_incident_card(
        "https://hooks.slack.com/services/T000/B000/XXXX",
        &report,
        true,
    );
    assert!(slack_res.is_ok());
    let msg = slack_res.unwrap();
    assert!(msg.contains("[DRY RUN]"));
    assert!(msg.contains("Slack"));
    assert!(msg.contains("1 findings"));

    let discord_res = WebhookReporter::post_incident_card(
        "https://discord.com/api/webhooks/12345/abcdef",
        &report,
        true,
    );
    assert!(discord_res.is_ok());
    let msg = discord_res.unwrap();
    assert!(msg.contains("[DRY RUN]"));
    assert!(msg.contains("Discord"));
    assert!(msg.contains("1 findings"));
}

#[test]
fn test_post_incident_card_empty_url() {
    let report = create_test_report(Vec::new(), 10);
    let res = WebhookReporter::post_incident_card("", &report, false);
    assert!(res.is_err());
    match res.unwrap_err() {
        SentrisError::Webhook(msg) => assert!(msg.contains("empty")),
        _ => panic!("Expected SentrisError::Webhook"),
    }
}

#[test]
fn test_post_incident_card_offline_transport_error() {
    let findings = vec![create_test_finding(
        "aws-access-key-id",
        Severity::Critical,
        "test.rs",
        1,
        "AKIA...7EXA",
        3.8,
    )];
    let report = create_test_report(findings, 50);

    let res = WebhookReporter::post_incident_card("http://127.0.0.1:9/webhook", &report, false);
    assert!(res.is_err());
    match res.unwrap_err() {
        SentrisError::Webhook(msg) => {
            assert!(msg.contains("transport") || msg.contains("offline") || msg.contains("failed"));
        }
        _ => panic!("Expected SentrisError::Webhook"),
    }
}
