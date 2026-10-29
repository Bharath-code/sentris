use serde_json::{json, Value};

use super::tools::{confine, text_result, workspace, ToolErr};
use crate::audit::{AuditAction, AuditLedger};
use crate::error::SentrisError;
use crate::investigate::investigate_target;
use crate::scanner::Scanner;

fn tool_err(e: SentrisError) -> ToolErr {
    match e {
        SentrisError::Refused(msg) => (-32001, msg),
        other => (-32603, other.to_string()),
    }
}

/// Read-only forensics for one finding; the only external call is a CloudTrail lookup with ambient credentials.
pub(super) fn investigate(args: &Value) -> Result<Value, ToolErr> {
    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    let target = confine(path)?;
    let finding_id = args.get("finding_id").and_then(Value::as_str);
    let known_ips: Vec<String> = args
        .get("known_ips")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let root = workspace()?;
    let scanner = Scanner::new().map_err(tool_err)?;
    let inv = investigate_target(&scanner, &target, finding_id, &known_ips, &root)
        .map_err(tool_err)?
        .ok_or((-32602, "No matching finding to investigate".to_string()))?;
    if inv.supported {
        record_run(&inv.finding_id, &inv.rule_id);
    }
    Ok(text_result(inv.to_json(), false))
}

fn record_run(finding_id: &str, rule_id: &str) {
    let Ok(root) = workspace() else { return };
    if let Ok(mut ledger) = AuditLedger::load_or_init(root.join(".sentris/audit_ledger.json")) {
        let _ = ledger.record_event(
            AuditAction::InvestigationRun {
                finding_id: finding_id.to_string(),
                provider: "AWS".to_string(),
            },
            json!({"rule_id": rule_id, "via": "mcp"}),
        );
        let _ = ledger.save();
    }
}
