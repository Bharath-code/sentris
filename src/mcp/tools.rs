use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::audit::AuditLedger;
use crate::mcp::McpServer;
use crate::remediator::Remediator;
use crate::scanner::Scanner;

type ToolErr = (i32, String);

/// Root every agent-supplied path must stay inside: `SENTRIS_WORKSPACE`, else the server's cwd.
fn workspace() -> Result<PathBuf, ToolErr> {
    let root = std::env::var_os("SENTRIS_WORKSPACE")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|e| (-32603, e.to_string()))?;
    root.canonicalize().map_err(|e| (-32603, e.to_string()))
}

/// Resolves `p` (symlinks included) and rejects anything outside the workspace.
fn confine(p: &str) -> Result<PathBuf, ToolErr> {
    confine_in(&workspace()?, p)
}

fn confine_in(root: &Path, p: &str) -> Result<PathBuf, ToolErr> {
    let root = root.canonicalize().map_err(|e| (-32603, e.to_string()))?;
    let resolved = root
        .join(p)
        .canonicalize()
        .map_err(|e| (-32602, format!("Cannot access '{p}': {e}")))?;
    if resolved.starts_with(&root) {
        Ok(resolved)
    } else {
        Err((-32602, format!("Path '{p}' is outside the workspace")))
    }
}

/// File-modifying tools stay off unless the human who launched the server opts in.
fn require_writes() -> Result<(), ToolErr> {
    let on = std::env::var("SENTRIS_MCP_ALLOW_WRITES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if on {
        Ok(())
    } else {
        Err((
            -32001,
            "Write tools are disabled. Preview with dry_run, then run `sentris fix` yourself, or start the MCP server with SENTRIS_MCP_ALLOW_WRITES=1".to_string(),
        ))
    }
}

/// Binds a real write to the exact finding that was previewed.
fn confirm_token(f: &crate::model::Finding, backend: &str) -> Result<String, ToolErr> {
    let msg = format!(
        "{}|{}|{}|{backend}",
        f.fingerprint, f.file_path, f.line_number
    );
    crate::keystore::mac_hex("mcp-confirm", msg.as_bytes())
        .map(|m| m[..16].to_string())
        .map_err(|e| (-32603, e.to_string()))
}

impl McpServer {
    /// Returns the MCP `tools/list` schema for AI coding agents.
    pub fn list_tools() -> Value {
        json!({
            "tools": [
                {
                    "name": "sentris_scan_path",
                    "description": "Scan a file or directory for hardcoded API keys, tokens, and credentials in <25ms. Returns zero-knowledge redacted findings and canonical environment variable names.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File or directory path to scan (defaults to '.')"
                            }
                        }
                    }
                },
                {
                    "name": "sentris_scan_staged",
                    "description": "Scan git staged index changes (git diff --cached) before committing code.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "sentris_remediate_finding",
                    "description": "Safely remediate a hardcoded secret by extracting it into .env / Vault / AWS Secrets Manager / Doppler and replacing the code literal with the idiomatic environment variable accessor.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Target file path containing the secret"
                            },
                            "backend": {
                                "type": "string",
                                "description": "Secret backend: env, vault, aws, or doppler (default: env)"
                            },
                            "fingerprint": {
                                "type": "string",
                                "description": "Fingerprint of the finding to remediate when the file has several (default: the first)"
                            },
                            "confirm": {
                                "type": "string",
                                "description": "Required when dry_run=false: the confirm_token returned by a dry_run=true call for this exact finding. Writes also need SENTRIS_MCP_ALLOW_WRITES=1 on the server"
                            },
                            "rotate": {
                                "type": "boolean",
                                "description": "If true, NOT SUPPORTED yet: returns an error. Leave false; revoke the old key at the provider after remediation"
                            },
                            "dry_run": {
                                "type": "boolean",
                                "description": "Preview only, no files modified (default: true). Set false together with confirm to write"
                            }
                        },
                        "required": ["file_path"]
                    }
                },
                {
                    "name": "sentris_audit_verify",
                    "description": "Verify the SOC 2 / ISO 27001 cryptographic HMAC-SHA256 hash chain audit ledger.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "ledger_path": {
                                "type": "string",
                                "description": "Path to audit ledger file (default: .sentris/audit_ledger.json)"
                            }
                        }
                    }
                },
                {
                    "name": "sentris_rollback_session",
                    "description": "Atomically revert a previous remediation session and restore the original file line byte-for-byte.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "string",
                                "description": "Optional session ID (e.g. rm_a1b2c3d4). Defaults to the most recent session."
                            }
                        }
                    }
                },
                {
                    "name": "sentris_team_blast_radius",
                    "description": "Query the Zero-Knowledge Multi-Repo Blast Radius Insight table correlating duplicate salted HMAC-SHA256 secrets across repositories with 0 bytes of source code ingested.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }
            ]
        })
    }

    pub(crate) fn call_tool(params: Option<&Value>, offline: bool) -> Result<Value, (i32, String)> {
        let params = params.ok_or((-32602, "Missing params object".to_string()))?;
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or((-32602, "Missing tool 'name'".to_string()))?;
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        match name {
            "sentris_scan_path" => {
                let target_path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
                let target = confine(target_path)?;
                let scanner = Scanner::new().map_err(|e| (-32603, e.to_string()))?;
                let report = scanner
                    .scan_path(&target)
                    .map_err(|e| (-32603, e.to_string()))?;

                let enriched_findings: Vec<Value> = report
                    .findings
                    .iter()
                    .map(|f| {
                        let env_var = Remediator::env_var_name_for_rule(&f.rule_id);
                        json!({
                            "rule_id": f.rule_id,
                            "severity": f.severity,
                            "file_path": f.file_path,
                            "line_number": f.line_number,
                            "column": f.column,
                            "redacted_match": f.redacted_match,
                            "entropy": f.entropy,
                            "fingerprint": f.fingerprint,
                            "recommended_env_var": env_var,
                        })
                    })
                    .collect();

                let payload = json!({
                    "status": if report.findings.is_empty() { "clean" } else { "secrets_detected" },
                    "files_scanned": report.stats.files_scanned,
                    "duration_ms": report.stats.duration_ms,
                    "findings_count": report.findings.len(),
                    "findings": enriched_findings,
                });

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                    }],
                    "isError": false
                }))
            }
            "sentris_scan_staged" => {
                let scanner = Scanner::new().map_err(|e| (-32603, e.to_string()))?;
                let report = scanner.scan_staged().map_err(|e| (-32603, e.to_string()))?;

                let payload = json!({
                    "status": if report.findings.is_empty() { "clean" } else { "secrets_detected" },
                    "staged_files_scanned": report.stats.files_scanned,
                    "duration_ms": report.stats.duration_ms,
                    "findings_count": report.findings.len(),
                    "findings": report.findings,
                });

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                    }],
                    "isError": false
                }))
            }
            "sentris_remediate_finding" => {
                let file_path = args
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .ok_or((-32602, "Missing required argument 'file_path'".to_string()))?;
                let backend = args
                    .get("backend")
                    .and_then(|v| v.as_str())
                    .unwrap_or("env");
                let rotate = args
                    .get("rotate")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // Preview unless the caller explicitly asks for a write
                let dry_run = args
                    .get("dry_run")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let confirm = args.get("confirm").and_then(|v| v.as_str()).unwrap_or("");
                if !dry_run {
                    require_writes()?;
                }

                let target = confine(file_path)?;
                let scanner = Scanner::new().map_err(|e| (-32603, e.to_string()))?;
                let report = scanner
                    .scan_path(&target)
                    .map_err(|e| (-32603, e.to_string()))?;

                let wanted = args.get("fingerprint").and_then(|v| v.as_str());
                let picked = match wanted {
                    Some(fp) => report.findings.iter().find(|f| f.fingerprint == fp),
                    None => report.findings.first(),
                };
                let finding = match picked {
                    Some(f) => f,
                    None => {
                        return Ok(json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&json!({
                                    "status": "clean",
                                    "message": "No secrets detected in target file."
                                })).unwrap_or_default()
                            }],
                            "isError": false
                        }));
                    }
                };

                let token = confirm_token(finding, backend)?;
                if !dry_run && !crate::keystore::ct_eq(confirm, &token) {
                    return Err((
                        -32602,
                        "Missing or stale 'confirm': run with dry_run=true first and pass its confirm_token".to_string(),
                    ));
                }

                let content = std::fs::read_to_string(&finding.file_path)
                    .map_err(|e| (-32603, e.to_string()))?;
                let mut raw_secret = scanner
                    .resolve_finding_secret(&content, finding)
                    .map_err(|e| (-32603, e.to_string()))?;
                let env_var = Remediator::resolve_env_var_name(finding, &raw_secret, backend);

                let remediator = Remediator::new();
                let res = remediator.remediate_finding_with_options(
                    finding,
                    &raw_secret,
                    dry_run,
                    Some(backend),
                    offline,
                    rotate,
                    true,
                );
                Remediator::zeroize_secret_string(&mut raw_secret);
                let session_id = res.map_err(|e| (-32603, e.to_string()))?;

                let backend_is_mock =
                    crate::remediator::backend::SecretBackendFactory::from_name(backend)
                        .map(|b| b.is_mock())
                        .unwrap_or(false);
                let payload = json!({
                    "status": if dry_run { "preview" } else { "remediated" },
                    "confirm_token": if dry_run { Some(token.clone()) } else { None },
                    "session_id": session_id,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "rule_id": finding.rule_id,
                    "env_var_injected": env_var,
                    "backend": backend,
                    "mode": if rotate { "provider_rotation" } else { "safe_local_extraction" },
                    "mock": !dry_run && backend_is_mock,
                    "key_revoked": false,
                    "dry_run": dry_run,
                });

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                    }],
                    "isError": false
                }))
            }
            "sentris_audit_verify" => {
                let requested = args
                    .get("ledger_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".sentris/audit_ledger.json");
                let ledger_path = confine(requested)?;
                let ledger_path = ledger_path.to_string_lossy();

                let ledger = AuditLedger::load_or_init(ledger_path.as_ref())
                    .map_err(|e| (-32603, e.to_string()))?;
                let valid = ledger.verify_integrity().unwrap_or(false);

                let payload = json!({
                    "ledger_path": ledger_path,
                    "records_count": ledger.records.len(),
                    "chain_integrity_verified": valid,
                });

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                    }],
                    "isError": !valid
                }))
            }
            "sentris_rollback_session" => {
                require_writes()?;
                let mut ledger = crate::remediator::rollback::RollbackLedger::load()
                    .map_err(|e| (-32603, e.to_string()))?;
                let target_session = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| ledger.transactions.last().map(|t| t.session_id.clone()));

                let Some(sess_id) = target_session else {
                    return Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&json!({
                                "status": "no_sessions",
                                "message": "No remediation sessions recorded in rollback ledger."
                            })).unwrap_or_default()
                        }],
                        "isError": false
                    }));
                };

                let msg = ledger
                    .revert(&sess_id)
                    .map_err(|e| (-32603, e.to_string()))?;
                let payload = json!({
                    "status": "rolled_back",
                    "session_id": sess_id,
                    "message": msg,
                });

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                    }],
                    "isError": false
                }))
            }
            "sentris_team_blast_radius" => {
                let creds = crate::cloud::Credentials::load_default().map_err(|_| {
                    (
                        -32001,
                        "Not logged in: run `sentris auth login --token <KEY>` first".to_string(),
                    )
                })?;
                let team = crate::cloud::TeamInfo::from_credentials(&creds);
                let payload = json!({
                    "org_id": team.org_id,
                    "org_name": team.org_name,
                    "zero_knowledge_bytes_ingested": 0,
                    "blast_radius_insights": team.blast_radius_insights,
                });

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                    }],
                    "isError": false
                }))
            }
            other => Err((-32601, format!("Unknown tool: {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confine_rejects_escapes_and_outside_symlinks() {
        let ws = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("ok.txt"), "x").unwrap();
        std::fs::write(outside.path().join("secret.txt"), "x").unwrap();

        assert!(confine_in(ws.path(), "ok.txt").is_ok());
        assert!(confine_in(ws.path(), ".").is_ok());
        assert!(confine_in(ws.path(), "/").is_err());
        assert!(confine_in(ws.path(), "..").is_err());
        assert!(confine_in(ws.path(), outside.path().to_str().unwrap()).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), ws.path().join("link")).unwrap();
            assert!(confine_in(ws.path(), "link/secret.txt").is_err());
        }
    }

    #[test]
    fn real_remediation_without_opt_in_is_refused_and_file_unchanged() {
        let ws = tempfile::tempdir().unwrap();
        let f = ws.path().join("a.py");
        let src = "k = \"sk_live_abcdefghijklmnopqrstuvwx\"\n";
        std::fs::write(&f, src).unwrap();
        let params = json!({"name":"sentris_remediate_finding","arguments":{
            "file_path": f.to_str().unwrap(), "dry_run": false, "confirm": "x"}});
        let err = McpServer::call_tool(Some(&params), true).unwrap_err();
        assert!(err.1.contains("disabled") || err.1.contains("outside the workspace"));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), src);
    }
}
