use std::io::{self, BufRead, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::audit::AuditLedger;
use crate::error::SentrisError;
use crate::remediator::Remediator;
use crate::scanner::Scanner;

/// JSON-RPC 2.0 Request frame for Model Context Protocol (MCP).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 Response frame for Model Context Protocol (MCP).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

pub struct McpServer;

impl McpServer {
    /// Generates the ready-to-paste MCP configuration snippet for Cursor, Claude Code, and Antigravity.
    pub fn generate_config_snippet() -> String {
        let cfg = json!({
            "mcpServers": {
                "sentris": {
                    "command": "sentris",
                    "args": ["mcp"],
                    "description": "High-performance zero-knowledge secret scanner & autonomous safe remediator"
                }
            }
        });
        serde_json::to_string_pretty(&cfg).unwrap_or_default()
    }

    /// Runs the stdio JSON-RPC 2.0 MCP loop for AI coding agents.
    pub fn run_stdio_loop(offline: bool) -> Result<(), SentrisError> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line_res in stdin.lock().lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => break,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(resp) = Self::handle_raw_message(trimmed, offline) {
                if let Ok(serialized) = serde_json::to_string(&resp) {
                    let _ = writeln!(stdout, "{serialized}");
                    let _ = stdout.flush();
                }
            }
        }

        Ok(())
    }

    /// Processes a single JSON-RPC 2.0 request line and returns an optional response.
    /// Notifications (requests without an `id`) return `None`.
    pub fn handle_raw_message(raw_json: &str, offline: bool) -> Option<JsonRpcResponse> {
        let req: JsonRpcRequest = match serde_json::from_str(raw_json) {
            Ok(r) => r,
            Err(err) => {
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(json!({
                        "code": -32700,
                        "message": format!("Parse error: {err}")
                    })),
                });
            }
        };

        // JSON-RPC notifications (e.g., notifications/initialized) do not expect a response
        let id = req.id?;

        let result = match req.method.as_str() {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "sentris-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(Self::list_tools()),
            "tools/call" => Self::call_tool(req.params.as_ref(), offline),
            other => Err((-32601, format!("Method not found: {other}"))),
        };

        match result {
            Ok(val) => Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(val),
                error: None,
            }),
            Err((code, msg)) => Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(json!({
                    "code": code,
                    "message": msg
                })),
            }),
        }
    }

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
                            "rotate": {
                                "type": "boolean",
                                "description": "If true, provision a rotated replacement credential instead of extracting the existing working key (default: false)"
                            },
                            "dry_run": {
                                "type": "boolean",
                                "description": "Preview remediation without modifying files (default: false)"
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
                }
            ]
        })
    }

    fn call_tool(params: Option<&Value>, offline: bool) -> Result<Value, (i32, String)> {
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
                let scanner = Scanner::new().map_err(|e| (-32603, e.to_string()))?;
                let report = scanner
                    .scan_path(Path::new(target_path))
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
                let dry_run = args
                    .get("dry_run")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let scanner = Scanner::new().map_err(|e| (-32603, e.to_string()))?;
                let report = scanner
                    .scan_path(Path::new(file_path))
                    .map_err(|e| (-32603, e.to_string()))?;

                let finding = match report.findings.first() {
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

                let content = std::fs::read_to_string(&finding.file_path)
                    .map_err(|e| (-32603, e.to_string()))?;
                let lines: Vec<&str> = content.lines().collect();
                let target_line = lines
                    .get(finding.line_number.saturating_sub(1))
                    .copied()
                    .unwrap_or("");
                let raw_secret = scanner
                    .extract_raw_secret(target_line, &finding.rule_id)
                    .unwrap_or_else(|| target_line.trim().to_string());

                let remediator = Remediator::new();
                let session_id = remediator
                    .remediate_finding_with_mode(
                        finding,
                        &raw_secret,
                        dry_run,
                        Some(backend),
                        offline,
                        rotate,
                    )
                    .map_err(|e| (-32603, e.to_string()))?;

                let env_var = Remediator::env_var_name_for_rule(&finding.rule_id);
                let payload = json!({
                    "status": "remediated",
                    "session_id": session_id,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "rule_id": finding.rule_id,
                    "env_var_injected": env_var,
                    "backend": backend,
                    "mode": if rotate { "provider_rotation" } else { "safe_local_extraction" },
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
                let ledger_path = args
                    .get("ledger_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".sentris/audit_ledger.json");

                let ledger =
                    AuditLedger::load_or_init(ledger_path).map_err(|e| (-32603, e.to_string()))?;
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
            other => Err((-32601, format!("Unknown tool: {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_initialize_and_tools_list() {
        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = McpServer::handle_raw_message(init_req, true).expect("Expected response");
        assert_eq!(resp.id, json!(1));
        let res = resp.result.unwrap();
        assert_eq!(res["protocolVersion"], "2024-11-05");
        assert_eq!(res["serverInfo"]["name"], "sentris-mcp");

        let list_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let list_resp = McpServer::handle_raw_message(list_req, true).expect("Expected response");
        let tools = list_resp.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn test_mcp_scan_path_tool_call() {
        let call_req = r#"{
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "sentris_scan_path",
                "arguments": {
                    "path": "tests/fixtures/sample_leak.ts"
                }
            }
        }"#;
        let resp = McpServer::handle_raw_message(call_req, true).expect("Expected response");
        let res = resp.result.unwrap();
        assert_eq!(res["isError"], false);
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("stripe-secret-key"));
        assert!(text.contains("STRIPE_SECRET_KEY"));
    }

    #[test]
    fn test_mcp_config_snippet() {
        let snippet = McpServer::generate_config_snippet();
        assert!(snippet.contains("mcpServers"));
        assert!(snippet.contains("sentris"));
    }
}
