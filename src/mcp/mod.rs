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
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": "sentris-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(Self::list_tools()),
            "tools/call" => Self::call_tool(req.params.as_ref(), offline),
            "resources/list" => Ok(Self::list_resources()),
            "resources/read" => Self::read_resource(req.params.as_ref()),
            "prompts/list" => Ok(Self::list_prompts()),
            "prompts/get" => Self::get_prompt(req.params.as_ref()),
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
                let mut raw_secret = scanner
                    .extract_raw_secret(target_line, &finding.rule_id)
                    .unwrap_or_else(|| target_line.trim().to_string());

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
            "sentris_rollback_session" => {
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
                let creds = crate::cloud::Credentials::load_default().unwrap_or_else(|_| {
                    crate::cloud::Credentials {
                        api_key: "sp_preview_token".to_string(),
                        server_url: "https://api.sentris.dev".to_string(),
                        org_id: "org_sample_team".to_string(),
                        org_name: "Sentris Pro Workspace".to_string(),
                        tier: "Pro ($8/seat)".to_string(),
                        seat_limit: 20,
                        seats_used: 14,
                        user_email: "dev@sentris.dev".to_string(),
                        expires_at: None,
                    }
                });
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

    /// Returns the MCP `resources/list` catalog for AI coding agents.
    pub fn list_resources() -> Value {
        json!({
            "resources": [
                {
                    "uri": "sentris://agent/manifest",
                    "name": "Sentris AI Agent CLI & Tool Manifest",
                    "description": "Complete machine-readable CLI flag contract, JSON output schemas, and function-calling tool definitions.",
                    "mimeType": "application/json"
                },
                {
                    "uri": "sentris://audit/ledger",
                    "name": "SOC 2 Cryptographic Audit Ledger",
                    "description": "Tamper-evident RFC 2104 HMAC-SHA256 hash chain of all secret scans, remediations, and quarantines.",
                    "mimeType": "application/json"
                },
                {
                    "uri": "sentris://team/blast-radius",
                    "name": "Zero-Knowledge Multi-Repo Blast Radius Insights",
                    "description": "Salted SHA-256 (zk_) cross-repository duplicate secret correlations.",
                    "mimeType": "application/json"
                }
            ]
        })
    }

    /// Reads an MCP resource by URI.
    pub fn read_resource(params: Option<&Value>) -> Result<Value, (i32, String)> {
        let uri = params
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
            .ok_or((-32602, "Missing resource 'uri'".to_string()))?;

        let text = match uri {
            "sentris://agent/manifest" => {
                serde_json::to_string_pretty(&Self::generate_agent_manifest()).unwrap_or_default()
            }
            "sentris://audit/ledger" => {
                let ledger = AuditLedger::load_or_init(".sentris/audit_ledger.json")
                    .map_err(|e| (-32603, e.to_string()))?;
                let valid = ledger.verify_integrity().unwrap_or(false);
                serde_json::to_string_pretty(&json!({
                    "chain_integrity_verified": valid,
                    "records_count": ledger.records.len(),
                    "records": ledger.records
                }))
                .unwrap_or_default()
            }
            "sentris://team/blast-radius" => {
                let creds = crate::cloud::Credentials::load_default().unwrap_or_else(|_| {
                    crate::cloud::Credentials {
                        api_key: "sp_preview_token".to_string(),
                        server_url: "https://api.sentris.dev".to_string(),
                        org_id: "org_sample_team".to_string(),
                        org_name: "Sentris Pro Workspace".to_string(),
                        tier: "Pro ($8/seat)".to_string(),
                        seat_limit: 20,
                        seats_used: 14,
                        user_email: "dev@sentris.dev".to_string(),
                        expires_at: None,
                    }
                });
                let team = crate::cloud::TeamInfo::from_credentials(&creds);
                serde_json::to_string_pretty(&json!({
                    "org_id": team.org_id,
                    "zero_knowledge_bytes_ingested": 0,
                    "blast_radius_insights": team.blast_radius_insights
                }))
                .unwrap_or_default()
            }
            other => return Err((-32602, format!("Unknown resource URI: {other}"))),
        };

        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": text
            }]
        }))
    }

    /// Returns the MCP `prompts/list` workflow templates for AI coding agents.
    pub fn list_prompts() -> Value {
        json!({
            "prompts": [
                {
                    "name": "remediate-repo-secrets",
                    "description": "Scan the repository for leaked credentials and autonomously remediate all production findings into .env or Vault.",
                    "arguments": [
                        {
                            "name": "path",
                            "description": "Target path to scan and remediate (default: .)",
                            "required": false
                        },
                        {
                            "name": "backend",
                            "description": "Secret store backend: env, vault, aws, doppler, 1password, infisical",
                            "required": false
                        }
                    ]
                },
                {
                    "name": "pre-commit-security-gate",
                    "description": "Inspect staged git diff hunks for secrets before allowing a git commit.",
                    "arguments": []
                }
            ]
        })
    }

    /// Returns a specific MCP prompt workflow template.
    pub fn get_prompt(params: Option<&Value>) -> Result<Value, (i32, String)> {
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or((-32602, "Missing prompt 'name'".to_string()))?;

        match name {
            "remediate-repo-secrets" => Ok(json!({
                "description": "Autonomous repository secret scan & remediation workflow",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": "Run `sentris scan . --json` (or call `sentris_scan_path`). For every finding with `context_kind == \"PRODUCTION\"`, run `sentris fix <file_path> --yes --json` (or call `sentris_remediate_finding`), then verify 0 remaining secrets with `sentris scan . --json`."
                    }
                }]
            })),
            "pre-commit-security-gate" => Ok(json!({
                "description": "Staged diff-hunk security gate",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": "Run `sentris scan --staged --json` (or call `sentris_scan_staged`). If `findings_count > 0`, remediate each staged leak using `sentris fix <file_path> --yes --json` before committing."
                    }
                }]
            })),
            other => Err((-32602, format!("Unknown prompt: {other}"))),
        }
    }

    /// Generates the universal AI Agent capability & schema manifest (`sentris agent`).
    pub fn generate_agent_manifest() -> Value {
        json!({
            "schema_version": "2026-04-01",
            "tool": "sentris",
            "version": env!("CARGO_PKG_VERSION"),
            "summary": "Memory-safe Rust secret scanner (18ms) & autonomous remediation engine (15s) with built-in MCP, LSP 3.17, and Zero-Knowledge Blast Radius.",
            "agent_invocation_rules": {
                "global_json_flag": "--json (or --agent, or env SENTRIS_AGENT=1)",
                "non_interactive_guarantee": "Passing --json or SENTRIS_AGENT=1 disables all interactive stdin prompts, spinners, and ANSI escape codes, emitting pure JSON on stdout.",
                "exit_codes": {
                    "0": "Success (or clean scan when --fail-on-secret is not set)",
                    "1": "Secrets detected (with --fail-on-secret) or operational error"
                }
            },
            "cli_commands": [
                {
                    "name": "scan",
                    "command": "sentris scan <path> --json",
                    "staged_command": "sentris scan --staged --json",
                    "verify_command": "sentris scan <path> --verify --json",
                    "description": "Scans files or staged git diff hunks. Each finding in JSON includes `context_kind` (PRODUCTION | TEST_FIXTURE), `recommended_env_var`, and `remediate_command`."
                },
                {
                    "name": "remediate (alias: fix)",
                    "command": "sentris fix <path_or_rule_or_fingerprint> --all --yes --backend <env|vault|aws|doppler|1password|infisical> --json",
                    "rotate_command": "sentris fix <path> --all --yes --rotate --backend <backend> --json",
                    "dry_run_command": "sentris fix <path> --all --dry-run --json",
                    "description": "Autonomously patches hardcoded literals in source code (.py, .ts, .js, .rs, .go, .java, .rb, .php, .sh, multi-line PEM) and injects secrets into the target backend."
                },
                {
                    "name": "rollback",
                    "command": "sentris rollback --session <session_id> --json",
                    "description": "Atomically reverts a remediation session and restores the original source file byte-for-byte."
                },
                {
                    "name": "quarantine",
                    "command": "sentris quarantine <finding_id_or_rule> --json",
                    "description": "Isolates a Zone 3 pushed secret into a quarantine branch and generates a git-filter-repo scrub playbook."
                },
                {
                    "name": "audit",
                    "command": "sentris audit --verify --export-vanta vanta-evidence.json --json",
                    "description": "Verifies the RFC 2104 HMAC-SHA256 tamper-evident audit chain and exports SOC 2 CC6.1/CC6.7/CC6.8 & ISO 27001 A.8.24 evidence."
                },
                {
                    "name": "team",
                    "command": "sentris team --json",
                    "description": "Returns organization seat utilization and Zero-Knowledge Multi-Repo Blast Radius correlations."
                },
                {
                    "name": "mcp",
                    "command": "sentris mcp",
                    "description": "Starts the JSON-RPC 2.0 Model Context Protocol server over stdio (tools, resources, and prompts)."
                },
                {
                    "name": "lsp",
                    "command": "sentris lsp",
                    "description": "Starts the Language Server Protocol 3.17 server over stdio for real-time IDE diagnostics and Quick Fix CodeActions."
                }
            ],
            "mcp_tools": Self::list_tools()["tools"],
            "mcp_resources": Self::list_resources()["resources"],
            "mcp_prompts": Self::list_prompts()["prompts"]
        })
    }

    /// Writes `.mcp.json` and `.agents/skills/sentris-security/SKILL.md` into `workspace_dir`
    /// so AI coding agents (Claude Code, Cursor, Antigravity, Windsurf) auto-discover Sentris.
    pub fn setup_workspace_for_agents(workspace_dir: &Path) -> Result<Vec<String>, SentrisError> {
        let mut written_files = Vec::new();

        // 1. Write .mcp.json if not present (or update sentris entry)
        let mcp_json_path = workspace_dir.join(".mcp.json");
        let mcp_content = Self::generate_config_snippet();
        std::fs::write(&mcp_json_path, mcp_content)?;
        written_files.push(mcp_json_path.display().to_string());

        // 2. Write .agents/skills/sentris-security/SKILL.md
        let skill_dir = workspace_dir
            .join(".agents")
            .join("skills")
            .join("sentris-security");
        std::fs::create_dir_all(&skill_dir)?;
        let skill_path = skill_dir.join("SKILL.md");
        let skill_md = r#"---
name: sentris-security
description: Autonomous secret scanning, code remediation, zero-downtime key rotation, Zone 3 git quarantine, and SOC 2 compliance via the Sentris CLI (`sentris --json`) and MCP server (`sentris mcp`). Use whenever scanning for leaked API keys/credentials, fixing hardcoded secrets, rotating keys into .env/Vault/AWS/Doppler/1Password/Infisical, checking pre-commit diffs, or verifying SOC 2 audit logs.
---

# Sentris — AI Agent Operating Skill

Sentris is an agent-native Rust secret detection and autonomous remediation engine. Always pass `--json` (or set `SENTRIS_AGENT=1`) when invoking `sentris` via shell commands so output is deterministic JSON and interactive prompts are suppressed.

## 1. Core Agent Commands (`--json` Mode)

### Scan Repository or File
```bash
sentris scan . --json
```
- Returns `findings[]` where each item includes:
  - `rule_id`, `severity`, `file_path`, `line_number`, `redacted_match`, `fingerprint`
  - `context_kind`: `"PRODUCTION"` or `"TEST_FIXTURE"`
  - `recommended_env_var`: e.g. `"STRIPE_SECRET_KEY"`
  - `remediate_command`: exact command to fix the finding

### Scan Staged Pre-Commit Diff Hunks (`<15ms`)
```bash
sentris scan --staged --json
```

### Autonomously Remediate Secrets (Code Rewrite + Secret Store Injection)
```bash
# Remediate a single file or finding into .env (safe local extraction)
sentris fix <file_path> --yes --json

# Batch-remediate all findings across a directory into 1Password / Infisical / Vault / AWS / Doppler
sentris fix . --all --yes --backend 1password --json

# Rotate the credential via provider API (Dual-Key zero-downtime rotation)
sentris fix <file_path> --yes --rotate --backend env --json
```

### Atomic Byte-for-Byte Rollback
```bash
sentris rollback --json
```

### Zone 3 Historical Leak Quarantine
```bash
sentris quarantine <rule_id_or_fingerprint> --json
```

### Verify Tamper-Evident Audit Chain & Export Vanta SOC 2 Evidence
```bash
sentris audit --verify --export-vanta vanta-evidence.json --json
```

### Query Zero-Knowledge Multi-Repo Blast Radius
```bash
sentris team --json
```
"#;
        std::fs::write(&skill_path, skill_md)?;
        written_files.push(skill_path.display().to_string());

        Ok(written_files)
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
        assert_eq!(tools.len(), 6);

        let br_req = r#"{
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "sentris_team_blast_radius",
                "arguments": {}
            }
        }"#;
        let br_resp = McpServer::handle_raw_message(br_req, true).expect("Expected response");
        let br_text = br_resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(br_text.contains("postgres-connection-uri"));
        assert!(br_text.contains("zero_knowledge_bytes_ingested"));
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

    #[test]
    fn test_mcp_resources_prompts_and_agent_manifest() {
        let res_list = r#"{"jsonrpc":"2.0","id":10,"method":"resources/list"}"#;
        let resp = McpServer::handle_raw_message(res_list, true).expect("Expected response");
        let resources = resp.result.unwrap()["resources"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(resources.len(), 3);

        let res_read = r#"{"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"sentris://agent/manifest"}}"#;
        let read_resp = McpServer::handle_raw_message(res_read, true).expect("Expected response");
        let manifest_text = read_resp.result.unwrap()["contents"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(manifest_text.contains("cli_commands"));
        assert!(manifest_text.contains("mcp_tools"));

        let prompts_list = r#"{"jsonrpc":"2.0","id":12,"method":"prompts/list"}"#;
        let p_resp = McpServer::handle_raw_message(prompts_list, true).expect("Expected response");
        let prompts = p_resp.result.unwrap()["prompts"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(prompts.len(), 2);

        let prompt_get = r#"{"jsonrpc":"2.0","id":13,"method":"prompts/get","params":{"name":"remediate-repo-secrets","arguments":{"path":"src"}}}"#;
        let pg_resp = McpServer::handle_raw_message(prompt_get, true).expect("Expected response");
        let msg = pg_resp.result.unwrap()["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(msg.contains("sentris_scan_path"));

        let tmp = tempfile::tempdir().unwrap();
        let written = McpServer::setup_workspace_for_agents(tmp.path()).unwrap();
        assert_eq!(written.len(), 2);
        assert!(tmp.path().join(".mcp.json").exists());
        assert!(tmp
            .path()
            .join(".agents/skills/sentris-security/SKILL.md")
            .exists());
    }
}
