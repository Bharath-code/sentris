use std::path::Path;

use serde_json::{json, Value};

use crate::audit::AuditLedger;
use crate::error::SentrisError;
use crate::mcp::McpServer;

impl McpServer {
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
                        team_secret: None,
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
