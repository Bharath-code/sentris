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
                        "text": "Run `sentris scan . --json` (or call `sentris_scan_path`). For every finding with `context_kind == \"PRODUCTION\"`, run `sentris fix <file_path> --yes --json` (or call `sentris_remediate_finding`), then verify 0 remaining secrets with `sentris scan . --json`. MCP remediation is preview-only by default: call `sentris_remediate_finding` with dry_run=true, then (only if the server was started with SENTRIS_MCP_ALLOW_WRITES=1) repeat with dry_run=false and the returned confirm_token."
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
    #[allow(clippy::too_many_lines)]
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
                    "staged_fix_command": "sentris scan --staged --fix --json",
                    "ignore_tests_command": "sentris scan <path> --ignore-tests --json",
                    "docker_command": "sentris scan --docker <image-or-tar> --json",
                    "stdin_command": "sentris scan --stdin --json",
                    "workstation_command": "sentris scan --workstation --json",
                    "verify_command": "sentris scan <path> --verify --json",
                    "probe_command": "sentris scan <path> --probe --json",
                    "from_report_command": "sentris scan --from-report <report.json> --json",
                    "description": "Scans files, staged git diff hunks (with optional --fix), Docker/OCI container layers (with Ghost Layer detection), stdin streams, or workstation AI/MCP configs & .jsonl transcripts. Each finding in JSON includes `context_kind` (PRODUCTION | TEST_FIXTURE), `recommended_env_var`, and `remediate_command`."
                },
                {
                    "name": "drift (aliases: rot, doctor)",
                    "command": "sentris drift <path> [--max-age-days 90] [--verify] [--webhook <url>] [--fail-on-drift] --json",
                    "rot_command": "sentris rot <path> [--verify] [--webhook <url>] [--fail-on-rot] --json",
                    "description": "Audits Secret Rot & Configuration Drift across code, `.env.example`, and `.env`/vault: computes `vault_coverage_pct`, `rot_score_pct`, `stale_keys` (>90d unrotated), `dead_or_revoked_keys` (live provider check), `shadow_env_vars` (orphaned `.env` keys), missing runtime keys, and hardcoded leaks."
                },
                {
                    "name": "remediate (alias: fix)",
                    "command": "sentris fix <path_or_rule_or_fingerprint> --all --yes --backend <env|vault|aws|doppler|1password|infisical> --json",
                    "workstation_command": "sentris fix --workstation --yes --json",
                    "rotate_command": "sentris fix <path> --rotate --yes --json",
                    "dry_run_command": "sentris fix <path> --all --dry-run --json",
                    "description": "Autonomously patches hardcoded literals in source code (.py, .ts, .js, .rs, .go, .java, .rb, .php, .sh, multi-line PEM), IaC (.github/workflows, .tf, Dockerfile, .mcp.json), and AI transcripts (.jsonl, .zsh_history) and injects secrets into the target backend without argv exposure."
                },
                {
                    "name": "run",
                    "command": "sentris run --backend <env|vault|aws|doppler|1password|infisical> --key <NAME>... -- <cmd> [args...]",
                    "description": "Fetches secrets from the chosen backend directly into child process environment memory (no .env on disk), zeroizes parent buffers, and refuses {{secret:...}} in argv."
                },
                {
                    "name": "revoke",
                    "command": "sentris revoke [finding_id_or_path] [--api] [--wait] --json",
                    "description": "Guided or API-driven credential revocation with 2-second live verification polling (--wait), post-remediation historical secret lookup, and SOC 2 KeyDeactivated audit logging."
                },
                {
                    "name": "investigate",
                    "command": "sentris investigate [finding_id_or_path] [--known-ip <IP>...] --json",
                    "description": "Read-only forensics for a leaked credential: earliest git commit introduction (even after remediation), `.github/CODEOWNERS` owner attribution, and AWS CloudTrail event history."
                },
                {
                    "name": "rotate",
                    "command": "sentris rotate <status|finish|undo> [rotation_id] [--force] [--delete-old] --json",
                    "description": "Inspects, completes, or reverts live provider key rotations started with `sentris fix --rotate` (AWS IAM access keys and Cloudflare API tokens)."
                },
                {
                    "name": "rollback",
                    "command": "sentris rollback [--session <session_id>] --json",
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
                    "description": "Verifies the RFC 2104 HMAC-SHA256 tamper-evident audit chain and exports SOC 2 CC6.1/CC6.7/CC6.8, ISO 27001 A.8.24, OWASP NHI Top 10:2025 (with live Vault Coverage %), and PCI-DSS v4.0 evidence."
                },
                {
                    "name": "install",
                    "command": "sentris install [--with-ai] [--auto-fix] [--force] --json",
                    "description": "Installs sub-35ms pre-commit & pre-push git hooks (with optional `--auto-fix` self-healing mode and `--with-ai` MCP/Claude Code hook scaffolding)."
                },
                {
                    "name": "hook",
                    "command": "sentris hook [--print-config] [--fail-closed]",
                    "description": "Claude Code / AI Agent stdin hook firewall blocking plaintext secrets and invisible Unicode tag injection across UserPromptSubmit, PreToolUse, and PostToolUse."
                },
                {
                    "name": "sync",
                    "command": "sentris sync [path] [--repo <name>] [--branch <name>] --json",
                    "description": "Synchronizes zero-knowledge organization-salted HMAC-SHA256 (`zk_`) findings to Sentris Pro Cloud with 0 bytes of source code transmitted."
                },
                {
                    "name": "team",
                    "command": "sentris team --json",
                    "description": "Returns organization seat utilization and Zero-Knowledge Multi-Repo Blast Radius correlations."
                },
                {
                    "name": "auth",
                    "command": "sentris auth <login|status|logout> [--token <sp_live_...>] [--team-secret <hex>] --json",
                    "description": "Manages Sentris Pro Cloud developer authentication and zero-knowledge 64-hex team secret configuration."
                },
                {
                    "name": "mcp",
                    "command": "sentris mcp [--print-config]",
                    "description": "Starts the JSON-RPC 2.0 Model Context Protocol server over stdio (14 tools, 3 resources, and 2 prompts)."
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

    /// Writes `.mcp.json`, `.agents/skills/sentris-security/SKILL.md`, and `.claude/settings.local.json`
    /// into `workspace_dir` so AI coding agents (Claude Code, Cursor, Antigravity, Windsurf) auto-discover
    /// Sentris and enforce the Pre/PostToolUse secret firewall.
    #[allow(clippy::too_many_lines)]
    pub fn setup_workspace_for_agents(workspace_dir: &Path) -> Result<Vec<String>, SentrisError> {
        let mut written_files = Vec::new();

        // 1. Write or merge .mcp.json without clobbering existing mcpServers entries
        let mcp_json_path = workspace_dir.join(".mcp.json");
        let snippet: Value =
            serde_json::from_str(&Self::generate_config_snippet()).unwrap_or_else(|_| json!({}));
        let merged_mcp = if let Ok(existing_raw) = std::fs::read_to_string(&mcp_json_path) {
            if let Ok(mut existing_val) = serde_json::from_str::<Value>(&existing_raw) {
                if let (Some(existing_servers), Some(new_servers)) = (
                    existing_val
                        .get_mut("mcpServers")
                        .and_then(|v| v.as_object_mut()),
                    snippet.get("mcpServers").and_then(|v| v.as_object()),
                ) {
                    for (k, v) in new_servers {
                        existing_servers.insert(k.clone(), v.clone());
                    }
                    existing_val
                } else {
                    snippet
                }
            } else {
                snippet
            }
        } else {
            snippet
        };
        std::fs::write(
            &mcp_json_path,
            serde_json::to_string_pretty(&merged_mcp).unwrap_or_default(),
        )?;
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
description: Autonomous secret scanning, code remediation, secret extraction into backends, Zone 3 git quarantine, and SOC 2 compliance via the Sentris CLI (`sentris --json`) and MCP server (`sentris mcp`). Use whenever scanning for leaked API keys/credentials, fixing hardcoded secrets, moving keys into .env/Vault/AWS/Doppler/1Password/Infisical, checking pre-commit diffs, or verifying SOC 2 audit logs.
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

### Scan Staged Pre-Commit Diff Hunks (`<15ms`), Docker Images, Stdin Streams, or Workstation AI/MCP Configs & Transcripts
```bash
sentris scan --staged --json
sentris scan --staged --fix --json
sentris scan . --ignore-tests --json
sentris scan --docker <image-or-tar> --json
sentris scan --workstation --json
gh run view --log | sentris scan --stdin --json
sentris scan . --probe --json
sentris rot . --verify --json
sentris drift . --max-age-days 90 --fail-on-drift --json
```

### Autonomously Remediate Secrets (Code / IaC / MCP Rewrite + Secret Store Injection + Transcript Scrubbing)
```bash
# Remediate a single file or finding into .env (safe local extraction; supports source code, .github/workflows, .tf, Dockerfile, .mcp.json)
sentris fix <file_path> --yes --json

# Remediate workstation AI/MCP configs (.mcp.json) and scrub local AI .jsonl transcripts & shell histories
sentris fix --workstation --yes --json

# Batch-remediate all findings across a directory into 1Password / Infisical / Vault / AWS / Doppler (zero argv leaks)
sentris fix . --all --yes --backend 1password --json

# Key rotation is supported for AWS IAM access keys and Cloudflare API tokens (sentris fix <file> --rotate --yes --json, then sentris rotate finish <id>); for every other provider revoke the old key with `sentris revoke <target> --wait --json`
# Forensics for a leaked key (read-only, including CODEOWNERS attribution & post-remediation lookup): sentris investigate <file> --json [--known-ip <ip>]
```

### Run Commands Without `.env` on Disk (`sentris run`)
```bash
sentris run --backend 1password -- npm start
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

        // 3. Write or merge .claude/settings.local.json with UserPromptSubmit, PreToolUse, and PostToolUse hooks
        let claude_dir = workspace_dir.join(".claude");
        std::fs::create_dir_all(&claude_dir)?;
        let claude_settings_path = claude_dir.join("settings.local.json");
        let hook_cfg: Value =
            serde_json::from_str(&crate::hook::config_snippet()).unwrap_or_else(|_| json!({}));
        let merged_claude = if let Ok(existing_raw) = std::fs::read_to_string(&claude_settings_path)
        {
            if let Ok(mut existing_val) = serde_json::from_str::<Value>(&existing_raw) {
                if let (Some(obj), Some(hooks)) =
                    (existing_val.as_object_mut(), hook_cfg.get("hooks"))
                {
                    obj.insert("hooks".to_string(), hooks.clone());
                    existing_val
                } else {
                    hook_cfg
                }
            } else {
                hook_cfg
            }
        } else {
            hook_cfg
        };
        std::fs::write(
            &claude_settings_path,
            serde_json::to_string_pretty(&merged_claude).unwrap_or_default(),
        )?;
        written_files.push(claude_settings_path.display().to_string());

        Ok(written_files)
    }
}
