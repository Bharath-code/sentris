---
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

### Scan Staged Pre-Commit Diff Hunks (`<15ms`), Stdin Streams, or Workstation AI/MCP Configs & Transcripts
```bash
sentris scan --staged --json
sentris scan --workstation --json
gh run view --log | sentris scan --stdin --json
sentris scan . --probe --json
```

### Autonomously Remediate Secrets (Code / IaC / MCP Rewrite + Secret Store Injection + Transcript Scrubbing)
```bash
# Remediate a single file or finding into .env (safe local extraction; supports source code, .github/workflows, .tf, Dockerfile, .mcp.json)
sentris fix <file_path> --yes --json

# Remediate workstation AI/MCP configs (.mcp.json) and scrub local AI .jsonl transcripts & shell histories
sentris fix --workstation --yes --json

# Batch-remediate all findings across a directory into 1Password / Infisical / Vault / AWS / Doppler (zero argv leaks)
sentris fix . --all --yes --backend 1password --json

# Key rotation exists for AWS IAM access keys only (sentris fix <file> --rotate --yes --json, then sentris rotate finish <id>)
# For other providers, use guided or API-driven revocation with live polling:
sentris revoke <file_path_or_rule_id> --wait --json
sentris revoke github-pat --api --wait --json
```

### Run Commands Without `.env` on Disk (`sentris run`)
```bash
# Fetch secrets from any backend directly into child process memory (never written to disk)
sentris run --backend 1password --key STRIPE_SECRET_KEY --key DATABASE_URL -- npm start
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
