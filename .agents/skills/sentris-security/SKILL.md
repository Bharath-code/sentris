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
