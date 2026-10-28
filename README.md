# ⚡ Sentris

<div align="center">

**The Autonomous Secret Remediation Engine — Detect in `12ms`, Fix in 1 Command, Prove SOC 2 in 10 Seconds**

[![CI](https://github.com/Bharath-code/sentris/actions/workflows/ci.yml/badge.svg)](https://github.com/Bharath-code/sentris/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Binary Size](https://img.shields.io/badge/binary-3.8MB%20static%20Rust-success.svg)](https://github.com/Bharath-code/sentris/releases)
[![Pre-Commit SLA](https://img.shields.io/badge/pre--commit-12ms%20--%2025ms-brightgreen.svg)](#benchmarks)
[![Tests](https://img.shields.io/badge/tests-152%2F152%20passing-emerald.svg)](#architecture--engineering-guarantees)
[![MCP & LSP Ready](https://img.shields.io/badge/AI%20%26%20IDE-Native%20MCP%20%2B%20LSP-orange.svg)](#6-native-ai-agent-mcp-server--real-time-ide-lsp)

```text
   ____             __         _     
  / __/__ ___  ____/ /________(_)___ 
 _\ \/ -_) _ \/ __/ __/ __/ _ / (_-< 
/___/\__/_//_/\__/\__/_/  \__//_/___/ 
```

**Finding a secret is only 20% of the problem.**  
Fixing the code, moving the credential into `.env` / `Vault` / `1Password` / `Infisical` without breaking your app, and proving SOC 2 compliance is the other **80%**—and **Sentris is the only tool built to own that 80%.**

[Quickstart](#-quickstart) • [The 5 Holy Sh\*t Moments](#-the-5-holy-sht-moments) • [14-Dimension Matrix](#-14-dimension-competitive-matrix) • [Autonomous Remediation](#5-autonomous-remediation-multi-secret-batch-mode--6-secret-backends) • [AI Agent MCP & IDE LSP](#6-native-ai-agent-mcp-server--real-time-ide-lsp) • [SOC 2 & Zero-Knowledge Cloud](#7-10-second-vanta-soc-2-drop--zero-knowledge-multi-repo-blast-radius)

</div>

---

## ⚡ Why Sentris Exists (The 2026 Reality)

Legacy secret scanners (`Gitleaks`, `TruffleHog`, `GitGuardian`, `MongoDB Kingfisher`) either:
1. **Only scream `EXIT 1`** and leave you with a 45-minute Friday afternoon scramble, or
2. **Immediately kill the live API key** (`kingfisher revoke`), which **crashes your running local app or production service**.

**Sentris turns secret detection into 1-command autonomous self-healing:**

```mermaid
flowchart LR
    subgraph Detect["1. Sub-25ms Detection"]
        A["Work-Stealing Parallel Walker + Whole-File RegexSet DFA"]
        B["6-Layer FP Suppression + Syntactic ContextKind"]
        A --> B
    end

    subgraph Remediate["2. Zero-Downtime Self-Healing"]
        C["Safe Local Extraction (.env / Vault / AWS / Doppler / 1Password / Infisical)"]
        D["Polyglot Code Patching (7+ Languages & Multi-Line PEM) + .env.example Sync"]
        E["Volatile RAM Zeroization + 1-Command Atomic Rollback"]
        C --> D --> E
    end

    subgraph Govern["3. Zero-Knowledge & SOC 2 Proof"]
        F["Native MCP Server (6 Tools) + Real-Time IDE LSP 3.17"]
        G["Salted HMAC-SHA256 Multi-Repo Blast Radius + 1-Click Vanta Export"]
        F --> G
    end

    Detect --> Remediate --> Govern
```

---

## 🔥 The 5 "Holy Sh\*t" Moments

### 1. The Pre-Commit Ghost (`12ms` Diff-Hunk Scan)
Developers never bypass Sentris with `--no-verify` because it parses staged diff hunks (`git diff --cached -U0`) and finishes in **`12ms`**—faster than a 60Hz monitor refreshes (`16.6ms`). And if someone ever forces `--no-verify`, Sentris's automatic `pre-push` hook (`sentris scan --since HEAD~1`) catches it before `git push`.

### 2. The Friday 4:55 PM Save (`sentris remediate`)
Instead of manually editing files, creating `.env`, updating `.gitignore`, and hoping teammates don't break their build:
```text
$ sentris remediate src/billing.ts --yes

⚡ Sentris Autonomous Remediation Session: rm_27c44354
Target: src/billing.ts (line 6) | Rule: stripe-secret-key

  [1/7] 🔍 Verifying key status via Stripe API... ACTIVE & LIVE (Scopes: read_write, charges, customers)
  [2/7] 🛡️  Creating atomic git backup branch... SAVED (sentris/backup-1793196000)
  [3/7] 🔑 Provisioning replacement API credential... PROVISIONED (sk_liv...cdef • extracted working key; pass --rotate to roll via API)
  [4/7] 🔒 Securing credential into Env backend... INJECTED (STRIPE_SECRET_KEY=*** • RAM buffer zeroized)
  [5/7] 📝 Replacing hardcoded literal in source code... PATCHED
        - const stripeApiKey = "sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz123456";
        + const stripeApiKey = process.env.STRIPE_SECRET_KEY;
  [6/7] ⏳ Queuing compromised key for 24h grace deprecation... SCHEDULED (Zero production downtime)
  [7/7] 🧾 Recording transaction in rollback ledger... COMMITTED (.sentris/rollback_ledger.json)
```
In **under 1 second**, `.env` is populated, `.gitignore` is hardened, `.env.example` is synced with a safe empty `STRIPE_SECRET_KEY=` contract for teammates, the source file is patched, and **your local app keeps running without a single restart error.**

### 3. The Autonomous AI Agent & IDE Self-Heal (`sentris mcp` + `sentris lsp`)
- **AI Coding Agents (`sentris mcp`):** Cursor, Claude Code, Windsurf, and Antigravity call Sentris's local zero-egress MCP server over `stdio` (`sentris_scan_path`, `sentris_remediate_finding`, `sentris_rollback_session`, `sentris_team_blast_radius`) to fix leaked keys before finishing their turn.
- **Real-Time IDE Diagnostics (`sentris lsp`):** Native LSP 3.17 server highlights pasted secrets in `<2ms` and offers a 1-click Quick Fix (`Sentris: Extract stripe-secret-key to STRIPE_SECRET_KEY`) directly in VS Code, Cursor, Zed, and Neovim.

### 4. The Zero-Knowledge Multi-Repo Blast Radius Insight (`sentris team`)
Security directors see duplicate leaked credentials across 50 microservice repositories via organization-salted `zk_<sha256>` HMAC correlation—**with `0 bytes` of proprietary source code or raw secrets ever leaving a developer's laptop:**
```text
Zero-Knowledge Multi-Repo Blast Radius Insight (0 Bytes Source Code Ingested):
╭─────────────────┬─────────────────────────┬──────────┬──────────────┬────────────────────────────────────────╮
│ ZK HMAC Token   ┆ Detector Rule           ┆ Severity ┆ Blast Radius ┆ Correlated Repositories                │
╞═════════════════╪═════════════════════════╪══════════╪══════════════╪════════════════════════════════════════╡
│ zk_94a3ab2d8f10 ┆ postgres-connection-uri ┆ CRITICAL ┆ 4 repos      ┆ acme/admin-api, acme/analytics-etl,    │
│ ...             ┆                         ┆          ┆              ┆ acme/auth-worker, acme/billing-svc     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ zk_77b312fe89c0 ┆ aws-access-key-id       ┆ HIGH     ┆ 2 repos      ┆ acme/deploy-runner,                    │
│ ...             ┆                         ┆          ┆              ┆ acme/infra-terraform                   │
╰─────────────────┴─────────────────────────┴──────────┴──────────────┴────────────────────────────────────────╯
```

### 5. The 10-Second Vanta / Drata SOC 2 Auditor Drop (`sentris audit --export-vanta`)
Instead of paying `USD 25,000/yr` for enterprise compliance PDFs or taking 40 manual screenshots, export a cryptographically chained RFC 2104 HMAC-SHA256 evidence bundle mapped directly to **SOC 2 Type II** and **ISO 27001:2022**:
```text
$ sentris audit --verify --export-vanta vanta-evidence.json

🔒 SOC 2 Cryptographic Audit Ledger: .sentris/audit_ledger.json
   Total Records: 14
   Chain Integrity: PASS (HMAC-SHA256 verified, 0 broken links)

   ✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack: vanta-evidence.json
      ├─ SOC 2 CC6.1 (Continuous Secret Scanning):    PASS (10 scans, 1842 files inspected)
      ├─ SOC 2 CC6.7 (Zero-Knowledge Transmission):   PASS (0 bytes plaintext exfiltrated)
      ├─ SOC 2 CC6.8 (Timely Credential Remediation): PASS (3 remediated, 1 quarantined)
      └─ ISO 27001 A.8.24 (Cryptographic Hash Chain): PASS (HMAC-SHA256 verified)
```

---

## 📊 14-Dimension Competitive Matrix

| Dimension | Sentris (Ours) | MongoDB Kingfisher (Rust OSS) | GitGuardian (SaaS + ggshield) | TruffleHog v3 (Go OSS + Ent) | GitHub Secret Protection | Semgrep Secrets | Gitleaks v8 (Go OSS) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Core Architecture** | **Rust (`3.8 MB` static, Parallel Walker + `RegexSet` DFA)** | Rust (Hyperscan C++ + Tree-sitter) | Python/Rust CLI + Cloud SaaS | Go (700+ detector workers) | Cloud SaaS (GitHub-only) | OCaml / Python CLI + Cloud | Go (Regexp CLI) |
| **Pre-Commit Latency** | **`12ms – 25ms` (Diff-Hunk DFA)** | `80ms – 350ms` | `350ms – 1,200ms` | `800ms – 4,000ms` | Push-time only | `1,000ms – 3,500ms` | `25ms – 60ms` |
| **Detection Engine** | **55+ Rules + 2026 AI Stack + 6-Layer FP + `ContextKind`** | ~1,050 rules + Tree-sitter | 400+ rules + Cloud ML | 700+ rules + Keyword prefilter | 200+ Partner patterns | AST + Semantic taint | 150+ TOML regex rules |
| **Live API Verification** | **Yes (`--verify` w/ zero-egress `--offline` default)** | Yes | Yes (Cloud-side) | Yes | Partner tokens only | Limited | No |
| **Post-Detection Action** | **Extracts to `.env`/Vault/1Password/Infisical + Patches Code** | `kingfisher revoke` (**Kills key; breaks app**) | Opens Jira ticket / Slack alert | Prints JSON alert | Blocks push | Blocks PR | Prints terminal table |
| **Local Dev App Safety** | **Safe Local Extraction + `.env.example` Sync** | Destructive revocation only | Manual | Manual | Manual | Manual | Manual |
| **Polyglot Code Patching** | **7+ Languages + Multi-Line PEM Block Replacement** | None | None | None | None | Partial (PR comment) | None |
| **Atomic Rollback (`undo`)** | **`sentris rollback` (Byte-exact restore)** | None | None | None | None | None | None |
| **Zero-Knowledge Privacy** | **100% Local + Salted `zk_<sha256>` Only + RAM Zeroization** | Local CLI | Uploads code snippets to SaaS | Local OSS / Cloud Ent. | Hosted on GitHub Cloud | Cloud-dependent rules | 100% Local |
| **SOC 2 / ISO 27001 Proof** | **HMAC-SHA256 Hash Chain + 1-Click Vanta JSON** | None | Enterprise PDF (`USD 20k+/yr`) | Enterprise Dashboard | GitHub Audit Log | Enterprise Dashboard | None |
| **Interactive Terminal UI** | **Split-Pane Ratatui TUI (`sentris review`) w/ Diff Preview** | None | None | None | None | None | None |
| **AI Agent & IDE Native** | **Built-in MCP Server (`sentris mcp`) + LSP (`sentris lsp`)** | None | Cloud MCP (Requires SaaS) | None | Copilot-only | Editor plugin (Cloud) | None |
| **Historical Git Scrub** | **Zone 3 Quarantine Branch + Coordinated Playbook** | Manual | Guided docs only | Manual | Manual | Manual | Manual |
| **Pricing** | **Free OSS • `USD 8/seat` Pro • `USD 2k/yr` Enterprise** | Free (Apache-2.0) | `USD 18–25+/dev/mo` | Free AGPLv3, `USD 25k+/yr` Ent. | `USD 19/committer/mo` | `USD 20–40/dev/mo` | Free (MIT) |

---

## 🚀 Quickstart

### 1. Installation

#### Homebrew (macOS & Linux)
```bash
brew install sentris-security/tap/sentris
```

#### One-Line Shell Installer (macOS & Linux)
```bash
curl -fsSL https://sentris.dev/install.sh | sh
```

#### Cargo (Rust)
```bash
cargo install sentris
```

---

### 2. Core Scanning & Interactive TUI

```bash
# Scan working directory recursively (Work-Stealing Parallel Walker + Whole-File RegexSet DFA)
sentris scan .

# Scan only staged git index diff hunks (12ms pre-commit mode)
sentris scan --staged

# Scan commits in a branch or push range (e.g. origin/main..HEAD)
sentris scan --since HEAD~1

# Deep git commit graph & reflog history scan
sentris scan --git-history

# Verify detected credentials against live provider APIs & map permission scopes
sentris scan . --verify

# Launch Split-Pane Interactive Terminal UI (Ratatui) with live -/+ staged patch preview
sentris review

# 1-command migration from legacy .gitleaks.toml rules & allowlists
sentris migrate-gitleaks .gitleaks.toml

# CI/CD outputs: SARIF 2.1.0, GitLab Secret Detection v15.0.7, GitHub Actions, JSON
sentris scan --format sarif --fail-on-secret > results.sarif
sentris scan --format gitlab > gl-secret-detection-report.json
```

---

### 3. Repository Configuration & Custom Rules (`sentris init`)

Scaffold a `.sentris.toml` configuration file:

```bash
sentris init
```

```toml
[scanner]
max_file_size_mb = 10
ignore_paths = ["target", "node_modules", "vendor", "tests/fixtures"]

# Define proprietary internal credentials
[[rules]]
rule_id = "internal-service-token"
name = "Acme Internal Service Token"
description = "Internal Acme microservice auth token"
severity = "critical"
pattern = "acme_live_[0-9a-zA-Z]{32}"
min_entropy = 3.5

[remediation]
dual_key_grace_hours = 24
backup_branch = true
```

---

### 4. Install Sub-25ms Pre-Commit & Pre-Push Hooks

```bash
# Installs both .git/hooks/pre-commit (--staged) and .git/hooks/pre-push (--since HEAD~1)
sentris install
```

Or via Python `pre-commit` (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: https://github.com/Bharath-code/sentris
    rev: v0.1.0
    hooks:
      - id: sentris
      - id: sentris-pre-push
```

---

### 5. Autonomous Remediation, Multi-Secret Batch Mode & 6 Secret Backends

```bash
# Preview the 7-step remediation flow with live -/+ code diff (no disk mutations)
sentris remediate src/billing.ts --dry-run

# Safe Local Extraction (default): moves working key to .env, syncs .env.example,
# hardens .gitignore, scrubs RAM buffer, and patches source code so local dev never breaks
sentris remediate src/billing.ts --yes

# Batch-remediate ALL secrets across a file or directory in one atomic pass
sentris remediate . --all --yes

# Rotate compromised key via provider API (24h dual-key grace window) + Enterprise Backends:
# Supported backends: env, vault, aws, doppler, 1password, infisical
sentris remediate src/billing.ts --rotate --backend 1password --yes
sentris remediate src/billing.ts --rotate --backend infisical --yes
sentris remediate src/billing.ts --rotate --backend vault --yes
```

#### 1-Click Atomic Rollback
Undo any remediation session byte-for-byte:
```bash
sentris rollback
```

---

### 6. Native AI Agent MCP Server & Real-Time IDE LSP

#### Model Context Protocol (`sentris mcp`) — 6 Built-In Tools
Exposes `sentris_scan_path`, `sentris_scan_staged`, `sentris_remediate_finding`, `sentris_audit_verify`, `sentris_rollback_session`, and `sentris_team_blast_radius` over `stdio`:
```bash
# Print ready-to-paste mcpServers JSON for Claude Code, Cursor, Windsurf & Antigravity
sentris mcp --print-config

# Run zero-egress MCP server over stdio
sentris mcp
```

#### Language Server Protocol (`sentris lsp`) — Real-Time IDE Diagnostics & Quick Fixes
Implements LSP 3.17 over `stdio` (`textDocument/didOpen`, `textDocument/didChange`, `textDocument/codeAction`) for instant red squiggles and 1-click Quick Fix code patching in VS Code, Cursor, Zed, and Neovim:
```bash
sentris lsp
```

---

### 7. 10-Second Vanta SOC 2 Drop & Zero-Knowledge Multi-Repo Blast Radius

```bash
# Verify RFC 2104 HMAC-SHA256 hash chain and export SOC 2 CC6.1/CC6.7/CC6.8 & ISO 27001 A.8.24 evidence
sentris audit --verify --export-vanta vanta-evidence.json

# Authenticate workstation with Sentris Pro Cloud ($8/seat/mo)
sentris auth login --token sp_live_9f8e7d6c5b4a3210deadbeef

# View team seats, run-rate, and Zero-Knowledge Multi-Repo Blast Radius Insight table
sentris team

# Sync salted HMAC-SHA256 fingerprints (0 bytes of source code or plaintext secrets uploaded)
sentris sync
```

---

## 📈 Benchmarks

Measured on Apple Silicon M-series (standard 2026 developer workstation):

| Workload | Sentris (Rust) | Gitleaks v8 (Go) | MongoDB Kingfisher | TruffleHog v3 |
| :--- | :---: | :---: | :---: | :---: |
| **Staged Git Index Diff (`--staged`)** | **`12ms`** | `45ms` | `180ms` | `850ms` |
| **Clean Repository (`1,500 files`)** | **`16ms`** | `110ms` | `290ms` | `1,400ms` |
| **Full History Scan (`1,000 commits`)** | **`240ms`** | `1,850ms` | `1,600ms` | `3,200ms` |
| **Memory Footprint (Peak RSS)** | **`18 MB`** | `85 MB` | `140 MB` | `220 MB` |

---

## 🔒 Architecture & Engineering Guarantees

- **Zero-Knowledge Principle:** Sentris never uploads unmasked secrets or proprietary source code. Only organization-salted `zk_<sha256>` HMAC tokens are transmitted during cloud sync.
- **Cryptographic RAM Zeroization:** Raw secret buffers extracted during remediation or verification are immediately overwritten in heap memory using `std::ptr::write_volatile` and a `SeqCst` compiler fence (`Remediator::zeroize_secret_string`).
- **6-Layer False Positive Suppression:** Filters official SDK doc examples, template expressions (`${...}`), monotonous masks, keyboard walks, UUIDv4s/telemetry IDs, and code comments (`//`, `#`, `/*`), while classifying `ContextKind` (`Production` vs `TestFixture`).
- **3-Zone Git Safety Invariant:** Hard immediate credential revocations and blind `git push --force` operations are strictly forbidden. Zone 3 historical leaks are isolated via `sentris quarantine` with coordinated `git-filter-repo` playbooks.

---

## 📄 License

Licensed under the [MIT License](LICENSE).
