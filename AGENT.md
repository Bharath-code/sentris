# AGENT.md — Sentris Systems Architecture, AI Agent (MCP/LSP) & Engineering Handbook

> **Target Audience:** AI Coding Agents (Claude Code, Cursor, Antigravity, Windsurf, OpenAI Codex/Agents, LangGraph, CrewAI, Aider) & Systems Engineers.  
> **Project:** Sentris (`sentris`)  
> **Binary Footprint:** `3.8 MB` stripped static Rust binary (`rustls`, zero C/C++/Python/Node runtime dependencies)  
> **Test Suite Status:** **155 / 155 Passing** (`130` unit + `24` CLI integration + `1` throughput SLA benchmark, `0` Clippy warnings)

---

## 1. Mission & 7 Non-Negotiable System Invariants

Sentris is a high-performance, memory-safe, zero-knowledge secret scanner and autonomous remediation engine written in Rust.

When modifying or extending this repository, **you must preserve all 7 Non-Negotiable Invariants**:

1. **Zero-Knowledge Privacy:** Raw source code and unmasked secrets **never leave the user's machine**. Cloud sync (`sentris sync` / `sentris scan --cloud`) transmits only organization-salted `zk_<sha256>` HMAC tokens.
2. **Safe Local Extraction Default & Dual-Key Rotation Safety:**
   - By default, `sentris remediate <file>` performs **Safe Local Extraction** (extracting the working key into `.env`, syncing an empty `KEY=` contract into `.env.example`, hardening `.gitignore`, and rewriting source code to an environment variable accessor) so local development **never breaks**.
   - When `--rotate` is passed, Sentris provisions a replacement credential via the provider API and queues the old key for a 24-hour deprecation grace window—**never immediate destructive revocation**.
3. **Cryptographic RAM Zeroization:** Every mutable `String` buffer holding a raw secret during remediation or live verification must be scrubbed immediately after use via `Remediator::zeroize_secret_string` (`std::ptr::write_volatile` + `compiler_fence(Ordering::SeqCst)`).
4. **3-Tiered Git Remediation Safety:**
   - *Zone 1 (Working Tree / Staged Hunks):* In-place polyglot code patching + `.env` / Vault / 1Password / Infisical injection (`<20ms`).
   - *Zone 2 (Local Unpushed Commits):* Pre-push range scanning (`sentris scan --since HEAD~1`).
   - *Zone 3 (Remote Historical Commits):* **Never blind force-push.** Isolate via `sentris quarantine <id>` to create a `sentris/quarantine-<id>` branch and generate a `.sentris/quarantine_qz_<id>_playbook.md` `git-filter-repo` runbook.
5. **Performance SLA as a Hard Invariant:**
   - Work-stealing parallel directory traversal (`ignore::WalkBuilder::build_parallel`) + whole-file `RegexSet` DFA prefiltering (`multi_line(true)`).
   - Staged diff-hunk pre-commit scan (`git diff --cached -U0`) must execute in `< 25ms`.
   - Full scan over 1,000+ files must sustain `> 10,000 files/sec` (enforced by `tests/benchmark_test.rs`).
6. **Zero Uncontrolled Panics & Terminal Safety:**
   - Never call `.unwrap()` on fallible I/O in library paths (`src/scanner/`, `src/detector/`, `src/remediator/`, `src/mcp/`, `src/lsp/`).
   - Interactive TUI (`src/tui/`) must always guard raw mode with `TerminalGuard` (`Drop` restoration).
7. **Tamper-Evident Compliance Chain:**
   - Every scan, remediation, baseline, and quarantine event appends an RFC 2104 `HMAC-SHA256` chained record to `.sentris/audit_ledger.json`, verifiable and exportable to Vanta/Drata (`sentris audit --verify --export-vanta`) with formal `SOC 2 CC6.1 / CC6.7 / CC6.8` and `ISO 27001 A.8.24` control attestations.

---

## 2. Exact Workspace Structure & Module Map

```text
sentris/
├── Cargo.toml                      # Rust 2021 crate manifest & LTO/strip release profile
├── README.md                       # Public documentation & 14-dimension competitive matrix
├── AGENT.md                        # AI Agent & Systems Engineering handbook (this file)
├── .pre-commit-hooks.yaml          # Pre-commit & pre-push hook definitions
├── action.yml                      # Composite GitHub Action with SARIF upload
├── Dockerfile                      # Hardened distroless/Alpine multi-stage container
├── Formula/sentris.rb              # Homebrew tap formula
├── install.sh                      # POSIX curl | sh installer
├── src/
│   ├── lib.rs                      # Library root exporting all 15 core modules
│   ├── main.rs                     # Minimal 7-line binary entry point delegating to sentris::cli::handlers
│   ├── model.rs                    # Finding, Severity, ContextKind (Production vs TestFixture), ScanReport
│   ├── error.rs                    # Centralized SentrisError (thiserror)
│   ├── audit/
│   │   ├── mod.rs                  # AuditAction, AuditRecord, and append-only AuditLedger hash chain
│   │   ├── crypto.rs               # RFC 2104 HMAC-SHA256 & repository/workstation audit salt derivation
│   │   ├── vanta.rs                # 1-Click Vanta/Drata SOC 2 (CC6.1/CC6.7/CC6.8) & ISO 27001 exporter
│   │   └── tests.rs                # Tamper-detection & hash-chain integrity test suite
│   ├── cli/
│   │   ├── mod.rs                  # Clap v4 CLI structs, flags, and subcommands
│   │   ├── completions.rs          # Shell completions (bash, zsh, fish, powershell, elvish)
│   │   └── handlers/               # Modular CLI subcommand execution handlers
│   │       ├── mod.rs              # Top-level subcommand router
│   │       ├── scan.rs             # Scan, baseline filter, live verification, webhook & cloud sync
│   │       ├── remediate.rs        # Remediate, rollback, and Zone 3 quarantine handlers
│   │       ├── review.rs           # Interactive Ratatui review & baseline snapshot handlers
│   │       ├── audit.rs            # Audit ledger, gitleaks migration, git hook & init handlers
│   │       └── cloud.rs            # Auth, sync, team blast-radius, MCP, LSP & AI agent handlers
│   ├── cloud/
│   │   ├── mod.rs                  # Zero-Knowledge Pro Cloud module exports
│   │   ├── auth.rs                 # License token parser & ~/.sentris/credentials.json storage
│   │   ├── client.rs               # Salted zk_<sha256> payload builder & Multi-Repo Blast Radius correlation
│   │   └── team.rs                 # Team seat overview & Multi-Repo Blast Radius terminal table
│   ├── config/
│   │   ├── mod.rs                  # .sentris.toml parser & custom enterprise regex rules
│   │   └── gitleaks_migrator.rs    # 1-command .gitleaks.toml -> .sentris.toml converter
│   ├── detector/
│   │   ├── mod.rs                  # DetectorEngine (Whole-file RegexSet DFA + capture-group & PEM extraction)
│   │   ├── patterns.rs             # 55+ precision rules (AWS, Stripe, OpenAI, Anthropic, Groq, Supabase, etc.)
│   │   ├── entropy.rs              # Shannon information entropy calculator
│   │   ├── false_positives.rs      # 6-Layer False Positive Suppression Engine
│   │   └── baseline.rs             # Cryptographic fingerprint baseline snapshot (.sentris-baseline.json)
│   ├── git/
│   │   ├── mod.rs                  # Staged diff-hunk parser (-U0), --since range scanner, hook installer
│   │   └── quarantine.rs           # Zone 3 quarantine brancher & git-filter-repo playbook generator
│   ├── lsp/
│   │   └── mod.rs                  # Native Language Server Protocol (LSP 3.17) over stdio (diagnostics + quickfix)
│   ├── mcp/
│   │   ├── mod.rs                  # Native Model Context Protocol (MCP JSON-RPC 2.0) server & router
│   │   ├── tools.rs                # 6 MCP tools (scan_path, scan_staged, remediate, rollback, audit, blast_radius)
│   │   └── manifest.rs             # MCP resources, prompts, AI Agent manifest & workspace scaffolder
│   ├── remediator/
│   │   ├── mod.rs                  # 7-step remediation pipeline & volatile RAM zeroization
│   │   ├── backend/                # Modular Secret Store Backends
│   │   │   ├── mod.rs              # SecretStoreBackend trait, SecretBackendType & SecretBackendFactory
│   │   │   ├── env.rs              # .env local file driver
│   │   │   ├── vault.rs            # HashiCorp Vault KV v2 driver
│   │   │   ├── aws.rs              # AWS Secrets Manager driver
│   │   │   ├── doppler.rs          # Doppler Secrets driver
│   │   │   ├── onepassword.rs      # 1Password op:// reference & CLI driver
│   │   │   └── infisical.rs        # Infisical secret manager driver
│   │   ├── code_replacer/          # Polyglot AST-like code replacer (10+ languages + multi-line PEM blocks)
│   │   │   ├── mod.rs              # Language-aware env accessor generator & literal/PEM replacer
│   │   │   ├── accessor_tests.rs   # Accessor generation unit tests
│   │   │   └── replacement_tests.rs# String & PEM replacement unit tests
│   │   ├── env_patcher.rs          # .env injector, .gitignore hardener, and .env.example contract syncer
│   │   └── rollback.rs             # Byte-exact atomic rollback ledger (.sentris/rollback_ledger.json)
│   ├── reporter/
│   │   ├── mod.rs                  # ANSI/ASCII table renderer, JSON exporter, GitHub Actions annotations
│   │   ├── sarif.rs                # OASIS SARIF v2.1.0 schema exporter
│   │   ├── gitlab.rs               # GitLab Secret Detection report v15.0.7 exporter
│   │   └── webhook/                # Slack Block Kit & Discord incident card dispatcher
│   │       ├── mod.rs              # Formatter & HTTP webhook dispatcher
│   │       └── tests.rs            # Webhook payload & transport unit tests
│   ├── scanner/
│   │   └── mod.rs                  # Lock-free work-stealing parallel directory scanner (build_parallel)
│   ├── tui/
│   │   ├── mod.rs                  # Panic-safe TerminalGuard & Ratatui event loop (sentris review)
│   │   ├── app.rs                  # Split-pane TUI state machine (j/k, r Remediate, b Baseline, i Ignore)
│   │   └── ui.rs                   # Split-pane Ratatui renderer with live -/+ staged patch diff preview
│   └── verifier/
│       ├── mod.rs                  # VerifierRegistry, ProviderVerifier trait, LiveStatus { scopes }
│       ├── stripe.rs               # Stripe live probe & dual-key rotation
│       ├── github.rs               # GitHub PAT probe & OAuth scope mapper
│       ├── aws.rs                  # AWS STS caller-identity verification
│       ├── slack.rs                # Slack auth.test verifier
│       ├── openai.rs               # OpenAI sk-proj- verifier & project key rotation
│       └── anthropic.rs            # Anthropic sk-ant-api03- verifier & rotation
├── tests/
│   ├── integration_tests.rs        # 23 end-to-end CLI integration tests
│   ├── benchmark_test.rs           # Throughput & latency SLA enforcement benchmark
│   └── fixtures/                   # Synthetic test fixtures
└── web/                            # Sentris Pro Web Platform (Three.js 3D Hash Reactor + SaaS Dashboard)
```

---

## 3. AI Agent CLI Mode (`--json` / `--agent` / `SENTRIS_AGENT=1`), MCP & LSP Reference

### 3.0 Universal Headless Agent CLI Mode (`--json` / `--agent` / `SENTRIS_AGENT=1`)
Any AI coding agent (Claude Code, Cursor, Antigravity, Windsurf, OpenAI Codex, LangGraph, CrewAI, Aider) can consume Sentris directly over CLI without human terminal formatting or interactive prompts:

- **Global Flag & Env Auto-Detection:** Pass `--json` (or `--agent`) on **any** subcommand, or set `SENTRIS_AGENT=1` in the agent's environment:
  - Suppresses all ANSI colors, progress spinners, and interactive `[y/N]` confirmation prompts (`--yes` auto-enabled so agents never hang on `stdin`).
  - Emits pure, deterministic, schema-stable JSON on `stdout` with actionable `next_agent_actions`.
- **Self-Describing `Finding` Objects:** Every serialized `Finding` JSON object automatically includes:
  - `context_kind`: `"PRODUCTION"` or `"TEST_FIXTURE"`
  - `recommended_env_var`: e.g. `"STRIPE_SECRET_KEY"`
  - `remediate_command`: e.g. `"sentris fix <file_path> --yes --json"`
- **`sentris agent` (alias `sentris ai`) Subcommand:**
  - `sentris agent`: Emits the complete machine-readable AI Agent CLI & Tool Schema Manifest (`schema_version`, `agent_invocation_rules`, `cli_commands`, `mcp_tools`, `mcp_resources`, `mcp_prompts`).
  - `sentris agent --setup`: Scaffolds `.mcp.json` and `.agents/skills/sentris-security/SKILL.md` in the repository root so any AI coding agent opening the workspace auto-discovers Sentris.

### 3.1 Model Context Protocol (`sentris mcp`)
Run `sentris mcp --print-config` (or `sentris agent --setup`) to generate the `mcpServers` block for Claude Code, Cursor, Windsurf, or Antigravity. `sentris mcp` speaks JSON-RPC 2.0 over `stdio` and exposes **6 Tools**, **3 Resources**, and **2 Prompts**:

| MCP Tool Name | Arguments | What It Does |
| :--- | :--- | :--- |
| `sentris_scan_path` | `{ "path"?: string }` | Scans a file or directory in `<25ms` and returns redacted findings with `recommended_env_var` and `remediate_command`. |
| `sentris_scan_staged` | `{}` | Scans staged git index diff hunks (`git diff --cached -U0`) before committing. |
| `sentris_remediate_finding` | `{ "file_path": string, "backend"?: string, "rotate"?: bool, "dry_run"?: bool }` | Quietly extracts the secret to `env`/`vault`/`aws`/`doppler`/`1password`/`infisical`, updates `.env.example`, and patches the source code without polluting `stdout`. |
| `sentris_rollback_session` | `{ "session_id"?: string }` | Reverts a remediation session from `.sentris/rollback_ledger.json` byte-for-byte. |
| `sentris_audit_verify` | `{ "ledger_path"?: string }` | Verifies the RFC 2104 HMAC-SHA256 cryptographic hash chain in `.sentris/audit_ledger.json`. |
| `sentris_team_blast_radius` | `{}` | Returns the Zero-Knowledge Multi-Repo Blast Radius correlation table (`zk_<sha256>` across repos). |

| MCP Resource URI | MIME Type | Purpose |
| :--- | :--- | :--- |
| `sentris://agent/manifest` | `application/json` | Full CLI & MCP tool schema manifest for autonomous AI agents. |
| `sentris://audit/ledger` | `application/json` | Live tamper-evident RFC 2104 HMAC-SHA256 SOC 2 audit ledger summary. |
| `sentris://team/blast-radius` | `application/json` | Zero-Knowledge `zk_<sha256>` cross-repository credential correlation. |

| MCP Prompt Name | Arguments | Purpose |
| :--- | :--- | :--- |
| `remediate-repo-secrets` | `{ "path"?: string }` | Autonomous workflow prompt to scan, extract secrets to `.env`, and verify the SOC 2 audit ledger. |
| `pre-commit-security-gate` | `{}` | Pre-commit staged diff security verification gate for AI coding agents. |

### 3.2 Language Server Protocol (`sentris lsp`)
`sentris lsp` implements LSP 3.17 over `stdio` (`Content-Length` headers or raw JSON lines):
- **`textDocument/didOpen` & `textDocument/didChange`:** Scans the active editor buffer in `<2ms` and emits `textDocument/publishDiagnostics` with exact 0-indexed character ranges.
- **`textDocument/codeAction`:** Returns a `quickfix` Code Action (`Sentris: Extract <rule_id> to <ENV_VAR>`) with a `WorkspaceEdit` that rewrites the hardcoded line into the language's idiomatic env accessor.

---

## 4. Complete CLI Command Reference

| Command | Purpose |
| :--- | :--- |
| `sentris scan [PATH]` | Parallel recursive directory scan (`--format text\|json\|sarif\|github\|gitlab`, `--min-severity`, `--fail-on-secret`). |
| `sentris scan --staged` | Diff-only staged hunk scan (`git diff --cached -U0`) in `12ms`. |
| `sentris scan --since <REF>` | Commit-range scan (`HEAD~1` or `origin/main..HEAD`) for pre-push and PR checks. |
| `sentris scan --git-history` | Full git commit DAG and diff history scan. |
| `sentris scan --verify` | Probes live provider APIs and prints the Identity & Blast Radius scope map. |
| `sentris review [PATH]` | Interactive Split-Pane Ratatui TUI with live `-`/`+` staged patch preview (`r`, `b`, `i`, `q`). |
| `sentris remediate [TARGET]` | 7-step autonomous remediation (`--all` batch mode, `--rotate` API rotation, `--backend env\|vault\|aws\|doppler\|1password\|infisical`, `--dry-run`, `--yes`). |
| `sentris rollback [--session ID]` | Atomically restores original file contents from `.sentris/rollback_ledger.json`. |
| `sentris quarantine <ID>` | Creates a Zone 3 quarantine branch and `.sentris/quarantine_qz_<id>_playbook.md`. |
| `sentris baseline record` | Snapshots existing findings into `.sentris-baseline.json`. |
| `sentris audit [--verify] [--export-vanta FILE]` | Verifies the HMAC-SHA256 audit chain and exports 1-click Vanta/Drata SOC 2 (`CC6.1/CC6.7/CC6.8`) & ISO 27001 (`A.8.24`) evidence JSON. |
| `sentris migrate-gitleaks <FILE>` | Converts `.gitleaks.toml` rules and allowlists into `.sentris.toml` in `3ms`. |
| `sentris install` / `uninstall` | Installs or removes `.git/hooks/pre-commit` and `.git/hooks/pre-push`. |
| `sentris auth login\|status\|logout` | Manages Sentris Pro Cloud workstation credentials. |
| `sentris sync` / `sentris team` | Syncs salted `zk_<sha256>` telemetry and renders the Zero-Knowledge Multi-Repo Blast Radius table. |
| `sentris mcp [--print-config]` | Runs the JSON-RPC 2.0 MCP server over `stdio` or prints IDE/Agent config JSON. |
| `sentris lsp` | Runs the LSP 3.17 real-time diagnostic & code-action server over `stdio`. |

---

## 5. Build, Test & Verification Commands

```bash
# 1. Run all 152 automated tests (128 unit + 23 integration + 1 SLA benchmark)
cargo test --offline

# 2. Enforce zero Clippy warnings across all targets
cargo clippy --offline --all-targets -- -D warnings

# 3. Verify rustfmt compliance
cargo fmt --check

# 4. Build stripped production release binary (3.8 MB)
cargo build --release --offline
```
