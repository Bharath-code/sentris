# AGENT.md — Sentris Systems Architecture, AI Agent (MCP/LSP) & Engineering Handbook

> **Target Audience:** AI Coding Agents (Claude Code, Cursor, Antigravity, Windsurf, OpenAI Codex/Agents, LangGraph, CrewAI, Aider) & Systems Engineers.  
> **Project:** Sentris (`sentris`)  
> **Binary Footprint:** `3.8 MB` stripped static Rust binary (`rustls`, zero C/C++/Python/Node runtime dependencies)  
> **Test Suite Status:** **395 / 395 Automated Tests Passing** (`333` unit tests + `62` integration/e2e/corpus/SLA tests across 8 test suites, `0` Clippy warnings)

---

## 1. Mission & 7 Non-Negotiable System Invariants

Sentris is a high-performance, memory-safe, zero-knowledge secret scanner and autonomous remediation engine written in Rust.

When modifying or extending this repository, **you must preserve all 7 Non-Negotiable Invariants**:

1. **Zero-Knowledge Privacy:** Raw source code and unmasked secrets **never leave the user's machine**. Cloud sync (`sentris sync` / `sentris scan --cloud`) transmits only organization-salted `zk_<sha256>` HMAC tokens.
2. **Safe Local Extraction Default & Dual-Key Rotation Safety:**
   - By default, `sentris remediate <file>` performs **Safe Local Extraction** (extracting the working key into `.env`, syncing an empty `KEY=` contract into `.env.example`, hardening `.gitignore`, and rewriting source code / IaC / MCP configs to an idiomatic environment variable accessor) so local development **never breaks**.
   - When `--rotate` is passed, Sentris provisions a replacement credential via the provider API (AWS IAM access keys) and queues the old key for a 24-hour deprecation grace window—**never immediate destructive revocation**.
3. **Cryptographic RAM Zeroization:** Every mutable `String` buffer holding a raw secret during remediation, probing, or live verification must be scrubbed immediately after use via `Remediator::zeroize_secret_string` (`std::ptr::write_volatile` + `compiler_fence(Ordering::SeqCst)`).
4. **3-Tiered Git Remediation Safety:**
   - *Zone 1 (Working Tree / Staged Hunks):* In-place polyglot code, IaC (`.github/workflows/*.yml`, `.tf`/`.tfvars`, `Dockerfile`, `docker-compose*.yml`, `.mcp.json`), and transcript (`.jsonl`, `.zsh_history`, `.bash_history`) patching + `.env` / Vault / 1Password / Infisical injection (`<20ms`).
   - *Zone 2 (Local Unpushed Commits):* Pre-push range scanning (`sentris scan --since HEAD~1`).
   - *Zone 3 (Remote Historical Commits):* **Never blind force-push.** Isolate via `sentris quarantine <id>` to create a `sentris/quarantine-<id>` branch and generate a `.sentris/quarantine_qz_<id>_playbook.md` `git-filter-repo` runbook.
5. **Performance SLA as a Hard Invariant:**
   - Work-stealing parallel directory traversal (`ignore::WalkBuilder::build_parallel`) + Single-pass Aho-Corasick literal prefilter + Structure-of-Arrays (SoA) rule layout.
   - Staged diff-hunk pre-commit scan (`git diff --cached -U0`) must execute in `< 25ms`.
   - Full scan over 1,000+ files must sustain `> 10,000 files/sec` (enforced by `tests/benchmark_test.rs`).
6. **Zero Uncontrolled Panics & Terminal Safety:**
   - Never call `.unwrap()` on fallible I/O in library paths (`src/scanner/`, `src/detector/`, `src/remediator/`, `src/mcp/`, `src/lsp/`).
   - Interactive TUI (`src/tui/`) must always guard raw mode with `TerminalGuard` (`Drop` restoration).
7. **Tamper-Evident Compliance Chain:**
   - Every scan, remediation, baseline, rotation, revocation, exposure probe, and quarantine event appends an RFC 2104 `HMAC-SHA256` chained record to `.sentris/audit_ledger.json`, verifiable and exportable to Vanta/Drata (`sentris audit --verify --export-vanta`) with formal `SOC 2 CC6.1 / CC6.7 / CC6.8`, `ISO 27001 A.8.24`, `OWASP NHI Top 10:2025 (NHI1, NHI2, NHI5, NHI7)`, and `PCI-DSS v4.0 (Req 3.5, Req 8.6, Req 10.3)` control attestations.

---

## 2. Exact Workspace Structure & Module Map

```text
sentris/
├── Cargo.toml                      # Rust 2021 crate manifest & LTO/strip release profile
├── README.md                       # Public documentation & 14-dimension competitive matrix
├── AGENT.md                        # AI Agent & Systems Engineering handbook (this file)
├── CLAUDE.md                       # Claude Code workspace operating & engineering instructions
├── .pre-commit-hooks.yaml          # Pre-commit & pre-push hook definitions
├── action.yml                      # Composite GitHub Action with SARIF upload
├── Dockerfile                      # Hardened distroless/Alpine multi-stage container
├── Formula/sentris.rb              # Homebrew tap formula
├── install.sh                      # POSIX curl | sh installer
├── src/
│   ├── lib.rs                      # Library root exporting all core modules
│   ├── main.rs                     # Minimal 7-line binary entry point delegating to sentris::cli::handlers
│   ├── model.rs                    # Finding, Severity, ContextKind (Production vs TestFixture), ScanReport
│   ├── error.rs                    # Centralized SentrisError (thiserror)
│   ├── fsutil.rs                   # Symlink rejection & atomic 0600 file helpers
│   ├── keystore.rs                 # Local machine audit/confirmation HMAC key derivation
│   ├── hook.rs                     # Claude Code / AI Agent hook (UserPromptSubmit, PreToolUse, PostToolUse, cloak_tool_output)
│   ├── import.rs                   # Betterleaks/Gitleaks JSON importer with flat arena & bit-packed u32 handles
│   ├── redact.rs                   # Inline text & stream redaction engine («sentris:<rule>:<fp8>» phantom markers)
│   ├── audit/
│   │   ├── mod.rs                  # AuditAction, AuditRecord, and append-only AuditLedger hash chain
│   │   ├── crypto.rs               # RFC 2104 HMAC-SHA256 & repository/workstation audit salt derivation
│   │   ├── vanta.rs                # 1-Click Vanta/Drata SOC 2, ISO 27001, OWASP NHI Top 10 (2025) & PCI-DSS v4.0 exporter
│   │   └── tests.rs                # Tamper-detection & hash-chain integrity test suite
│   ├── cli/
│   │   ├── mod.rs                  # Clap v4 CLI structs, flags, and subcommands
│   │   ├── completions.rs          # Shell completions (bash, zsh, fish, powershell, elvish)
│   │   └── handlers/               # Modular CLI subcommand execution handlers
│   │       ├── mod.rs              # Top-level subcommand router
│   │       ├── scan.rs             # Scan (--workstation, --stdin, --probe, --verify), baseline filter
│   │       ├── scan_output.rs      # Scan output formatting, parallel verification, exposure display, webhook & cloud sync
│   │       ├── remediate.rs        # Remediate (--all, --rotate, --workstation, --from-report) and rollback handlers
│   │       ├── quarantine.rs       # Zone 3 quarantine branch & playbook handler
│   │       ├── revoke.rs           # Guided & API credential revocation (--api, --wait) + KeyDeactivated audit log
│   │       ├── run.rs              # Zero-disk .env runtime runner across all 6 secret backends
│   │       ├── review.rs           # Interactive Ratatui review & baseline snapshot handlers
│   │       ├── audit.rs            # Audit ledger, gitleaks migration, git hook (--with-ai) & init handlers
│   │       ├── auth.rs             # Pro Cloud authentication handlers
│   │       ├── hook.rs             # Claude Code stdin hook runner
│   │       ├── rotate.rs           # AWS IAM dual-key rotation status/finish/undo handlers
│   │       ├── investigate.rs      # AWS CloudTrail forensic investigation & CODEOWNERS attribution handler
│   │       └── cloud.rs            # Sync, team blast-radius, MCP, LSP & AI agent handlers
│   ├── cloud/
│   │   ├── mod.rs                  # Zero-Knowledge Pro Cloud module exports
│   │   ├── auth.rs                 # License token parser & ~/.sentris/credentials.json storage
│   │   ├── client.rs               # Salted zk_<sha256> payload builder & Multi-Repo Blast Radius correlation
│   │   └── team.rs                 # Team seat overview & Multi-Repo Blast Radius terminal table
│   ├── config/
│   │   ├── mod.rs                  # .sentris.toml parser & custom enterprise regex rules
│   │   └── gitleaks_migrator.rs    # 1-command .gitleaks.toml -> .sentris.toml converter
│   ├── detector/
│   │   ├── mod.rs                  # DetectorEngine (Single-pass Aho-Corasick + SoA rules + DECODE_OWNER)
│   │   ├── decode.rs               # Multi-layer Base64 (incl. k8s Secret YAML) & URL-percent secret decoder
│   │   ├── patterns.rs             # 119 precision rules (AWS, Stripe, OpenAI, Anthropic, Cloudflare, Tavily, Pinecone, Firecrawl, etc.)
│   │   ├── entropy.rs              # Shannon information entropy calculator
│   │   ├── false_positives.rs      # 6-Layer False Positive Suppression Engine
│   │   └── baseline.rs             # Cryptographic fingerprint baseline snapshot (.sentris-baseline.json)
│   ├── exposure/
│   │   ├── mod.rs                  # Read-only capability exposure probes, canary bypass, OWASP NHI5 advisor & flat tier ranking
│   │   ├── http.rs                 # Read-only HTTP transport abstraction for exposure probes
│   │   ├── stripe.rs               # Stripe live balance & read/write capability probe
│   │   ├── github.rs               # GitHub PAT scopes & organization membership probe
│   │   ├── aws.rs                  # AWS IAM attached/inline user & group policy probe
│   │   ├── huggingface.rs          # Hugging Face fine-grained role & org write access probe
│   │   └── gitlab.rs               # GitLab PAT scopes & expiration probe
│   ├── git/
│   │   ├── mod.rs                  # Staged diff-hunk parser (-U0), --since scanner, parallel --git-history, CODEOWNERS & OIDC generators
│   │   └── quarantine.rs           # Zone 3 quarantine brancher & git-filter-repo playbook generator
│   ├── investigate/
│   │   ├── mod.rs                  # Leaked credential commit introduction, CODEOWNERS attribution & CloudTrail forensics
│   │   ├── aws.rs                  # AWS CloudTrail LookupEvents client
│   │   └── window.rs               # Exposure window & IP anomaly analyzer
│   ├── lsp/
│   │   └── mod.rs                  # Native Language Server Protocol (LSP 3.17) over stdio (diagnostics + quickfix)
│   ├── mcp/
│   │   ├── mod.rs                  # Native Model Context Protocol (MCP JSON-RPC 2.0) server & router
│   │   ├── tools.rs                # 10 MCP tools (scan, staged, remediate, rollback, redact, rotate, investigate, audit, blast_radius)
│   │   ├── rotate_tools.rs         # MCP rotation tool handlers
│   │   ├── investigate_tool.rs     # MCP forensic investigation tool handler
│   │   └── manifest.rs             # MCP resources, prompts, AI Agent manifest & workspace scaffolder
│   ├── remediator/
│   │   ├── mod.rs                  # 7-step remediation pipeline & volatile RAM zeroization
│   │   ├── backend/                # Modular Secret Store Backends (inject_secret + fetch_secret, zero argv leaks)
│   │   │   ├── mod.rs              # SecretStoreBackend trait, SecretTempFile (0600) & SecretBackendFactory
│   │   │   ├── env.rs              # .env local file driver
│   │   │   ├── vault.rs            # HashiCorp Vault KV v2 driver (stdin + HTTP CAS)
│   │   │   ├── aws.rs              # AWS Secrets Manager driver (0600 file:// tempfile)
│   │   │   ├── doppler.rs          # Doppler Secrets driver (stdin)
│   │   │   ├── onepassword.rs      # 1Password CLI driver (0600 --template JSON tempfile)
│   │   │   └── infisical.rs        # Infisical CLI driver (0600 --file= tempfile)
│   │   ├── code_replacer/          # Polyglot code, IaC, MCP & transcript replacer
│   │   │   ├── mod.rs              # Path-aware accessor generator (.github/workflows, .tf, Dockerfile, .mcp.json, .jsonl) & PEM replacer
│   │   │   ├── accessor_tests.rs   # Accessor generation unit tests
│   │   │   └── replacement_tests.rs# String, IaC, transcript & PEM replacement unit tests
│   │   ├── env_patcher.rs          # .env injector, .gitignore hardener, and .env.example contract syncer
│   │   └── rollback.rs             # Byte-exact atomic rollback ledger (.sentris/rollback_ledger.json)
│   ├── reporter/
│   │   ├── mod.rs                  # ANSI/ASCII table renderer, JSON exporter, GitHub Actions annotations
│   │   ├── sarif.rs                # OASIS SARIF v2.1.0 schema exporter
│   │   ├── gitlab.rs               # GitLab Secret Detection report v15.0.7 exporter
│   │   └── webhook/                # Slack Block Kit & Discord incident card dispatcher
│   │       ├── mod.rs              # Formatter & HTTP webhook dispatcher
│   │       └── tests.rs            # Webhook payload & transport unit tests
│   ├── rotator/
│   │   ├── mod.rs                  # ProviderRotator trait & dual-key rotation state machine
│   │   ├── aws.rs                  # AWS IAM dual-key lifecycle driver
│   │   ├── flow.rs                 # Crash-safe rotation orchestration
│   │   ├── ledger.rs               # HMAC-signed rotation ledger (.sentris/rotations.json)
│   │   └── timefmt.rs              # RFC 3339 UTC timestamp parser & formatter
│   ├── scanner/
│   │   ├── mod.rs                  # Work-stealing parallel directory scanner, --stdin stream reader & workstation AI/MCP/transcript auditor
│   │   └── ignore_tests.rs         # Component-aware ignore & config security unit tests
│   ├── tui/
│   │   ├── mod.rs                  # Panic-safe TerminalGuard & Ratatui event loop (sentris review)
│   │   ├── app.rs                  # Split-pane TUI state machine (j/k, r Remediate, b Baseline, i Ignore)
│   │   └── ui.rs                   # Split-pane Ratatui renderer with live -/+ staged patch diff preview
│   └── verifier/
│       ├── mod.rs                  # VerifierRegistry (12 providers), detect_canary_token, ProviderVerifier trait, LiveStatus
│       ├── stripe.rs               # Stripe live verifier
│       ├── github.rs               # GitHub PAT live verifier & OAuth scope mapper
│       ├── gitlab.rs               # GitLab PAT (/api/v4/personal_access_tokens/self) live verifier
│       ├── huggingface.rs          # Hugging Face (/api/whoami-v2) live verifier
│       ├── aws.rs                  # AWS STS caller-identity verifier
│       ├── slack.rs                # Slack auth.test verifier
│       ├── openai.rs               # OpenAI sk-proj- verifier
│       ├── anthropic.rs            # Anthropic sk-ant-api03- verifier
│       ├── groq.rs                 # Groq (/openai/v1/models) live verifier
│       ├── sendgrid.rs             # SendGrid (/v3/scopes) live verifier
│       ├── cloudflare.rs           # Cloudflare API Token (/client/v4/user/tokens/verify) live verifier
│       └── digitalocean.rs         # DigitalOcean PAT (/v2/account) live verifier
├── tests/
│   ├── integration_tests.rs        # 25 end-to-end CLI integration tests
│   ├── exposure_e2e_test.rs        # 11 exposure probe & risk-tier gating e2e tests
│   ├── hook_cli_test.rs            # 8 Claude Code hook security & fail-closed e2e tests
│   ├── rotation_e2e_test.rs        # 7 AWS IAM two-phase rotation lifecycle e2e tests
│   ├── import_e2e_test.rs          # 4 Betterleaks/Gitleaks report import & remediation e2e tests
│   ├── investigate_e2e_test.rs     # 4 CloudTrail forensic investigation e2e tests
│   ├── corpus_test.rs              # 2 labeled corpus precision/recall & redaction regression tests
│   ├── benchmark_test.rs           # Throughput & latency SLA enforcement benchmark
│   └── fixtures/                   # Synthetic test & golden fixtures
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
Run `sentris mcp --print-config` (or `sentris agent --setup`) to generate the `mcpServers` block for Claude Code, Cursor, Windsurf, or Antigravity. `sentris mcp` speaks JSON-RPC 2.0 over `stdio` and exposes **10 Tools**, **3 Resources**, and **2 Prompts**:

| MCP Tool Name | Arguments | What It Does |
| :--- | :--- | :--- |
| `sentris_scan_path` | `{ "path"?: string }` | Scans a file or directory in `<25ms` and returns redacted findings with `recommended_env_var` and `remediate_command`. |
| `sentris_scan_staged` | `{}` | Scans staged git index diff hunks (`git diff --cached -U0`) before committing. |
| `sentris_remediate_finding` | `{ "file_path": string, "backend"?: string, "fingerprint"?: string, "confirm"?: string, "rotate"?: bool, "dry_run"?: bool }` | Quietly extracts the secret to `env`/`vault`/`aws`/`doppler`/`1password`/`infisical`, updates `.env.example`, and patches source/IaC/MCP files (requires two-step `confirm_token` + `SENTRIS_MCP_ALLOW_WRITES=1` when `dry_run=false`). |
| `sentris_rollback_session` | `{ "session_id"?: string }` | Reverts a remediation session from `.sentris/rollback_ledger.json` byte-for-byte. |
| `sentris_redact_text` | `{ "text": string }` | Replaces every detected secret in arbitrary text with a stable `«sentris:<rule>:<fp8>»` phantom marker. |
| `sentris_rotate_status` | `{}` | Lists active and completed AWS IAM dual-key rotations from `.sentris/rotations.json`. |
| `sentris_rotate_finish` | `{ "rotation_id": string, "force"?: bool }` | Deactivates the old AWS IAM access key after the grace window (refuses if CloudTrail shows recent use). |
| `sentris_investigate` | `{ "target"?: string, "known_ips"?: string[] }` | Read-only forensics: earliest git commit + `.github/CODEOWNERS` attribution + AWS CloudTrail event history. |
| `sentris_audit_verify` | `{ "ledger_path"?: string }` | Verifies the RFC 2104 HMAC-SHA256 cryptographic hash chain in `.sentris/audit_ledger.json`. |
| `sentris_team_blast_radius` | `{}` | Returns the Zero-Knowledge Multi-Repo Blast Radius correlation table (`zk_<sha256>` across repos). |

| MCP Resource URI | MIME Type | Purpose |
| :--- | :--- | :--- |
| `sentris://agent/manifest` | `application/json` | Full CLI & MCP tool schema manifest for autonomous AI agents. |
| `sentris://audit/ledger` | `application/json` | Live tamper-evident RFC 2104 HMAC-SHA256 SOC 2 audit ledger summary. |
| `sentris://team/blast-radius` | `application/json` | Zero-Knowledge `zk_<sha256>` cross-repository credential correlation. |

| MCP Prompt Name | Arguments | Purpose |
| :--- | :--- | :--- |
| `remediate-repo-secrets` | `{ "path"?: string, "backend"?: string }` | Autonomous workflow prompt to scan, extract secrets to `.env`/Vault, and verify the SOC 2 audit ledger. |
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
| `sentris scan --stdin` | Scans an arbitrary stream from `stdin` (e.g. `gh run view --log \| sentris scan --stdin` or `docker history`) bounded by `max_file_size_mb`. |
| `sentris scan --staged` | Diff-only staged hunk scan (`git diff --cached -U0`) in `12ms`. |
| `sentris scan --since <REF>` | Commit-range scan (`HEAD~1` or `origin/main..HEAD`) for pre-push and PR checks. |
| `sentris scan --git-history` | Full git commit DAG and diff history scan. |
| `sentris scan --verify` | Probes 12 live provider APIs in parallel (bypassing Canary/Honeytoken tripwires) and prints the Identity & Blast Radius scope map. |
| `sentris scan --probe` | Read-only capability exposure probes for Stripe, GitHub, AWS, Hugging Face, and GitLab ranked by risk tier with OWASP NHI5 least-privilege advisories. |
| `sentris scan --workstation` | Audits workstation AI coding agent configs, `.jsonl` transcripts (`~/.claude/projects/**/*.jsonl`), shell histories (`~/.zsh_history`, `~/.bash_history`), `~/.aws/credentials`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, and `~/.git-credentials`. |
| `sentris review [PATH]` | Interactive Split-Pane Ratatui TUI with live `-`/`+` staged patch preview (`r`, `b`, `i`, `q`). |
| `sentris remediate [TARGET]` | 7-step autonomous remediation (`--all` batch mode, `--workstation` AI config/transcript scrubber, `--rotate` AWS IAM rotation, `--backend env\|vault\|aws\|doppler\|1password\|infisical`, `--dry-run`, `--yes`). |
| `sentris run --backend <B> --key <K>... -- <CMD>` | Zero-disk `.env` runtime runner: fetches secrets from any of the 6 backends into child process memory only and zeroizes parent buffers. |
| `sentris revoke [TARGET]` | Guided or API-driven (`--api`) credential revocation with 2-second live verification polling (`--wait`) and `KeyDeactivated` SOC 2 audit logging. |
| `sentris rotate status\|finish\|undo` | Inspects, completes, or reverts an AWS IAM dual-key rotation started with `remediate --rotate`. |
| `sentris investigate <TARGET>` | Read-only forensics for a leaked AWS key: earliest git commit + `.github/CODEOWNERS` attribution + CloudTrail management event history. |
| `sentris hook [--print-config] [--fail-closed]` | Claude Code / AI agent hook blocking secrets in `UserPromptSubmit`, `PreToolUse`, and `PostToolUse` tool outputs. |
| `sentris rollback [--session ID]` | Atomically restores original file contents from `.sentris/rollback_ledger.json`. |
| `sentris quarantine <ID>` | Creates a Zone 3 quarantine branch and `.sentris/quarantine_qz_<id>_playbook.md`. |
| `sentris baseline record` | Snapshots existing findings into `.sentris-baseline.json`. |
| `sentris audit [--verify] [--export-vanta FILE]` | Verifies the HMAC-SHA256 audit chain and exports 1-click Vanta/Drata evidence JSON (`SOC 2 CC6.1/CC6.7/CC6.8`, `ISO 27001 A.8.24`, `OWASP NHI Top 10:2025`, `PCI-DSS v4.0`). |
| `sentris migrate-gitleaks <FILE>` | Converts `.gitleaks.toml` rules and allowlists into `.sentris.toml` in `3ms`. |
| `sentris install [--with-ai]` / `uninstall` | Installs or removes `.git/hooks/pre-commit` and `.git/hooks/pre-push` (and optionally `.mcp.json`, `SKILL.md`, and `.claude/settings.local.json`). |
| `sentris auth login\|status\|logout` | Manages Sentris Pro Cloud workstation credentials. |
| `sentris sync` / `sentris team` | Syncs salted `zk_<sha256>` telemetry and renders the Zero-Knowledge Multi-Repo Blast Radius table. |
| `sentris mcp [--print-config]` | Runs the JSON-RPC 2.0 MCP server over `stdio` or prints IDE/Agent config JSON. |
| `sentris lsp` | Runs the LSP 3.17 real-time diagnostic & code-action server over `stdio`. |

---

## 5. Build, Test & Verification Commands

```bash
# 1. Run all 395 automated tests (333 unit + 62 integration/e2e/corpus/SLA tests)
cargo test --offline

# 2. Enforce zero Clippy warnings across all targets
cargo clippy --offline --all-targets -- -D warnings

# 3. Verify rustfmt compliance
cargo fmt --check

# 4. Build stripped production release binary (3.8 MB)
cargo build --release --offline
```
