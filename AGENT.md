# AGENT.md — Sentris Development & Operational Guide

> **Target Audience:** AI Coding Agents & Systems Engineers working on this codebase.  
> **Project Codename:** Sentris  
> **Target Binary:** `sentris` (Crate: `sentris-cli`)  
> **Primary Source Document:** [`SENTRIS-MASTER-PRD-AND-TODO.md`](./SENTRIS-MASTER-PRD-AND-TODO.md)

---

## 1. Mission & System Invariants

Sentris is a high-performance, memory-safe, zero-knowledge secret scanner and autonomous remediation engine built in Rust. 

When modifying or writing code in this repository, **you must preserve these 5 Non-Negotiable Invariants**:

1. **Zero-Knowledge Privacy:** Raw source code and unmasked secrets **never leave the user's machine**. Upstream telemetry transmits only salted `HMAC-SHA256` fingerprints.
2. **Dual-Key Production Safety:** Auto-remediation must **never immediately revoke an active credential**. The new replacement key must be provisioned and verified functional *before* the compromised key is queued for deprecation (24h grace window or explicit human confirmation).
3. **3-Tiered Git Remediation Safety:**
   * *Zone 1 (Uncommitted / Staged):* Patch files in-place (<20ms).
   * *Zone 2 (Local Unpushed Commits):* Safe `git commit --amend` or soft reset.
   * *Zone 3 (Remote Historical Commits):* **Never blind force-push.** Generate an isolated quarantine branch (`sentris/fix-<id>`) and a structured pull request.
4. **Performance as an Invariant:**
   * Full local scan over 5,000 files must complete in `< 250ms`.
   * Staged pre-commit hook must execute in `< 35ms`.
   * Use `rayon` for data parallelism and the `ignore` crate (ripgrep engine) for `.gitignore` traversal.
5. **Zero Dynamic Dependencies:** Single static binary (`< 8.0MB` stripped). Use `rustls` instead of native OpenSSL. Zero Python or Node.js runtime dependencies.
6. **Scoped Admin Delegation:** Leaked keys are never assumed to possess rotation rights. Use local CLI sessions (`stripe-cli`, `aws-cli`, `gh auth`) or fallback to a 1-Click Slack / Webhook Incident Card for the DevOps lead.
7. **Multi-Cloud Portability & ICP Focus:** Must execute seamlessly across GitHub, GitLab, Bitbucket, and air-gapped repositories with zero cloud infrastructure dependencies, purpose-built to serve fast-growing tech startups (10–75 devs).

---

## 2. Workspace Structure & Module Hierarchy

```
sentris/
├── Cargo.toml                  # Workspace & release optimization profiles
├── .pre-commit-hooks.yaml      # Global Python pre-commit framework manifest
├── src/
│   ├── lib.rs                  # Core library exports
│   ├── main.rs                 # CLI entry point & dispatch
│   ├── cli/                    # clap v4 args, subcommands, help formatting
│   ├── config/                 # .sentris.toml parser & custom enterprise rules
│   ├── scanner/                # Rayon parallel directory walker (ignore crate)
│   ├── detector/               # Regex signatures, Shannon entropy filter
│   │   ├── engine.rs           # Detector trait & execution pipeline
│   │   ├── patterns.rs         # 50+ built-in secret rules
│   │   ├── entropy.rs          # Shannon entropy calculator
│   │   ├── false_positives.rs  # Precision FP suppression engine (docs, templates, walks, UUIDs)
│   │   └── gitleaks.rs         # .gitleaks.toml compatibility parser
│   ├── verifier/               # Multi-provider live key validation (ureq)
│   │   ├── mod.rs              # VerifierRegistry & ProviderVerifier trait
│   │   ├── stripe.rs           # Stripe live balance probe & rotation
│   │   ├── github.rs           # GitHub PAT / user API probe & scope audit
│   │   ├── aws.rs              # AWS STS SigV4 verification & IAM probe
│   │   └── slack.rs            # Slack auth.test probe & team identity

│   ├── remediator/             # Autonomous self-healing engine
│   │   ├── pipeline.rs         # 7-step remediation state machine
│   │   ├── env_patcher.rs      # .env file safe injection & .gitignore verify
│   │   ├── code_replacer.rs    # Source code string-to-envvar replacer
│   │   └── rollback.rs         # Atomic rollback ledger & recovery
│   ├── git/                    # Git operations (git2 bindings)
│   │   ├── hook.rs             # .git/hooks/pre-commit installer
│   │   ├── staged.rs           # Index hunk diff scanner
│   │   └── history.rs          # Commit DAG walker & quarantine brancher
│   ├── reporter/               # Output presentation layer
│   │   ├── terminal.rs         # comfy-table ANSI UI & secret masking
│   │   ├── json.rs             # Typed JSON serializer
│   │   └── sarif.rs            # OASIS SARIF v2.1.0 schema exporter
│   └── error.rs                # thiserror centralized error types
└── tests/                      # Hermetic integration test fixtures
```

---

## 3. Engineering Guidelines & Coding Standards

### 3.1 Rust Idioms & Quality
* **Rust Edition:** Rust 2021+.
* **Error Handling:** Use `thiserror` for library modules and `anyhow` for top-level CLI error handling.
* **No Uncontrolled Panics:** Never call `.unwrap()` or `.expect()` in library paths (`src/scanner/`, `src/detector/`, `src/remediator/`). Use explicit `Result<T, SentrisError>` propagation with `?`.
* **Zero-Allocation String Scanning:** Utilize string slices (`&str`), byte slices (`&[u8]`), and `Cow<'a, str>` where possible. Avoid allocating intermediate strings in the hot scanning loop.
* **Redaction by Default:** When formatting any finding or log entry, format secrets as:
  ```rust
  pub fn mask_secret(secret: &str) -> String {
      if secret.len() <= 8 {
          "********".to_string()
      } else {
          format!("{}...{}", &secret[..4], &secret[secret.len() - 4..])
      }
  }
  ```

---

## 4. Key CLI Commands Specification

| Command | Purpose | Behavior |
|---|---|---|
| `sentris scan [PATH]` | Local filesystem scan | Scans directory recursively respecting `.gitignore`. Default output: ANSI table. |
| `sentris scan --staged` | Pre-commit staged scan | Scans git index staged hunks only in `< 35ms`. |
| `sentris scan --format json` | Structured JSON output | Emits strictly typed JSON payload for machine consumption. |
| `sentris scan --format sarif` | GitHub Security upload | Emits valid SARIF 2.1.0 payload. |
| `sentris scan --fail-on-secret` | CI/CD enforcement | Returns exit code `1` if findings exist, `0` if clean. |
| `sentris install` | Pre-commit hook setup | Installs idempotent `.git/hooks/pre-commit`. |
| `sentris remediate <ID>` | Autonomous safe fix | Executes the 7-step safe dual-key remediation workflow. |
| `sentris rollback --session <ID>` | Revert remediation | Restores original git branch and local files from rollback ledger. |

---

## 5. Build, Test & Verification Commands

```bash
# 1. Build in debug mode
cargo build

# 2. Run all unit & integration tests
cargo test --workspace

# 3. Check lints (treat all warnings as errors)
cargo clippy --workspace -- -D warnings

# 4. Check formatting
cargo fmt --check

# 5. Build optimized release binary
cargo build --release

# 6. Verify stripped binary size (< 8MB target)
strip target/release/sentris
ls -lh target/release/sentris

# 7. Benchmark performance
hyperfine --warmup 3 'target/release/sentris scan .'
```

---

## 6. Current Sprint Objective

* **Milestone 1 — High-Performance Local Scanner Engine:** ✅ **COMPLETED**
  * Binary size: **1.9 MB** (target was < 8.0MB).
  * Scan speed: **16ms** for 30 files.
  * Formats supported: ANSI table, JSON schema, `--fail-on-secret` CI exit codes.
* **Milestone 2 & 3 — SARIF 2.1.0 Exporter & Pre-Commit Git Hook Engine:** ✅ **COMPLETED**
  * OASIS SARIF v2.1.0 exporter for GitHub Advanced Security upload.
  * `sentris install` and `sentris uninstall` lifecycle verified.
  * `sentris scan --staged` executes in <45ms and blocks commits with live secrets.
  * 11 unit tests passing, 0 warnings.
* **Active Milestone: Milestone 4 — Autonomous Safe Remediation (Stripe Pilot with Dual-Key Safety)**
  * Implement async provider trait (`verify`, `rotate`, `deprecate`).
  * Implement Stripe API integration with read probe verification.
  * Implement atomic backup branch creation and rollback ledger (`.sentris/rollback_ledger.json`).
  * Implement `.env` injection and source code string replacement.
