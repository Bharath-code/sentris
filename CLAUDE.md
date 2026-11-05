# CLAUDE.md — Sentris Engineering & AI Agent Guide

This file provides guidance to Claude Code (`claude.ai/code`) and other AI coding agents when working in or operating on the **Sentris** repository.

---

## 1. Build, Lint & Test Commands

Always run these commands before concluding any code change:

```bash
# 1. Format check
cargo fmt --check

# 2. Strict Clippy lint check (0 warnings allowed across all targets)
cargo clippy --offline --all-targets -- -D warnings

# 3. Full test suite (401 tests: 339 unit + 62 e2e/integration/corpus/benchmark)
cargo test --offline

# 4. Run a single unit or integration test
cargo test --offline --lib exposure::tests
cargo test --offline --test exposure_e2e_test
```

---

## 2. Invoking Sentris as an AI Agent (`--json` & MCP)

When running `sentris` to scan or remediate secrets in a project, **always pass `--json`** (or set `SENTRIS_AGENT=1`) so output is deterministic JSON and interactive `[y/N]` prompts are auto-approved:

```bash
# Scan working tree, staged diff hunks (with optional --fix), Docker tarballs, stdin stream, or workstation AI/MCP configs & .jsonl transcripts
sentris scan . --json
sentris scan . --ignore-tests --json
sentris scan --staged --fix --json
sentris scan --docker app:latest --json
gh run view --log | sentris scan --stdin --json
sentris scan --workstation --json

# Audit Vault Coverage % & secrets configuration drift between code, .env.example, and .env
sentris drift . --json

# Probe live provider capabilities & OWASP NHI5 overprivilege advisories (skips Canary/Honeytoken tripwires)
sentris scan . --probe --json

# Remediate findings into .env / Vault / AWS Secrets Manager / Doppler / 1Password / Infisical
sentris fix <file_path> --yes --json
sentris fix . --all --yes --backend 1password --json
sentris fix --workstation --yes --json

# Atomic byte-for-byte rollback of the last remediation session
sentris rollback --json

# Export SOC 2 (CC6.1/CC6.7/CC6.8), ISO 27001 (A.8.24), OWASP NHI Top 10 (2025) & PCI-DSS v4.0 Vanta evidence
sentris audit --verify --export-vanta vanta-evidence.json --json
```

---

## 3. Core Architectural & Security Invariants

When modifying the Rust codebase, preserve these invariants (enforced by tests):

1. **Zero-Knowledge & Secret Hygiene:**
   - `Finding` structs never store raw secret bytes—only `redacted_match` and a SHA-256 `fingerprint`.
   - Whenever a secret is re-read from source (`Scanner::resolve_finding_secret`) for remediation, verification, or exposure probing, scrub the mutable `String` buffer immediately after use with `Remediator::zeroize_secret_string` (`std::ptr::write_volatile` + `compiler_fence(Ordering::SeqCst)`).
   - Secret store backends (`src/remediator/backend/`) and rotators (`src/rotator/`) must **never** pass raw secrets in child process `argv`; use `stdin` pipes or `0600` `SecretTempFile` templates.
2. **ASCII-Only Regex Patterns (`src/detector/patterns.rs`):**
   - Built-in detection patterns in `src/detector/patterns.rs` must use explicit ASCII character classes (`[0-9a-zA-Z_-]`, `[0-9]`) and **never** Unicode classes (`\w`, `\d`), enforced by `detector::patterns::tests::rule_patterns_use_ascii_classes_only`.
3. **Read-Only Exposure Probes & Canary Tripwire Immunity (`src/exposure/`, `src/verifier/`):**
   - Exposure probes (`src/exposure/*.rs`) must never use mutating HTTP verbs (`POST`, `PUT`, `PATCH`, `DELETE`), enforced by `exposure::tests::probe_sources_use_no_mutating_http_method`.
   - Both `scan --verify` and `scan --probe` run `verifier::detect_canary_token` before any network call so Thinkst Canary (`canarytokens.com`/`.org`) and GitGuardian Honeytoken (`ggcanary`, `honeytoken`, `sentris-canary`) markers never trigger false intrusion alarms.
4. **Polyglot Code, IaC, MCP & Transcript Replacement (`src/remediator/code_replacer/`):**
   - `CodeReplacer::get_env_accessor_for_path` and `CodeReplacer::replace_secret_in_file` handle:
     - Source code (`py`, `js`/`ts`, `rs`, `go`, `rb`, `php`, `java`, `cs`, `sh`, multi-line PEM blocks).
     - GitHub Actions workflows (`.github/workflows/*.yml` → `${{ secrets.<VAR> }}`).
     - Terraform (`.tf`, `.tfvars` → `var.<var_lowercase>`).
     - Docker & Compose (`Dockerfile`, `docker-compose*.yml`, `*.k8s.yml`, `.mcp.json` → `"${<VAR>}"`).
     - AI transcripts & shell histories (`.jsonl`, `.zsh_history`, `.bash_history` → in-place `[REDACTED_BY_SENTRIS:<VAR>]` substring scrubbing).
5. **Two-Phase Rotation (`src/rotator/`) & Forensics (`src/investigate/`):**
   - `sentris remediate --rotate` is implemented for `aws-access-key-id` (two-key grace window via `sentris rotate status|finish|undo`); unsupported rules must fail pre-flight with `SentrisError::NotImplemented` before mutating files or git branches.
   - `src/investigate/mod.rs` has golden output fixtures in `tests/fixtures/investigate/report.json` and `report.txt`. Any new fields on `Investigation` (such as `codeowners`) must be omitted when empty so golden outputs remain byte-identical.
6. **Symlink & Path Confinement (`src/fsutil.rs`, `src/mcp/tools.rs`, `src/hook.rs`):**
   - Reject symlinks before reading or writing sensitive files (`crate::fsutil::reject_symlinks`).
   - `Scanner::trusted()` (used by `sentris hook`) ignores any `.sentris.toml` inside the working tree so an untrusted repository cannot weaken the Claude Code hook guardrails.

---

## 4. Key Module Map

- `src/detector/`: Single-pass Aho-Corasick literal prefilter, Structure-of-Arrays (SoA) engine, 119 rules (`patterns.rs`), Base64/URL-percent decoder (`decode.rs`), and 6-layer false-positive filter (`false_positives.rs`).
- `src/scanner/`: Parallel work-stealing directory walker (`scan_path`), staged diff-hunk scanner (`scan_staged`), `--stdin` stream scanner (`scan_reader`), and workstation AI/MCP/transcript scanner (`scan_workstation`).
- `src/verifier/` & `src/exposure/`: 12 live provider verifiers, canary tripwire detector (`detect_canary_token`), 5 read-only capability exposure probes, and `OWASP NHI5` least-privilege scope advisor (`advise_least_privilege`).
- `src/remediator/`: 7-step remediation pipeline, 6 secret store backends (`env`, `vault`, `aws`, `doppler`, `1password`, `infisical`), polyglot/IaC/transcript replacer (`code_replacer/`), and byte-exact rollback ledger (`rollback.rs`).
- `src/git/` & `src/investigate/`: Diff-hunk parser, history scanner, Zone 3 quarantine playbook generator, `.github/CODEOWNERS` attribution (`resolve_codeowners`), AWS OIDC trust policy generators (`generate_aws_oidc_trust_policy`), and CloudTrail forensics.
- `src/mcp/`, `src/lsp/`, `src/hook.rs`, `src/redact.rs`: JSON-RPC 2.0 MCP server (14 tools), LSP 3.17 server, Claude Code `PreToolUse`/`PostToolUse`/`UserPromptSubmit` hook guardrails, and `«sentris:<rule>:<fp8>»` phantom-token redaction.
- `src/audit/`: Tamper-evident RFC 2104 HMAC-SHA256 hash chain and Vanta/Drata compliance pack exporter (`SOC 2`, `ISO 27001`, `OWASP NHI Top 10:2025`, `PCI-DSS v4.0`).
