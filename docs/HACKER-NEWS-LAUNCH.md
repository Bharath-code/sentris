# Show HN: Sentris – A Rust secret scanner that moves leaked keys into your secret store and patches the code

**URL:** https://github.com/Bharath-code/sentris  
**Author:** Sentris Contributors  

---

### Submission Title:
> **Show HN: Sentris – A Rust secret scanner that moves leaked keys into your secret store and patches the code**

---

### Submission Body:

Hey HN,

Every team has lived through the 4:55 PM Friday alert: a developer accidentally commits a live Stripe key, AWS access key, or GitHub token.

Existing tools (Gitleaks, TruffleHog, GitGuardian) stop at alerting you. Then begins the painful 45-minute incident drill:
1. Revoking the key immediately (which breaks live production checkout).
2. Hunting down every service that depended on it.
3. Rewriting git history on remote branches, triggering nasty rebase conflicts for everyone else on the team.

We built **Sentris** (https://github.com/Bharath-code/sentris) because we wanted a secret scanner that doesn't just alert—it moves the leaked value out of your source, patches the code, and can rotate AWS IAM access keys.

### What makes it different:

1. **Sub-25ms Pre-Commit Hook (with Optional Auto-Fix):** Scans git index staged diffs in `<25ms` (`sentris scan --staged`). With `sentris install --auto-fix` (`sentris scan --staged --fix`), it automatically extracts staged secrets into `.env`, rewrites the code to an idiomatic env var lookup, updates `.env.example`, and re-stages the fixed files so `git commit` succeeds cleanly.
2. **Autonomous Remediation Across Code, IaC & 6 Secret Stores:** Sentris moves hardcoded credentials out of source code (`.py`, `.ts`, `.js`, `.rs`, `.go`, `.java`, `.rb`, `.php`, `.sh`, multi-line PEM), IaC (`.github/workflows/*.yml`, `.tf`, `Dockerfile`, `.mcp.json`), and AI transcripts (`.jsonl`, `.zsh_history`) into `.env`, `Vault`, `AWS Secrets Manager`, `Doppler`, `1Password`, or `Infisical` (zero `argv` secret exposure). For **AWS IAM access keys** (`aws-access-key-id`) and **Cloudflare API tokens** (`cloudflare-api-token`), `--rotate` provisions/rolls the credential at the provider.
3. **"Secret Rot" & Drift Watchdog (`sentris rot` / `sentris drift`):** Watches `.env`, `.env.example`, CI workflows, and vendor keys after every deploy—flagging stale (`>90d`) unrotated keys, dead/revoked vendor keys (`--verify` across 12 provider APIs with Canary tripwire immunity), orphaned `.env` keys, and missing runtime vars, and pinging Slack (`--webhook`) the second a key rots or leaves the repo.
4. **Docker "Ghost Layer" & AI/MCP Supply-Chain Scanner:** `sentris scan --docker <image-or-tar>` walks OCI container layers in pure Rust to catch secrets deleted in later layers (`rm .env` whiteouts), while `sentris hook` and `sentris scan --workstation` block invisible Unicode tag prompt-injection (`U+E0000`–`U+E007F`), unpinned `npx` MCP servers, and plaintext keys in `~/.claude/projects/**/*.jsonl` transcripts.
5. **1-Click Atomic Rollback & Zone 3 Quarantine:** Every file mutation is logged to a signed `.sentris/rollback_ledger.json` (`sentris rollback` restores files byte-for-byte). Historical leaks are isolated into `sentris/quarantine-<id>` branches with a `git-filter-repo` playbook and `.github/CODEOWNERS` attribution (`sentris investigate`).
6. **Zero-Knowledge Privacy & 4.0 MB Static Binary:** Raw code and secrets never leave your workstation (RAM buffers are scrubbed with `write_volatile` after use). Single static Rust binary (`~4.0 MB`) with built-in MCP server (`sentris mcp`, 14 tools) and LSP 3.17 server (`sentris lsp`).

### Benchmarks (Apple Silicon M-series):
- Staged Pre-Commit Diff: **12ms**
- Clean Repo (1,500 files): **16ms**
- Deep Git History Scan (1,000 commits): **240ms**
- Memory Footprint (Peak RSS): **18MB**

### Try it:
```bash
# Install via Homebrew
brew install sentris-security/tap/sentris

# Or one-line curl installer
curl -fsSL https://raw.githubusercontent.com/Bharath-code/sentris/master/install.sh | sh

# Scan current directory
sentris scan .

# Test autonomous remediation in dry-run preview mode
sentris remediate --dry-run
```

The CLI is completely open-source under the MIT license:  
👉 https://github.com/Bharath-code/sentris

We'd love your feedback on the UX, detection rules, and the remediation flow!
