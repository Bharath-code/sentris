# Show HN: Sentris – A 3.2MB Rust Secret Scanner that Auto-Rotates Leaked Keys with 0s Downtime

**URL:** https://github.com/Bharath-code/sentris  
**Author:** Sentris Contributors  

---

### Submission Title:
> **Show HN: Sentris – A 3.2MB Rust Secret Scanner that Auto-Rotates Leaked Keys with 0s Downtime**

---

### Submission Body:

Hey HN,

Every team has lived through the 4:55 PM Friday alert: a developer accidentally commits a live Stripe key, AWS access key, or GitHub token.

Existing tools (Gitleaks, TruffleHog, GitGuardian) stop at alerting you. Then begins the painful 45-minute incident drill:
1. Revoking the key immediately (which breaks live production checkout).
2. Hunting down every service that depended on it.
3. Rewriting git history on remote branches, triggering nasty rebase conflicts for everyone else on the team.

We built **Sentris** (https://github.com/Bharath-code/sentris) because we wanted a secret scanner that doesn't just alert—it safely fixes the leak in 15 seconds.

### What makes it different:

1. **Sub-35ms Pre-Commit Hook:** Scans git index staged diffs in <35ms. Because it’s written in Rust with Rayon and ignore-walker, developers won't bypass it with `--no-verify`.
2. **Autonomous Dual-Key Staged Rotation:** When a live key is found, Sentris verifies it via the provider API (e.g. Stripe), provisions a replacement key, injects it into `.env`, updates source code with AST-aware environment variable accessors, and activates a **24-hour deprecation grace window** on the old key. No production microservices go down.
3. **1-Click Rollback Ledger:** Every file mutation is logged to an append-only `.sentris/rollback_ledger.json`. Running `sentris rollback` instantly restores the original state.
4. **Zero-Knowledge Privacy:** Raw code and secrets never leave your workstation. Only salted HMAC-SHA256 telemetry fingerprints are ever processed.
5. **Nuclear Force-Push Guard:** 3-tiered Git Zones. Working tree edits are in-place; unpushed commits are amended; remote history commits are isolated into `sentris/quarantine/<id>` branches with automated team coordination playbooks. No blind `git push --force`.
6. **Ultra-lightweight:** 3.2MB single static binary with zero runtime dependencies (no external OpenSSL or Python requirement).

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
curl -fsSL https://sentris.dev/install.sh | sh

# Scan current directory
sentris scan .

# Test autonomous remediation in dry-run preview mode
sentris remediate --dry-run
```

The CLI is completely open-source under the MIT license:  
👉 https://github.com/Bharath-code/sentris

We'd love your feedback on the UX, detection rules, and the dual-key rotation engine!
