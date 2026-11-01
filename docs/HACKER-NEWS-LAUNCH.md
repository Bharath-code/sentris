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

1. **Sub-35ms Pre-Commit Hook:** Scans git index staged diffs in <35ms. Because it’s written in Rust with Rayon and ignore-walker, developers won't bypass it with `--no-verify`.
2. **Remediation with a rollback:** Sentris moves the hardcoded credential into `.env` or a secret store (Vault, AWS Secrets Manager, Doppler) and patches the code. For AWS IAM access keys only, `--rotate` creates a second key and leaves the old one active until you run `sentris rotate finish` (24h grace, refuses while the old key is still in use). Every other provider: the leaked key stays valid until you revoke it at the provider. Rotation is tested against a CLI stub, not yet a real AWS account.
3. **1-Click Rollback Ledger:** Every file mutation is logged to an append-only `.sentris/rollback_ledger.json`. Running `sentris rollback` instantly restores the original state.
4. **Zero-Knowledge Privacy:** Raw code and secrets never leave your workstation. Only salted HMAC-SHA256 telemetry fingerprints are ever processed.
5. **Nuclear Force-Push Guard:** 3-tiered Git Zones. Working tree edits are in-place; unpushed commits are amended; remote history commits are isolated into `sentris/quarantine/<id>` branches with automated team coordination playbooks. No blind `git push --force`.
6. **Ultra-lightweight:** single static binary (~4.6MB) with zero runtime dependencies (no external OpenSSL or Python requirement).

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
