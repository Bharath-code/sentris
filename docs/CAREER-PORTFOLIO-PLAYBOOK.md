# 💼 Sentris Portfolio & Career Playbook ($150k–$250k Remote US Roles)

How to turn **Sentris** into an unfair advantage to land high-paying remote US engineering roles (**Senior DevSecOps Engineer**, **Rust Systems Engineer**, **Staff Security Infrastructure Engineer**).

---

## 1. Resume Bullet Points (Ready to Copy-Paste)

### Project Section:
> **Sentris — High-Performance Zero-Knowledge Secret Scanner & Autonomous Remediation CLI**  
> *Rust • Rayon • Git Internals • OASIS SARIF 2.1.0 • Systems Security* | [GitHub Link]
> - Architected and engineered an open-source secret scanning CLI in pure Rust, achieving **sub-35ms pre-commit index scans** and **>10,000 files/sec** parallel throughput across thread pools using Rayon and `ignore`.
> - Designed an **autonomous dual-key credential rotation engine** with Stripe and AWS API integrations; established a 24-hour deprecation grace window preventing microservice outages, paired with an append-only JSON rollback ledger.
> - Implemented a **3-tiered Git history safety model** that classifies leaked credentials into working tree, local commit, and remote history zones, preventing destructive `git push --force` team collisions via isolated quarantine branches and automated playbooks.
> - Engineered native **OASIS SARIF v2.1.0** export for GitHub Code Scanning and cross-platform distribution pipelines (Homebrew, Linux musl, macOS, Windows) producing a single, self-contained **3.2MB stripped binary**.
> - Enforced strict **zero-knowledge privacy guarantees**, processing salted HMAC-SHA256 telemetry fingerprints with zero raw source code or credentials leaving the client.

---

## 2. Technical Interview Talking Points & Architecture Defense

When an interviewer asks: *"Tell me about a challenging systems or security project you built recently."*

### 🎙️ The 2-Minute Elevator Pitch:
> "I designed and built **Sentris**, a 3.2MB static Rust binary that solves the biggest pain point in DevSecOps: traditional secret scanners (like TruffleHog or Gitleaks) only alert, turning leaked credentials into a 45-minute incident fire drill.
> 
> Sentris turns alerts into an autonomous 15-second fix. It verifies the leaked credential via provider APIs, provisions a replacement, updates `.env`, patches multi-language source code with AST accessors, and queues the old key for a 24-hour deprecation window so production checkout services never experience downtime.
> 
> On the performance side, standard pre-commit hooks take 2 to 3 seconds, so developers bypass them with `--no-verify`. I built Sentris in pure Rust using Rayon thread pools and diff hunk streaming, getting pre-commit scan latency down to **under 35ms**."

---

### 🧠 Deep-Dive Architecture Questions & Exact Answers

#### Q1: "How did you ensure git history rewriting doesn't break production or cause split-brain for team members?"
**Answer:**
> "I implemented a strict 3-Tier Git Zone invariant:
> - **Zone 1 (Working Tree / Staged):** In-place file patch before commit creation.
> - **Zone 2 (Unpushed Commits):** Clean local `git commit --amend` or interactive rebase.
> - **Zone 3 (Pushed Remote History):** Blind force-pushes are strictly prohibited. Sentris creates an isolated branch (`sentris/quarantine/<finding-id>`), generates an automated scrub playbook with `git-filter-repo` commands, and mandates scheduled team coordination using `--force-with-lease`."

#### Q2: "How did you achieve a 3.2MB binary without sacrificing capabilities?"
**Answer:**
> "Three deliberate architectural decisions:
> 1. Avoided heavy async runtimes (`tokio` + `reqwest` add ~40MB and hundreds of dependencies). Used synchronous `ureq` with pure Rust `rustls` for lightweight, memory-safe HTTPS.
> 2. Applied Fat Link-Time Optimization (`lto = 'fat'`), single codegen unit (`codegen-units = 1`), `panic = 'abort'`, and binary symbol stripping.
> 3. Zero dynamic C runtime dependencies—everything compiles to a single self-contained executable."

#### Q3: "What prevents false positives on high-entropy data like UUIDs or SVG images?"
**Answer:**
> "A two-phase detection filter:
> 1. Curated regex catalog compiled once at startup with exact token prefix anchors (`sk_live_`, `AKIA`, `ghp_`).
> 2. Shannon entropy evaluation gate ($H \ge 3.0$). Repetitive strings and low-entropy sequences are dropped before fingerprint generation.
> 3. Universal inline comment parser supporting `sentris-ignore`, `gitleaks:allow`, `nosec`, and `trufflehog:ignore`."

---

## 3. Target Roles & Compensation Benchmarks

| Role Title | Target Companies | Typical US Remote Compensation |
|---|---|---|
| **Senior DevSecOps Engineer** | Series B–D Startups, Scale-ups | **$160,000 – $210,000 / year** |
| **Rust Systems / Infrastructure Engineer** | Crypto, Cloudflare, Datadog, Fastly | **$175,000 – $240,000 / year** |
| **Staff Security Engineer (Product/AppSec)** | Stripe, Vercel, HashiCorp, GitHub | **$210,000 – $275,000 / year** |

---

## 4. GitHub Repository Checklist for Maximum Recruiter Impact
- [x] High-contrast SVG/PNG logo & ASCII banner
- [x] Clear CI badges (passing tests on Linux, macOS, Windows)
- [x] Clean benchmark comparison table vs legacy tools
- [x] Animated terminal GIF showing the 15-second remediation flow
- [x] 1-line installation instructions (`brew install`, `curl | sh`)
- [x] Reusable GitHub Action (`action.yml`)
- [x] Fully tested codebase (23 unit & integration tests passing, 0 warnings)
