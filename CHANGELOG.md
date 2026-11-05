# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged yet.

## [Unreleased]

### Added
- **MCP Supply-Chain, Tool Poisoning & Prompt-Injection Guard**: detects unpinned MCP `npx` packages (`mcp-unpinned-npx-server`), hidden Unicode Tag / Trojan Source bidirectional override characters (`unicode-prompt-injection`), and prompt-injection credential exfiltration instructions (`ai-prompt-injection-exfil`) in `.mcp.json`, `SKILL.md`, `CLAUDE.md`, `AGENT.md`, `.cursorrules`, and `.windsurfrules`, plus blocks hidden Unicode tags in `sentris hook` (`UserPromptSubmit` / `PostToolUse`)
- **Container Image & "Ghost Layer" Tarball Scanner (`sentris scan --docker <image-or-tar>`)**: pure-Rust OCI/Docker tarball parser that recursively walks nested `layer.tar` archives and flags secrets deleted in later image layers (`[GHOST LAYER]` via `.wh.<file>` whiteouts or layer overwrites) that remain extractable from image layer history
- **Vault Coverage % & Secrets Drift Auditor (`sentris drift [path] [--fail-on-drift]`)**: audits source code environment variable references (`process.env.*`, `os.environ.get(...)`, `std::env::var(...)`, `${{ secrets.* }}`, `var.*`) against `.env.example`, `.env`, and rollback ledgers to compute `vault_coverage_pct` (also included in `sentris audit --export-vanta` under `OWASP_NHI_2025`)
- **Zero-Friction Auto-Fix on Pre-Commit (`sentris scan --staged --fix` & `sentris install --auto-fix`)**: automatically extracts staged secrets into `.env`, rewrites source code, syncs `.env.example`, and re-stages the fixed files during `git commit`
- **Test-Fixture Classifier (`sentris scan --ignore-tests`)**: suppresses findings in `tests/`, `__tests__/`, `fixtures/`, `testdata/`, `*_test.*`, and `*.spec.*` when scanning production codebases
- **Cloudflare API Token Live Rotator (`CloudflareRotator`)**: live token roll (`PUT /user/tokens/{id}/value`) integrated into `sentris fix --rotate` for `cloudflare-api-token`
- IaC, MCP & AI Transcript Smart Patching in `CodeReplacer`: native GitHub Actions (`${{ secrets.VAR }}`), Terraform (`var.<name>`), Dockerfile / Docker Compose / Kubernetes (`"${VAR}"`), MCP JSON (`"${VAR}"`), and in-place `.jsonl` / `.zsh_history` / `.bash_history` secret scrubbing (`[REDACTED_BY_SENTRIS:VAR]`)
- `sentris scan --stdin` stream scanner for CI/CD logs (`gh run view --log`), `docker history`, and Kubernetes manifests
- `sentris fix --workstation` autonomous remediation and scrubbing across local `.mcp.json` configs, Claude Code `~/.claude/projects/**/*.jsonl` session transcripts, and shell history files
- Canary / Honeytoken pre-flight tripwire detection (`detect_canary_token`) to skip outbound network verification on Thinkst Canary and GitGuardian honeytokens without triggering false SOC alarms
- 2 new live verifiers (`Cloudflare`, `DigitalOcean`, bringing `VerifierRegistry` to 12 providers) and 4 new 2026 AI/RAG & Cloud detector rules (`cloudflare-api-token`, `tavily-api-key`, `pinecone-api-key`, `firecrawl-api-key`, bringing built-in rules to 119)
- `CODEOWNERS` team ownership attribution (`GitManager::resolve_codeowners`) integrated into `sentris investigate` (`OWASP NHI1`) plus `OWASP_NHI_2025` and `PCI_DSS_v4_0` compliance attestations in `sentris audit --export-vanta`
- `sentris run` zero-disk `.env` runtime runner: fetches secrets from `env`, `vault`, `aws`, `doppler`, `1password`, or `infisical` directly into child process memory and zeroizes parent buffers
- `sentris revoke` guided and API-driven (`--api` for GitHub tokens) credential revocation with 2-second live verification polling (`--wait`) and `KeyDeactivated` SOC 2 audit ledger entries
- `sentris scan --workstation` auditor for AI coding agent & MCP configs (`.mcp.json`, Cursor, Claude Code/Desktop, Windsurf, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.git-credentials`)
- `PostToolUse` guard in `sentris hook` to block tool outputs (`stdout`, `stderr`, `output`, `content`, `text`) containing secrets before they enter AI context windows
- Multi-layer Base64 (including Kubernetes `Secret` YAML `data:` blocks) and URL-percent secret decoding integrated into `DetectorEngine` (`DECODE_OWNER`)
- 4 new live verifiers (`Hugging Face`, `GitLab`, `Groq`, `SendGrid`, bringing `VerifierRegistry` to 10 providers) and 2 new read-only capability exposure probes (`Hugging Face`, `GitLab`, bringing `--probe` to 5 providers)
- Release pipeline (`release.yml`): 5 targets, SHA256SUMS, CycloneDX SBOM, build provenance attestations; installer verifies checksums
- 115 detection rules including vendor token formats, URL basic auth, password literals and keyed secrets
- Git history scan, SARIF output, MCP server, LSP
- Reproducible benchmark harness (`bench/`) against gitleaks, trufflehog and kingfisher with pinned versions
- Web dashboard and API (`web/`): ingest, billing webhooks, rate limits, CSP
- Zero-knowledge sync: fingerprints are HMACs under a team secret, previews are never uploaded

### Changed
- Data-oriented detector and scanner optimizations: Structure-of-Arrays (SoA) rule layout, flat `ImportedSecrets` arena with bit-packed `u32` handles, Rayon parallel file scanning, parallel `--git-history` diff scanning, and bounded 8-worker parallel HTTP verification/probing
- Upgraded `1Password` (`op item edit --template <0600-tempfile>`) and `Infisical` (`infisical secrets set --file=<0600-tempfile>`) backends so all 6 backends write secrets without ever exposing values in process `argv`
- Aho-Corasick literal prefilter replaces the single large `RegexSet` (django checkout 8.7 s to under 0.5 s; peak RSS 143 MB to 20 MB)
- Source patching is atomic; `.env` writes refuse to clobber existing variables
- Mock backends are opt-in and labelled in CLI, JSON and MCP output

### Removed
- Fake `--rotate` implementations and unverified marketing claims

### Security
- Updated rustls, rustls-webpki and webpki-roots to clear RUSTSEC-2026-0346/0347/0348/0349/0381/0382
- `cargo audit` and `cargo deny` run in CI (`audit.yml`) and gate releases
- MCP workspace confinement, write gate and confirm tokens
- Rollback ledger integrity and tamper-evident audit chain
- Secrets passed to backends via stdin or private temp files, never argv
