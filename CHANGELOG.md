# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged yet.

## [Unreleased]

### Added
- 115 detection rules including vendor token formats, URL basic auth, password literals and keyed secrets
- Git history scan, SARIF output, MCP server, LSP
- Reproducible benchmark harness (`bench/`) against gitleaks, trufflehog and kingfisher with pinned versions
- Web dashboard and API (`web/`): ingest, billing webhooks, rate limits, CSP
- Zero-knowledge sync: fingerprints are HMACs under a team secret, previews are never uploaded

### Changed
- Aho-Corasick literal prefilter replaces the single large `RegexSet` (django checkout 8.7 s to under 0.5 s; peak RSS 143 MB to 20 MB)
- Source patching is atomic; `.env` writes refuse to clobber existing variables
- Mock backends are opt-in and labelled in CLI, JSON and MCP output

### Removed
- Fake `--rotate` implementations and unverified marketing claims

### Security
- MCP workspace confinement, write gate and confirm tokens
- Rollback ledger integrity and tamper-evident audit chain
- Secrets passed to backends via stdin or private temp files, never argv
