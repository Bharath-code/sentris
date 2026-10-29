# Security Policy

Sentris is pre-release (0.1.x). Only the latest commit on `master` is supported.

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub:
<https://github.com/Bharath-code/sentris/security/advisories/new>

Include affected version or commit, reproduction steps, and impact. Expect an acknowledgement within 7 days. Fixes are developed privately and credited in the advisory unless you prefer otherwise.

## In scope

- The `sentris` CLI, its MCP server and LSP (`src/`)
- The hosted dashboard and API (`web/`)
- Anything that makes Sentris leak, corrupt, or fail to restore a user's secrets or source files, or weakens its audit and rollback guarantees

## Out of scope

- Findings that only affect the synthetic secrets in `tests/` and `docs/` (all fixtures are fake)
- Denial of service through very large inputs on a local scan
- Backends not yet verified against live services: Vault, AWS and Doppler are tested with shims only, so integration bugs there are welcome as normal issues

## Known limitations

See "Known gaps" in `.claudedocs/tasks/hardening-plan.md` for the current honest list.
