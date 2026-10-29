# Sentris Value Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Every task is test-first: write the failing test named in its AC, watch it fail, implement, watch it pass, one commit.

**Goal:** Turn Sentris from "detect, fix, prove" into "detect, fix, rotate, investigate, prove" and make it the safe path for AI coding agents.

**Architecture:** New `src/rotator/` module beside `verifier/` and `remediator/`: a `Rotator` trait per provider plus a signed `RotationLedger` modelled on `RollbackLedger`. First provider shells out to the `aws` CLI exactly like the existing backends (no new HTTP signing code). Investigation, exposure probing and the agent hook reuse the scanner, the audit ledger and the MCP server.

**Tech Stack:** Rust (clap, ureq, serde, sha2, existing `keystore` HMAC), `aws` CLI shim pattern from `src/remediator/backend/aws.rs`, TypeScript/TanStack Start on Cloudflare Workers + D1 for the web pieces.

**Spec:** the ideas list in the 2026-10-29 product-brainstorm conversation; builds on `.claudedocs/tasks/hardening-plan.md` (Phase 6 "Moat"). SecretBench is intentionally out of scope (dataset not received; user will revisit).

Legend: ⬜ todo · 🟡 in progress · ✅ done · 👤 needs you · Size: S <2h, M half-day, L 1 day+

## Global Constraints

- Rule for every task (inherited from hardening-plan): not done until its AC passes, `cargo test` + `cargo clippy -- -D warnings` (Rust) or `npm run typecheck && npm test` (web) are green, one commit per task.
- Lints are enforced: `clippy::unwrap_used = "deny"`, `too_many_lines = "warn"`. No `unwrap()`; split long functions.
- No new crates unless a task says so. No `zeroize` crate today: reuse the `Remediator::zeroize_secret_string` pattern.
- A secret value (old or new) must never appear in: argv, logs, error strings, MCP payloads, either ledger, audit `details`, or web ingest. Ledgers store `fingerprint` + provider key id only.
- Write ledgers `0600` via `write_private`; never follow symlinks (`fsutil::reject_symlinks`).
- Copy rule (hardening T0.2): no README/site/llms.txt claim without a test or a "roadmap" label. Say "rotation: AWS IAM access keys only" until more providers ship.
- Evidence rule: never print "safe", "secure" or "no compromise". Print what was observed and its limits.
- Real mutation of external services needs explicit opt-in (`--rotate`, confirm token for MCP), same as `remediate`.

## Review Focus

Failure modes the feature set implies but no single task's happy path covers; each has an owning test in the task named.

1. Crash or store failure after the provider created the new key (secret exists only in memory): no orphan key, or the key id is named loudly for manual deletion. → **R3**
2. User's app still uses the old key and deactivation breaks production: `finish` refuses while the old key was used inside the grace window; `undo` reactivates. → **R3**
3. Ambient AWS credentials are the leaked key itself (rotating with the key being rotated). → **R2**
4. IAM user already holds 2 access keys (AWS hard limit): refuse, never auto-delete. → **R2**
5. Empty CloudTrail result read as "safe": output must state window + management-events-only limit. → **F2**
6. Secrets in argv via placeholder expansion in `sentris run`: expansion only into env values and stdin. → **X2**

## Demand gate (read before scheduling)

hardening-plan Phase 6 says "no item starts without ≥3 users asking for it". This plan is deliberately ahead of that gate. Mitigation: R0 and A-phase are cheap and reversible; R2+ is the first real investment. Suggested check before R2: 3 conversations with users who have leaked a key and asked "can it also rotate?" If fewer, ship A-phase first (smaller, no external side effects).

## Phase map

| Phase | Goal | Depends on | Est. |
|---|---|---|---|
| R (7) | Real rotation, AWS IAM access keys, grace + undo | none | 3d + 👤 |
| F (8) | "Was it used?" forensics after a leak | R2 (principal helper) | 1.5d |
| D (9) | Exposure triage: what can this key do | R2 (principal helper) | 1.5d |
| A (10) | AI-agent firewall: redact + Claude Code hook | none (parallel to R) | 2d |
| X (11) | `sentris run`, no `.env` on disk | one backend live-tested | 1.5d + 👤 |
| M (12) | Growth: local stats, opt-in badge | R3 for best story | 1d + 👤 |

Execution order: R0 → (R1 → R2 → R3 → R4 → R5) ∥ (A1 → A2 → A3) → F1–F3 ∥ D1–D2 → X → M.

---

## Phase R: Real rotation (AWS IAM access keys first)

Why AWS first (to be confirmed in R0): an IAM user can hold at most 2 access keys, so "old and new side by side" is native; `update-access-key --status Inactive` is a reversible kill switch before any delete; the CLI is already a shell-out dependency. GitHub PATs are believed to have no create-via-API endpoint, so GitHub becomes "guided revoke + poll until `verify_live` says Revoked", not rotation.

### R0 ✅ Provider capability matrix (S) — output: `.claudedocs/rotation-capability-matrix.md`
- Official-docs research (WebSearch/Context7 per RULES): for AWS, GitHub, Stripe, OpenAI, Anthropic, Slack record: can a key be created via API? deactivated reversibly? deleted? max concurrent keys? Output `.claudedocs/rotation-capability-matrix.md`.
- **AC:** every cell has an official-doc URL · a one-line decision names the first provider and why · GitHub PAT cell states definitively whether programmatic create exists · CloudTrail `lookup-events` `AccessKeyId` attribute and 90-day/management-events-only limits are confirmed from docs (feeds F2).

### R1 ✅ Rotation domain + signed ledger (M)
**Files:** Create `src/rotator/mod.rs`, `src/rotator/ledger.rs`; Modify `src/lib.rs` (mod), `src/audit/mod.rs:31` (new variants), `src/error.rs`; Tests live in `#[cfg(test)]` modules (the state-dir lock `TEST_ENV_LOCK` is crate-private); `src/audit/vanta.rs` also counts the new actions.

**Interfaces — Produces:**
```rust
pub enum RotationState { Planned, Minted, Stored, OldDeactivated, OldDeleted, RolledBack }
pub struct RotationRecord {
    pub id: String, pub provider: String, pub rule_id: String,
    pub principal: String, pub old_key_id: String, pub old_fingerprint: String,
    pub new_key_id: Option<String>, pub backend: String,
    pub state: RotationState, pub created_at: u64, pub grace_until: u64,
}
pub struct RotationLedger { /* records + mac, mirrors RollbackLedger */ }
impl RotationLedger {
    pub fn path() -> PathBuf;                       // .sentris/rotation_ledger.json
    pub fn load() -> Result<Self, SentrisError>;
    pub fn save(&self) -> Result<(), SentrisError>;
    pub fn advance(&mut self, id: &str, to: RotationState) -> Result<(), SentrisError>;
}
pub trait Rotator: Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn plan(&self, old_secret: &str) -> Result<RotationPlan, SentrisError>;
    fn mint(&self, plan: &RotationPlan) -> Result<MintedCredential, SentrisError>;
    fn deactivate_old(&self, plan: &RotationPlan) -> Result<(), SentrisError>;
    fn reactivate_old(&self, plan: &RotationPlan) -> Result<(), SentrisError>;
    fn discard_new(&self, plan: &RotationPlan, new_key_id: &str) -> Result<(), SentrisError>;
    fn delete_old(&self, plan: &RotationPlan) -> Result<(), SentrisError>;
}
```
`RotationPlan { provider, rule_id, principal, old_key_id, old_fingerprint }` and `MintedCredential { key_id: String, secret: String }` (secret zeroized on drop of the caller's copy, never `Debug`-printed) are defined in `src/rotator/mod.rs`. `ProviderVerifier::rotate` (src/verifier/mod.rs) stays `NotImplemented` for providers without a `Rotator`; do not widen it.
- **AC:** test `illegal_transition_rejected` (e.g. Planned→OldDeleted) · `tamper_detected` (edit one byte → load errors, file not overwritten, mirrors rollback ledger behaviour) · `ledger_never_contains_secret` (serialize a record built from a known secret, assert 0 occurrences of it and of any `AKIA…` value) · file mode 0600 · existing audit ledgers still `verify_integrity()` after new `AuditAction::KeyRotated`/`KeyDeactivated` variants are added · `grace_until` computed from an injected clock, not `SystemTime::now()` inside logic.

### R2 ✅ AWS rotator via `aws` CLI (L)
**Files:** Create `src/rotator/aws.rs`; Tests in-module: a stateless shell shim passed via `AwsCli::with_program` (no PATH mutation), records argv per call.

**Interfaces — Consumes:** `Rotator` from R1. **Produces:** `pub struct AwsRotator;` implementing `Rotator`, plus `pub(crate) struct AwsCli { run(&[&str]) -> Result<String>, resolve_principal(&str) -> Result<String> }` (wraps `aws`, ambient credentials only), reused by F2 and D1.
- `plan`: resolve owning IAM user; `list-access-keys`; refuse if the user already has 2 keys.
- `mint`: `create-access-key --user-name`; parse `AccessKeyId`/`SecretAccessKey` from CLI JSON stdout into memory only.
- `deactivate_old` / `reactivate_old`: `update-access-key --status Inactive|Active`. `discard_new`/`delete_old`: `delete-access-key`.
- **AC:** `refuses_when_ambient_key_is_the_leaked_key` (env `AWS_ACCESS_KEY_ID == old key` → error, zero mutating calls) · `refuses_at_two_key_limit` (error names the user, zero `create-access-key` calls, nothing deleted) · `dry_run_is_read_only` (shim log contains only `get-`/`list-` verbs) · `argv_never_contains_secret` for old and new values · `unknown_principal` (access key not found) → clear error · all shim error paths map to `SentrisError`, no panic · `resolve_principal` has its own test with a recorded `get-access-key-last-used` fixture.

### R3 ✅ Orchestration: `remediate --rotate`, `rotate status|finish|undo` (L)
**Files:** Modify `src/remediator/mod.rs` (`remediate_finding_with_options`, line ~204), `src/cli/handlers/remediate.rs`; Create `src/cli/handlers/rotate.rs`; Test `tests/rotation_e2e_test.rs`.

Sequence for `remediate --rotate` (old key stays **active**): `plan` → persist `Planned` → `mint` → **immediately** `inject_secret(new)` into the chosen backend → persist `Stored` → patch source to reference the env var (existing path; the injected value is the new secret, the leaked literal is never written anywhere) → audit `KeyRotated`.
`rotate finish <id>`: refuse before `grace_until` unless `--force`; refuse if `get-access-key-last-used` shows the old key used inside the grace window (print service/region/time); else `deactivate_old` → `OldDeactivated`. Delete is a separate `--delete-old`, only from `OldDeactivated`, never default.
`rotate undo <id>`: `reactivate_old` (if deactivated), `discard_new`, → `RolledBack`.
- **AC (e2e, shim-driven):** after `remediate --rotate` the shim shows old key Active, new key present in backend, source patched, both ledgers written, `sentris audit --verify` passes · store failure after mint → `discard_new` called; if that also fails the output names the orphan key id and exits non-zero (**Review Focus 1**) · `finish` before grace → refuses; with recent old-key use → refuses and shows last-used; after grace and idle → old key Inactive (**Focus 2**) · `undo` after `finish` → old Active, new deleted · re-running `remediate --rotate` on the same finding after a crash resumes from the persisted state and never mints a third key · `sentris rollback` on a rotated session prints the rotation id and `rotate undo` hint · `--dry-run` prints the plan and mutates nothing · exit codes: 0 ok, 2 refused-by-policy, 1 error.

**R3 as built (deviations and limits):**
- Orchestration lives in `src/rotator/flow.rs` (`provision`, `finish`, `undo`, `delete_old`), unit-tested with a fake rotator + backend; CLI paths are covered by `tests/rotation_e2e_test.rs` against a shell shim selected with `SENTRIS_AWS_BIN`.
- Added `Rotator::last_used` and `Rotator::env_values` (AWS stores the new key id under the finding's env var and the secret under `AWS_SECRET_ACCESS_KEY…`), and `SentrisError::Refused` (CLI exit code 2).
- `--rotate` is refused with `--offline`, and with `SENTRIS_MOCK_BACKEND` (it would mint a real key and store nothing).
- Crash handling: a record stuck in `Planned` makes the next run refuse and point to `rotate undo` (a key may exist unrecorded); `Minted` is discarded then re-minted; `Stored` resumes without minting.
- `finish` blocks until `grace_until` (24h, constant `DEFAULT_GRACE_SECS`) and while the provider shows the old key used after the rotation began; provider last-used data may lag.
- Known limit: a separate `aws-secret-access-key` finding for the old key stays in code until remediated on its own; it stops working once the old key is deactivated.

### R4 ✅ MCP tools + docs/copy honesty (S)
- Add `sentris_rotate_plan` (read-only) and `sentris_rotate_apply` (needs the existing `confirm_token` + `require_writes()` gate in `src/mcp/tools.rs`); update `list_tools` manifest; README Status row: "Provider key rotation: AWS IAM access keys only"; remove nothing else.
- **AC:** apply without confirm token → refused, no shim calls · manifest test lists both tools · copy-lint script (T0.2) still passes · no payload contains a secret value.

**R4 as built (deviation):** instead of separate plan/apply tools, the existing `sentris_remediate_finding` accepts `rotate=true` (preview by default, writes need `SENTRIS_MCP_ALLOW_WRITES=1` plus a confirm token that now also binds the `rotate` flag, so a plain preview cannot authorise a rotation). New tools: `sentris_rotate_status` (read-only) and `sentris_rotate_finish` (preview/confirm, no `force`). `undo` stays CLI-only. Left as is, needs your call: `web/src/routes/app/index.tsx` says "Pro unlocks ... API key rotation" although rotation is in the free CLI, and `docs/HACKER-NEWS-LAUNCH.md` / `docs/CAREER-PORTFOLIO-PLAYBOOK.md` still carry the old rotation claims (M3).

### R5 👤 Live validation on a real throwaway AWS account (S)
- Create a dedicated IAM user + leaked-looking key, run the full R3 flow, delete everything afterwards. Region/SCP restrictions on IAM key creation in your AWS setup are unverified; this task answers that.
- **AC:** redacted transcript saved to `.claudedocs/rotation-live-aws.md` · README "Known gaps" updated from "unverified" to the observed result · all created IAM users/keys deleted (confirm with `aws iam list-users`).

---

## Phase F: Forensics, "was it used?"

### F1 ✅ Exposure window (S)
**Files:** Create `src/investigate/window.rs`; uses `src/git`.
**Produces:** `pub fn first_exposure(repo: &Path, fingerprint: &str) -> Result<Option<ExposureStart>, SentrisError>` where `ExposureStart { commit: String, author_time: u64 }`.
- **AC:** temp-repo test with the secret introduced in commit 2 of 4 returns commit 2 · secret never in history → `None` · output labels the time "author date of first commit containing the value; not the push time" · works on shallow clones (returns `None` with a stated reason, not a panic).

### F2 ✅ AWS usage report (M)
**Files:** Create `src/investigate/aws.rs`; Test with recorded CloudTrail JSON fixtures under `tests/fixtures/cloudtrail/`.
**Produces:** `pub fn usage_since(access_key_id: &str, since: u64) -> Result<UsageReport, SentrisError>`; `UsageReport { last_used: Option<…>, events: Vec<UsageEvent>, window_note: String }`; group by source IP + user agent + event name; `--known-ip` allowlist marks unknown IPs.
- R0 findings: `LookupEvents` takes one attribute (`AccessKeyId`), 50 events/page with `NextToken`, 2 requests/s/account/Region, 90 days, management events only; source IP and user agent are inside the `CloudTrailEvent` JSON string, so parse it.
- **AC:** pagination test (>50 events across pages) and throttling-retry test · fixture with 3 IPs (1 allowlisted) → 2 flagged · events before `since` excluded · empty result prints "no recorded use in CloudTrail event history (management events only, last 90 days)" and never "safe" (**Focus 5**) · CloudTrail throttling/permission error → distinct message pointing at the missing `cloudtrail:LookupEvents` permission · uses ambient credentials only, never the leaked key.

### F3 ✅ `sentris investigate <finding-id>` + MCP tool + audit entry (S)
- **AC:** human and `--json` outputs match golden files · MCP `sentris_investigate` is read-only and returns the same JSON · audit ledger gets an `InvestigationRun` record (finding id, provider, no secret) · unsupported provider → exit 0 with "no forensics for <provider> yet", not an error.

---

**F as built (deviations):** `first_exposure(repo, fingerprint)` returns `Exposure { start, note }` (the note carries the time semantics or the shallow/not-found reason) and finds the value by re-running the detector over added lines of `git log --all --reverse -p`, because a fingerprint is a hash and cannot be fed to `git log -S`. The CloudTrail query always covers the full 90 days: git author dates are forgeable, so they only label each group `after_exposure`/before, never narrow the window. CloudTrail-derived strings (IP, user agent, event name, region) have control characters stripped and are capped at 200 chars before printing or MCP output. `usage_since` refuses when `AWS_ACCESS_KEY_ID` is the key under investigation; `--known-ip` with an empty allowlist flags nothing. `sentris investigate` and `sentris_investigate` share `investigate_target`; the audit record (`InvestigationRun`) is written only for supported providers. MCP and CLI JSON are identical except `finding.file_path` (scan root spelling). Tested against a CLI stub and recorded CloudTrail JSON, **not yet against a real account** (fold into R5). `AwsCli::json` is now `pub(crate)`.

## Phase D: Exposure triage, "what can this key do"

Honesty note: a dollar figure is only shown when the provider returns a real number (Stripe balance). Everything else is a capability tier, not an invented dollar estimate.

### D1 ✅ `Exposure` model + read-only probes behind `--probe` (M)
**Produces:**
```rust
pub enum RiskTier { Low, Medium, High, Critical }
pub struct Exposure { pub provider: String, pub live: LiveStatus, pub capabilities: Vec<String>,
                      pub tier: RiskTier, pub measured_usd: Option<f64> }
pub trait ExposureProbe { fn probe(&self, secret_or_keyid: &str) -> Result<Exposure, SentrisError>; }
```
- Stripe: `GET /v1/balance` (live vs test, available balance); restricted-key 403 → capability "restricted, balance not readable". AWS: policy inspection of the **owning user via ambient creds** (admin policy attached → Critical); the leaked key is never used for this. GitHub: scopes (already returned) + org membership.
- **AC:** each probe has a recorded-fixture test · probes are GET/list/describe only (grep test over probe code for mutating verbs/methods) · without `--probe`, behaviour is identical to today (no new network calls; assert via a failing-transport test) · every probe call is noted in the audit record ("probe performed with credential fingerprint …") · `measured_usd` is `None` unless the provider returned it.

**D1 as built (deviations and limits):**
- Code in `src/exposure/` (`mod.rs` types + `probe_report`, one file per provider, `http.rs` GET-only `Http` seam). Verdicts live in `ScanReport.exposures`, keyed by fingerprint (one probe and one audit note per distinct credential), not on `Finding`; `exposures` is absent from JSON unless `--probe` ran.
- Audit: `AuditAction::ExposureProbed` written just before each network call, details carry "probe performed with credential fingerprint <12 hex>". `--offline` suppresses all probes (stderr note).
- A probe that cannot answer (network, 429, unknown key, ambient key == probed key) is `Unverified` and keeps the finding's severity as its tier: an unanswered probe never lowers risk.
- Stripe: 403 counts as "live restricted key" only for `rk_` keys. GitHub: tier from classic scopes + `/user/orgs` count (a lower bound without `read:org`); fine-grained/app tokens send no scope header and are `Medium` with that stated. AWS: attached managed policies of the owning user and its groups; only AWS-managed `AdministratorAccess`/`IAMFullAccess` (Critical) and `PowerUserAccess` (High) are recognised, inline policy contents, boundaries and SCPs are not evaluated and the output says so.
- Fixtures are shaped from the provider docs, not captured from live accounts; fold a live pass into R5.

### D2 ✅ Rank findings by tier (S)
- Sort `scan --probe` output, SARIF `properties.sentris.tier`, and `--json` by tier then rule.
- **AC:** ordering test over mixed fixtures · SARIF validates against schema (existing SARIF test) · `--fail-on critical` exit-code flag works and is documented in `--help`.

**D2 as built:** `rank_findings` (tier desc, then rule, path, line) runs only when probes produced exposures, so output order is unchanged without `--probe`. A finding's tier is the probe's verdict, else its severity (`tier_of`). `--fail-on <tier>` also works without `--probe` (severity tiers) and exits 1 with a stderr line. SARIF gets `properties.sentris.tier` on probed results only; the existing SARIF structure is untouched otherwise. The exposure text section honors `--no-color`/`NO_COLOR` (the older `--verify` output still does not).

---

## Phase A: AI-agent firewall

Staged on purpose: text redaction and a Claude Code hook now; a TLS-intercepting proxy is a non-goal (new attack surface, large trust cost).

### A1 ✅ Scan and redact arbitrary text (M)
**Files:** Create `src/redact.rs`; reuse scanner internals (confirm the entry point that scans a `&str` during the task; add a thin public wrapper if only file-based scanning is exposed).
**Produces:** `pub fn scan_text(text: &str) -> Vec<Finding>`; `pub fn redact(text: &str, findings: &[Finding]) -> String` replacing each secret with `«sentris:<rule_id>:<fp8>»`.
- **AC:** `redact_is_idempotent` · `preserves_non_secret_bytes` (byte-diff outside spans is empty) · multi-secret and adjacent-secret cases · multi-line PEM redacted as one span · output never contains any original secret substring (property test over the test corpus rules) · unicode boundaries safe (no panic on multibyte neighbours).

**A1 as built:** `src/redact.rs` (`redact(&DetectorEngine, &str) -> Redaction`, plus `Scanner::redact_text`). If a secret cannot be isolated on its line the whole line is hidden (fail-safe). A corpus-wide property test (`tests/corpus_test.rs::redaction_removes_every_detected_secret_in_the_corpus`) found that the generic rule re-flagged its own marker; the detector now ignores any candidate containing `sentris:` so redaction is idempotent.

### A2 ✅ MCP `sentris_redact_text` (S)
- **AC:** returns redacted text + findings metadata (no raw secrets) · size cap (reject > documented limit with clear error) · listed in manifest test · works with `--offline`.

### A3 ✅ `sentris hook` for Claude Code (M)
- Research first: confirm the current hook stdin JSON and exit-code contract from official Claude Code docs; record URL in the task commit message.
- Modes: `UserPromptSubmit` (block prompts that contain a secret, exit 2 with message naming the rule, not the value) and `PreToolUse` (deny `Read`/`Grep`/`Bash` that target `.env*`, `*.pem`, `id_rsa*`, or whose input contains a secret). `sentris hook --print-config` prints the `settings.json` snippet; it never edits user settings.
- Configurable `--fail-open` (default) vs `--fail-closed` for internal errors.
- **AC:** fixture-driven tests built from the documented hook JSON for each mode · `.env` read denied, `.env.example` allowed · prompt containing `sk-…` test key blocked, message has no raw value · malformed stdin → follows fail-open/closed flag · measured median and p95 latency recorded in the PR description (no latency claim in copy without those numbers) · `--print-config` output is valid JSON that parses.

**A3 as built:** contract confirmed from https://code.claude.com/docs/en/hooks (`UserPromptSubmit` stdin `prompt`; `PreToolUse` `tool_name`/`tool_input`; exit 2 blocks, stderr goes to the user for prompts and to Claude for tools). One command, `sentris hook`, dispatches on `hook_event_name`. Latency measured on the release build (macOS, 60 runs each): median 15.3 ms, p95 15.9 ms for a clean prompt, a clean Bash call and a denied `.env` read. Two automated security reviews of A1 led to fail-closed redaction (inline ignores, truncated PEM) and a marker check that requires a real rule id. Hardened after a third automated review: the hook uses `Scanner::trusted()` (built-in rules, never a repo `.sentris.toml`; confirmed that a broken repo config previously made the hook exit 0), oversize or scanner-start failures always block, Grep `glob` and `.ssh/.gnupg/.aws` directories are checked, symlinks are resolved, Bash denies any token naming a secret file except for known name-only commands (`echo`, `ls`, `git add`, ...), and agents cannot edit `.sentris.toml`. Known limits: no `PostToolUse` output scan, no shell expansion or glob resolution, `Glob` and `Task` are not inspected.

---

## Phase X: `sentris run` (no `.env` on disk)

Gate: one backend (Vault dev server or AWS) must be live-tested first; hardening-plan "Known gaps" says none is today.

### X1 ⬜ Read path on backends (M)
**Modify:** `SecretStoreBackend` in `src/remediator/backend/mod.rs` gains `fn fetch_secret(&self, key: &str) -> Result<String, SentrisError>` (default `NotImplemented`); implement for `Env` and the one live-tested backend.
- **AC:** round-trip test inject→fetch · fetch never logs value · mock backend returns `mock:true` consistently with T1.2 · unimplemented backends return `NotImplemented`, not an empty string.

### X2 ⬜ `sentris run -- <cmd>` (M)
- Resolve `NAME` references from the backend, set them as child **environment** only, pass through stdin/stdout/exit code and forward SIGINT/SIGTERM. `{{secret:NAME}}` placeholders expand in env values and stdin only; in argv they are an error (**Focus 6**).
- **AC:** child sees the secret in env, `ps`-style argv capture does not (shim test) · exit code passthrough (0, 1, 130) · placeholder in argv → refused with explanation · missing secret → non-zero before spawning the child · README states the residual risk: same-user processes can read the child's environment.

---

## Phase M: Growth surfaces

### M1 ⬜ `sentris stats` from local ledgers (S)
- Counts scans, secrets remediated, rotations, rollbacks from audit + rotation ledgers; no network.
- **AC:** golden output on a fixture ledger · zero state → friendly empty output · offline works.

### M2 ⬜ Opt-in public badge (M)
**Files:** `web/src/routes/api/badge/…`, migration `0004_badge.sql`, `web/src/server/badge-core.ts` + test.
- Per-repo toggle, default **off** (a badge reveals security posture of a possibly private repo). Grade is derived from existing rollup table data (open findings, age), returned as SVG with `Cache-Control: public, max-age=300`.
- **AC:** disabled repo → 404 identical to nonexistent repo (no existence oracle) · grade function unit-tested at boundaries · SVG escapes repo name (XSS test) · toggle requires org admin · rate-limited via existing `limit.ts` · `npm run typecheck && npm test` green.

### M3 👤 Launch assets for rotation (M)
- Update HN/launch copy after R5 passes: a real transcript, honest "AWS first" scope.
- **AC:** every number or command in the copy maps to a test, transcript, or "roadmap" label (T0.2 rule).

---

## Deferred (with revisit triggers)

| Idea | Why deferred | Revisit when |
|---|---|---|
| Public-leak threat-intel feed | Today's fingerprints are keyed by a team secret the server never sees; matching public leaks needs a global fingerprint, which contradicts the zero-knowledge design. Needs an explicit product/privacy decision. | ≥3 customers ask, and a privacy design is written |
| Declarative provider spec (YAML) | Rule of three: wait until two `Rotator`s exist so the shape is known, not guessed | Second provider rotator lands |
| Canary credential swaps | New legal/ops surface, needs provider canary accounts | After forensics (F) proves demand |
| Git history rewrite | High blast radius on shared repos; needs its own rollback design | Users ask after rotation exists |
| Non-git surfaces (Docker layers, CI logs, bundles) | Each is a new scanner front-end; recall unmeasured | SecretBench or equivalent corpus available |
| GitHub App / PR bot | Already in hardening Phase 6 | Demand gate met |
| Usage-based pricing (per rotation) | Metering needs real rotation volume | After M3 launch data |
| Insurance attestation report | Unverified that insurers accept it | A buyer asks |
| TLS-intercepting LLM proxy | Trust and attack-surface cost | Not planned |

## Definition of done (whole plan)
- [ ] R0–R4 AC pass; R5 live transcript saved; README says "AWS IAM access keys only".
- [ ] `cargo test`, `cargo clippy -- -D warnings`, `cargo audit`, web typecheck/test/build green.
- [ ] No secret value found by grepping logs, ledgers, audit file, MCP payloads and shim logs from a full e2e run.
- [ ] Every new CLI flag/command appears in `sentris --help` and in the copy-lint check.
- [ ] No claim without a test, transcript, or "roadmap" label.
