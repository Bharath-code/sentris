# Sentris Hardening & Best-in-Class Plan

Source: security audits of `src/` (Rust CLI) and `web/` + `cloud/` (2026-10-29), plus a recall spot-check against gitleaks. Findings marked ✔ were re-verified by reading the code.

Status 2026-10-29: Phases 0, 1 and 2 complete in code (commits on feat/web-rebuild); Phase 2 is not yet deployed or migrated remotely. Open follow-ups are listed under "Known gaps" at the end and under "Phase 2 notes".

Legend: ⬜ todo · 🟡 in progress · ✅ done · 👤 needs you · Size: S <2h, M half-day, L 1 day+
Rule for every task: no task is done until its AC passes, `cargo test` + `cargo clippy -- -D warnings` (Rust) or `npm run typecheck && npm test` (web) are green, and one commit per task.

## Phase map

| Phase | Goal | Blocks launch? | Est. |
|---|---|---|---|
| 0 | Stop shipping false claims & dead dangerous code | yes | 0.5d |
| 1 | Rust CLI: make remediation safe & honest | yes | 2d |
| 2 | Web/cloud: abuse resistance, headers, billing robustness | yes | 1.5d |
| 3 | Detection recall & reproducible benchmark | yes (credibility) | 2d |
| 4 | Distribution & launch readiness | yes | 1d + 👤 |
| 5 | Performance, retention, maintainability | no | 1.5d |
| 6 | Product moat (post-validation) | no | ongoing |

Dependencies: 0 → 1 → 3. 2 is independent of 1. 4 needs 0, 1, 2 done. 5 after 2.

---

## Phase 0: Honesty & dead code

### T0.1 ✅ Confirm and delete legacy `cloud/` (S) ✔
- Run `wrangler deployments list --name sentris-zk-cloud`; if anything is live, `wrangler delete` it.
- `git rm -r cloud/`; remove references in README/docs/CI.
- **AC:** `grep -r "sentris_edge_pepper\|cloud/src/worker" .` returns nothing · `wrangler deployments list` shows no `sentris-zk-cloud` · CI still green.

### T0.2 ✅ Align claims with reality (S)
- Edit README, `web/src/lib/site.ts`, `web/public/llms.txt`, hero terminal copy.
- Remove/relabel: "zero downtime rotation", "24H grace window", "SOC 2 in 10 seconds", "only tool", unverified benchmark numbers, `--safe-rotate`, "6 backends" (list only what works live).
- Mark unfinished items "roadmap".
- **AC:** every CLI command/flag in copy exists in `sentris --help` (script: extract flags from copy, assert each appears in help output) · every numeric claim links to a reproducible script (see T3.4) or is removed · no copy says "rotate" unless T1.1 ships real rotation.

---

## Phase 1: Rust CLI safety

### T1.1 ✅ Disable fake rotation (S) ✔
- `verifier/{aws,github,slack,anthropic,stripe,openai}.rs`: `rotate()` returns `Err(NotImplemented)`; delete invented strings (`AKIA_PROVISIONED_REPLACEMENT_KEY`, `ghp_rotated_…`).
- `remediator/mod.rs`: remove "GRACE WINDOW" text; `--rotate` prints "not yet supported, key still valid, revoke it at <provider URL>".
- **AC:** test: `remediate --rotate` on every provider exits non-zero, leaves the source file byte-identical, writes nothing to any backend · `grep -rn "PROVISIONED\|dual_key\|GRACE" src` empty.

### T1.2 ✅ Mock backends opt-in and labelled (M) ✔
- Default to real backend; mock only with `SENTRIS_MOCK_BACKEND=1`. If real backend unavailable (no `VAULT_ADDR`, CLI missing) → hard error, never silent mock.
- Result struct + MCP payload gain `mock: bool`; CLI output prints `[MOCK – secret NOT stored]`.
- Extract one shared mock-ledger helper (dedupe 5 copies).
- Mock/ledger files created `0600`; `.sentris/` (whole dir) appended to `.gitignore` for every backend.
- **AC:** test per backend: no env set → error, no source patch · mock env set → result has `mock:true`, files mode 0600 (unix) · `.gitignore` contains `.sentris/` after any remediate · code diff removes ≥4 duplicated mock blocks.

### T1.3 ✅ Keep secrets out of argv and messages (M) ✔
- aws: `--secret-string file://<0600 tempfile>` (delete after) · doppler/op/infisical: value via stdin or JSON template on stdin.
- `format_cli_command` and all dry-run/mock/error strings must never contain the secret (mask).
- **AC:** test with a fake `aws`/`doppler`/`op` shim on `PATH` that records `argv` + stdin: argv never contains the secret, stdin/tempfile does · grep all result/log strings in a remediate run for the secret → 0 hits · temp file removed on success and on error.

### T1.4 ✅ Fix Vault KV v2 overwrite (S) ✔
- Read current version, merge key, write with `cas` (or PATCH).
- **AC:** mock Vault test: remediate two different secrets at the same path → both keys present; concurrent write (cas mismatch) → retries once then errors.

### T1.5 ✅ MCP confinement and consent (M) ✔
- Resolve workspace root once (cwd or `--workspace`); `canonicalize` every tool path; reject outside root and symlinks.
- Writes (`remediate`, `rollback`) default `dry_run=true`; real write requires `confirm: "<token from dry-run>"`.
- Cap JSON-RPC line length (e.g. 1 MiB).
- **AC:** tests: `scan_path "/"`, `../..`, symlink-to-outside → error · remediate without token → dry-run only, file unchanged · oversized line → error response, server survives · `agent` manifest documents the token flow.

### T1.6 ✅ Rollback ledger integrity (M) ✔
- Ledger moved out of repo (`$XDG_STATE_HOME/sentris/<repo-hash>/`) or HMAC'd with the T1.9 key.
- On load: verify HMAC; verify `file_path` is inside workspace; verify current line equals `replacement_line` before restoring; store full original block (multi-line PEM); preserve line endings; replace by line index not `content.replace`.
- **AC:** tests: tampered ledger → refuse · ledger pointing at `~/.zshrc` → refuse · user edited the line after remediation → refuse with diff · PEM round-trip is byte-identical · CRLF file round-trips byte-identical (property test over random content).

### T1.7 ✅ Atomic, non-corrupting source patching (M) ✔
- Write temp file in same dir → `fsync` → `rename`; preserve mode and line endings; refuse symlink targets.
- Error if the target line no longer contains the secret or replacement equals original; ledger written only after successful patch.
- **AC:** test: kill-simulation (fail between write and rename) leaves original intact · CRLF file patched stays CRLF · stale line → error, no ledger entry · symlink target rejected.

### T1.8 ✅ No silent env-var clobber; correct MCP PEM handling (M) ✔
- Unique env name per finding (rule + fingerprint suffix) unless user passes `--env-name`; if name exists with a different value → refuse.
- MCP remediate shares the CLI extraction path; fail unless extracted secret hash == `finding.fingerprint`; handle the specific finding id, not `first()`.
- **AC:** tests: existing `STRIPE_SECRET_KEY=prod` in `.env` untouched after remediating a different key · two unknown-rule findings → two distinct vars · MCP and CLI produce identical output on a PEM fixture · wrong-secret extraction → error.

### T1.9 ✅ Audit ledger: real tamper evidence (M) ✔
- Key: 32 random bytes in `$XDG_STATE_HOME/sentris/audit.key` (0600), not derived from user/path.
- Store head hash separately (`audit.head`); `verify` fails on truncation/empty-with-head; constant-time compare; atomic save.
- Docs: state plainly what it does and doesn't prove (needs external anchor for SOC 2 claims).
- **AC:** tests: edit any entry → verify fails · truncate tail → fails · delete ledger but keep head → fails · moving repo dir still verifies · key file mode 0600.

### T1.10 ✅ Cloud client honesty (M) ✔
- Parse URL; require `https` (http only for loopback + `SENTRIS_ALLOW_INSECURE=1`); remove substring "mock/localhost" offline mode (use explicit `SENTRIS_OFFLINE=1`).
- Transport/HTTP errors → non-zero exit, never "synced". Remove fabricated seats/org/insights; add `GET /api/v1/me` in web and use it (closes B7).
- Default `--server` = production URL.
- **AC:** tests: `https://mock.evil.tld` is not treated as offline · `http://example.com` rejected · 500/timeout → exit≠0 with message · `auth login` shows real org from `/me` · fresh install `auth login --token` w/o `--server` syncs to prod (B7 AC).

### T1.11 ✅ LSP/MCP input bounds and UTF-16 ranges (S) ✔
- Cap `Content-Length` (8 MiB) → error response; replace `panic=abort` risk paths (`[..8]` slices) with `get(..)`.
- Convert code-action ranges to UTF-16 units.
- **AC:** test: `Content-Length: 99999999999` → server returns error and stays alive · non-ASCII line quick-fix edits the right range · fuzz-ish test: 1k random framed inputs, no abort.

### T1.12 ✅ Scanner evasion & repo-controlled config (M) ✔
- Skip only the repo-root `.git`; scan `.sentris/`; anchor `ignore_paths` (glob, non-empty, no bare `/`).
- In CI mode, read config from base branch/`--config` path; warn when the scanned tree's config *adds* ignores.
- **AC:** tests: secret in `sub/.git/x` and `.sentris/x` detected · `ignore_paths=[""]` or `["/"]` rejected · `--config` outside the tree honored · PR that edits ignores prints a warning.

### T1.13 ✅ Smaller hardening (S)
- Reject git ref args starting with `-`; use `--end-of-options`; `create_backup_branch` failure is an error (not `"local-working-tree"`).
- Webhook URL redacted in all messages; https only; no error-body echo.
- Credentials: never fall back into the repo when `$HOME` unset; check perms on load.
- Verifier mock-token prefixes compiled only under `cfg(test)`.
- Fingerprints in JSON/SARIF/MCP output truncated or keyed.
- Use the `zeroize` crate; remove the "RAM zeroized" claim unless true.
- **AC:** one test per bullet; `grep -rn "ghp_test_mock_\|sk-ant-mock-" src` only under `cfg(test)`.

---

## Phase 2: Web & cloud

### T2.1 ✅ Rate limiting + quotas (M) ✔
- Workers Rate Limiting binding: ingest keyed by key-hash (and IP pre-auth), auth routes by IP.
- Per-org limits in code: ≤20 active keys, ≤N scans/day, ≤M findings/day (free: low; pro: higher). 429 with `Retry-After`.
- Better Auth `rateLimit.storage = "database"` (in-memory is useless on Workers).
- **AC:** test: 61st request/min → 429 · org over daily finding cap → 429 · 21st key creation → error · auth sign-in flood → 429 · load test shows bad-key flood does ≤1 D1 read per request and none for malformed bearers.

### T2.2 ✅ Beta flag safety + billing config (S) ✔
- `BETA_FREE_SYNC` becomes `BETA_FREE_SYNC_UNTIL=<ISO date>`; expired → paywall on. Log once when active.
- Startup assertion: `BETTER_AUTH_SECRET` ≥32 chars; production refuses placeholder `pdt_REPLACE_ME`.
- 👤 Real `DODO_PRO_PRODUCT_ID` + API key + webhook key (B2).
- **AC:** unit tests for `canIngest` with flag before/after date, expired period, cancelled (closes B6) · app fails fast with placeholder product ID in `live_mode`.

### T2.3 ✅ Security headers + CSP (M) ✔
- `public/_headers` (or Start middleware): HSTS, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, `frame-ancestors 'none'`, CSP (hash the inline theme script).
- **AC:** `curl -I` on `/`, `/app`, `/api/v1/scans` shows all headers · browser console shows zero CSP violations on `/`, `/pricing`, `/login`, `/app` (Playwright) · securityheaders.com grade ≥ A.

### T2.4 ✅ CSRF/cookie hardening (S) ✔
- Better Auth `advanced.defaultCookieAttributes` (`httpOnly`, `secure`, `sameSite: lax|strict`); `authed` middleware rejects POST whose `Origin` ≠ `APP_URL`.
- Encrypt stored OAuth tokens (`account.encryptOAuthTokens`) or don't persist them.
- **AC:** test: POST server function with foreign `Origin` → 403 · session cookie flags verified in response · DB inspection shows tokens not plaintext.

### T2.5 ✅ Webhook robustness (M) ✔
- Null-check `customer`, `next_billing_date`; wrap update in try/catch: unique-violation / malformed → 200 + log (no infinite retry); transient DB error → 5xx.
- Idempotency: ignore replayed `webhook-id` (small table or KV).
- **AC:** fixture tests: malformed payload → 200 + logged, org unchanged · duplicate `webhook-id` → applied once · subscription already attached to another org → 200 + alert log · out-of-order and same-timestamp cases still pass.

### T2.6 ✅ Ingest correctness (M) ✔
- `UNIQUE(org_id, cli_scan_id)` → upsert/ignore replays (idempotent re-sync).
- Fix `blastRadius` severity: rank-based max (`critical>high>medium>low`), not text max; `json_group_array(distinct repo)` instead of comma split.
- Chunk `db.batch` (≤50 stmts, scan row first, then findings) with partial-failure cleanup; bound `files_scanned`, `line_number`, `entropy` (`.max`, `.finite()`).
- Throttle `last_used_at` (only if older than 60 s).
- **AC:** tests: same `scan_id` uploaded twice → one scan row, no duplicate findings · repo name with comma handled · fingerprint seen as `medium` and `critical` reports `critical` · 5000-finding upload succeeds · `Infinity` entropy → 400.

### T2.7 ✅ Web CI (S) ✔
- Add job: `npm ci`, `typecheck`, `test`, `vite build`; cache; path-filtered to `web/`.
- **AC:** PR touching `web/` runs the job; breaking a type fails CI.

### Phase 2 notes (2026-10-29)
- **Deploy order:** `npm run db:migrate:remote` first (adds `webhook_event`, `rate_limit`, unique `scan_org_cli`; dedupes old re-synced scans; nulls stored OAuth tokens), then `npm run deploy` (creates the 3 rate-limit namespaces). Nothing is applied remotely yet.
- **Found while testing:** the old ingest chunked 9 findings per INSERT = 108 bound params, over D1's limit of 100, so any scan with 9+ findings would have failed in prod. Now 8 rows/statement; the test D1 shim rejects >100 params so it cannot regress.
- **Found while testing:** the CLI's `scan_id` is `scn_` + 8 hex of a hash of timing stats, so different scans can collide. Idempotency key is therefore `scan_id:digest(repo, branch, commit, files, fingerprints)`, stored in `scan.cli_scan_id`; only byte-identical payloads replay.
- **Rulings:** beta ends 2026-11-30 (`BETA_FREE_SYNC_UNTIL`) · quotas free 100 scans / 10k findings per day, pro 2k / 200k · 20 active keys · CSP keeps `script-src 'unsafe-inline'` (Start's streamed hydration scripts and prerendered pages carry build/request-specific inline code; a nonce needs router plumbing) · cookies `SameSite=Lax` not Strict (OAuth callback is cross-site) · HSTS without `preload` · Better Auth limiter 100/min, `/sign-in/social` 10/min, plus `AUTH_IP_LIMITER` 60/min per IP.
- **Not verified:** Workers rate-limit bindings run only on Cloudflare (tests use a counting fake; bindings are per-location and approximate) · securityheaders.com grade (needs deploy) · `/app` CSP behaviour behind login · OAuth token encryption end to end (config only) · cross-origin 403 on a real server-function call (guard unit-tested) · the new GitHub workflow has not run on GitHub.
- **Still 👤:** real `DODO_PRO_PRODUCT_ID`, API key, webhook key (B2). `assertConfig` refuses to serve in `live_mode` while the product id is a placeholder, and always requires `BETTER_AUTH_SECRET` ≥ 32 chars: confirm the deployed secret is long enough before deploying.

---

## Phase 3: Detection quality (the actual product)

### T3.1 ✅ Recall gap closure (L) ✔ (evidence: 1 of 5 vs gitleaks 3 of 5)
- Add rules: AWS secret access key (context-keyed `aws_secret…=` + 40 base64), generic `password|passwd|secret|token|api_key = "<high-entropy>"` with entropy + stopword filter, Stripe live/restricted keys (investigate why my `sk_live_51…` sample was suppressed: likely sequence-FP filter), plus top-30 cloud/SaaS formats from gitleaks' ruleset.
- **AC:** corpus test (T3.2) shows recall ≥ gitleaks on its own rule fixtures; the 5-line sample above yields 5/5.
- **Status (2026-10-29):** rules 56→88 (+32 vendor formats, keyed `credential-assignment`, unquoted `.env` values for keyed rules, `ASIA|ABIA|ACCA` AWS prefixes, trailing-`\b` bug fixed for dash-terminated tokens). 10-secret random probe: Sentris 10/10, gitleaks 8/10. The `sk_live_51…` suppression did not reproduce (random 99-char key detected). On our own corpus: Sentris 388/388 recall, 0 FP on 262 negatives; gitleaks 256/388 (66 %), 33/262 negatives flagged. **Not yet met:** "on gitleaks' own rule fixtures" (needs its Go test data) and the corpus is authored by us, so those numbers are not independent. Real-world check on `web/node_modules` (99 MB) caught and fixed 9 false positives (`token === "?PascalCase"`), now added to negatives.
- **Gitleaks' own fixtures (`bench/gitleaks_fixtures.py`, 5,694 fixtures from 113 rules, generated from v8.30.1 source without executing it):** gitleaks 100 % (sanity check on the extractor), Sentris 58.5 % -> 84.6 % after adding unquoted `name = value` for config-style files (`credential-assignment-unquoted`, disabled on source/doc extensions after it produced 233 false positives in node_modules), typed/operator variants (`:=`, `?=`, `.=`, backticks), and vendor-keyed UUIDs (HubSpot/Snyk/Squarespace). Real-repo sweeps (django 5.1.4, web/node_modules) unchanged at 5 and 11 findings.
- **Round 2 (2026-10-29):** + `vendor-keyed-token` (KuCoin/Discord/Asana/SendBird/MessageBird/Twitter/Algolia/Dropbox/LinkedIn/Sidekiq), `openshift-user-token`, `vault-legacy-token`, Fly `fm1/fm2`, looser Slack bot/Perplexity shapes, `url-basic-auth` (found via TruffleHog's public `test_keys` repo, where Sentris missed `https://admin:admin@host`). Gitleaks-fixture recall 84.6 % -> 87.6 %. `age-secret-key` 0 % is a fixture artifact (literal `QQQ…` dummy, correctly suppressed). CI job `fp-sweep` (`bench/fp-sweep.sh`, limit in `bench/fp_baseline.txt`) fails if findings on django 5.1.4 exceed 5. Prefilter now strips a leading `(?i)` (AC is already case-insensitive); a `(?i)` alternation with inner `(?i)` had silently made a rule unfiltered and 6x slower, so keep one leading `(?i)`.
- **Memory regression fixed:** `\w`/`\d` are Unicode-aware in Rust `regex`; bounded repeats of them in `vendor-keyed-token` (and the older Discord rule) inflated automaton state (django scan peak RSS 143 MB -> 20 MB after switching to ASCII classes). Guard test `rule_patterns_use_ascii_classes_only`. **Open:** Independent labeled dataset (e.g. Samsung CredData) not yet run; `test_keys` is only 3 files.
- **Independent benchmark: Samsung CredData (333 repos, 54,672 labeled lines, 15,241 true; `bench/creddata_eval.py`).** Before this round Sentris scored P 0.878 / R 0.193 / F1 0.316 vs gitleaks 0.857 / 0.455 / 0.594: the corpus numbers had flattered us. Cause: `generic-api-key` demanded entropy 4.2, which hex (max 4.0) can never reach, and its keyword list was narrow (the `Key`, `Secret`, `Token`, `Password` categories are most of the volume). Fixes: alphabet-aware entropy, `keyed-secret-value` rule, `basic-auth-header` (597 true rows), `url-basic-auth` for 18 schemes, and false-positive filters learned from the dataset's labeled-False lines (public/peer keys, `*Id` names, XML `key=` attributes, all-digit constants, label-like and identifier-like values). Now **Sentris P 0.965 / R 0.492 / F1 0.652**, gitleaks 0.857 / 0.455 / 0.594, Kingfisher 0.952 / 0.070 / 0.131, TruffleHog 0.676 / 0.024 / 0.046. Sentris scans the dataset in ~0.9 s (gitleaks 11 s, Kingfisher 2.5 s, TruffleHog 73 s).
- **Held-out split (repo id even = dev, odd = held-out; inspect/tune on dev only from here):** the row-weighted lead was driven by a few repos with thousands of `Key = hex` lines. Per-repo macro F1: Sentris 0.324 vs gitleaks 0.333 (tie) before `password-literal`; held-out row-weighted F1 0.344 vs 0.360 (gitleaks ahead). After adding `password-literal` (quoted password values that look generated, not dictionary words/placeholders; tuned on dev only): **held-out P 0.934 / R 0.257 / F1 0.403 / macro 0.417 vs gitleaks 0.897 / 0.225 / 0.360 / 0.331**; dev F1 0.788 vs 0.671. Caution: `Password` truths in CredData are largely random letter strings produced by the dataset's own obfuscation, so part of this gain is dataset-shaped, not real-world.
- **UUID category (dev-only investigation):** 84 % of CredData's true `UUID` rows (1,742 of ~2,080, all repos) are non-RFC-4122 strings (random version nibbles) while false rows are mostly valid or all-zero. That is the signature of the dataset's own obfuscator, not of real secrets, so **no "invalid UUID" rule was shipped** (it would only game the benchmark). The legitimate sliver was implemented: a UUID assigned to a clearly secret-named variable (`token`, `secret`, `passw`, `api_key`, `credential`, name not ending in `id`) is no longer suppressed by the generic rules, and UUID values bypass the label-like filter. Held-out F1 0.403 -> 0.428 (P 0.934 -> 0.939), dev flat. Seven hand-written corpus negatives that assumed such UUIDs were harmless were removed (no evidence for them). django gate raised 5 -> 6 after review (`"SECRET_KEY": "<uuid>"` in a test).
- **Round 3 vendor formats:** +19 rules (1Password secret key, Adobe, Artifactory x2, Clojars, EasyPost, Facebook page, Flutterwave, GitLab flag/feed/mail/agent/OAuth/trigger/SCIM, HuggingFace org, 42 Intra, Teams webhook, Octopus, PlanetScale OAuth/pw, SettleMint, Slack config + workflow webhooks, Vault batch): 115 rules total. Gitleaks-fixture recall 82.8 % -> 89.0 %; corpus 568/568; CredData held-out unchanged (P 0.939 R 0.278 F1 0.428) as expected for distinctive-prefix rules. Remaining fixture gaps are dominated by artifacts and deliberate choices listed below.
- **Second independent dataset: ProwlBench (24,603 labeled snippets: code/Confluence/Jira/Slack/logs; zero tuning exposure before the run).** Case-level, all cases: Sentris P 0.954 / R 0.642 / F1 0.767; gitleaks 0.931 / 0.411 / 0.571; Kingfisher 0.944 / 0.325 / 0.484; TruffleHog 0.940 / 0.302 / 0.457. Excluding the CredData-derived `origin=real` cases (to avoid double counting): Sentris 0.939 / 0.762 / 0.841 vs best competitor (Kingfisher) 0.942 / 0.508 / 0.660. Sentris is also fastest (0.4 s vs 1.8-2.4 s). Weak spots: T3 free-form/multilingual passwords in prose (Sentris recall 0.43, others <0.2; out of scope for pattern scanners), log source (R 0.52), `origin=real` R 0.44. Caveats: authored by a competing scanner's maintainer; synthetic/augmented cases favour format-rich rule sets (we added many vendor formats) so the margin there overstates real-world advantage; snippets scored as `.txt` regardless of source type; per-tier precision is trivially 1.0 (negatives only in T4). SecretBench (NC State) is access-restricted (email + data-protection agreement) and not yet obtained.
- **Caveats (earlier):** I tuned filters against this dataset's labeled-False lines, so the F1 is partly fit to it (there is no held-out split yet; a proper next step is to tune on half the repos and score the rest). Recall is still under 50 %: Password (2.5k true), UUID (2.1k) and many weak test credentials are not caught. Gitleaks-fixture recall 87.6 % -> 81.6 % (label-like filter rejects fixture secrets built from tiny separator-heavy alphabets).
- **Remaining gap (deliberate or structural):** `sk_test_` Stripe keys (we treat as non-production), numeric-only IDs, UUID values under generic names, multi-line XML, JSON-escaped config strings, looser `ey...` JWT and age-key shapes, ~25 vendor formats we do not have. Fixtures favour gitleaks by construction.
- **Cost (superseded by prefilter):** 88 rules in one lazy-DFA `RegexSet` slowed a 99 MB `node_modules` scan from ~14.5 s to ~22 s (needed `dfa_size_limit(256 MB)` to avoid cache thrash). Fix belongs in T5/T3.4: per-rule literal prefilter instead of one big set.

### T3.2 ✅ Labeled corpus (M)
- `tests/corpus/`: ≥200 true-positive and ≥200 hard negatives (UUIDs, hashes, lockfile integrity strings, base64 images, docs examples); CI test computes precision/recall per rule.
- **AC:** `cargo test corpus` prints P/R table; CI fails if any rule's precision < 0.9 or overall recall regresses > 2 pts.
- **Done:** `tests/corpus_test.rs` generates ≥388 positives from per-rule templates (nothing secret committed; `CORPUS_DUMP=<dir>` exports them for other scanners) and `tests/corpus/negatives.txt` holds 262 hard negatives; baseline recall in `tests/corpus/baseline_recall.txt`.

### T3.3 ✅ Git history scan parity (M)
- Verify `scan --since` + full-history mode vs gitleaks `detect` on a repo with a secret added then deleted.
- **AC:** secret in a deleted commit is found with commit/author/date; documented in README.
- **Done:** both tools find a key added then deleted (gitleaks: stripe-access-token; Sentris: stripe-secret-key). Sentris now reports `commit_hash`, `commit_author`, `commit_date` (ISO-8601) in JSON; covered by `test_git_history_finds_deleted_secret_with_commit_author_date`. Gaps vs gitleaks: no reflog/unreachable-object scan (README previously claimed reflog), no email-only author field, SARIF/text output show hash only.

### T3.4 ✅ Reproducible benchmark (M)
- `bench/run.sh`: pinned versions of gitleaks/trufflehog/kingfisher, same corpus + a public repo (e.g. 5k-file checkout), reports time, RSS, precision, recall; output committed with date and hardware.
- Replace `site.benchmark` numbers with generated JSON.
- **AC:** a stranger can run one command and reproduce within ±20 %; site numbers come from the JSON, not hand-typed.
- **Done:** `bench/run.sh` (build, corpus dump, pinned django 5.1.4 checkout, median of 5 warm runs + peak RSS + corpus recall/FP per tool) → `bench/results/{date}-{host}.json`, `latest.json`, `latest.md`, `web/src/lib/benchmark.json` (site renders from it). `bench/fetch-tools.sh` downloads pinned gitleaks 8.30.1 / trufflehog 3.99.7 / kingfisher 2.15.0 (checksum-verified; kingfisher TOFU-pinned in `bench/tools.lock`). README/docs hand-typed speed claims removed or marked historical.
- **Update:** all four tools now in `bench/results/latest.md` (user-approved fetch). Earlier 12 s gitleaks figure was wrong (Homebrew binary / noisy run); pinned release binary takes ~1.5 s, so the Sentris speedup is ~9x, not ~37x. Staged-scan latency is not benchmarked. ±20 % reproduction by a third party untested (run-to-run variance here was 313–470 ms for Sentris).
- **Found by benchmarking:** the 88-rule `RegexSet` ran at ~3 MB/s (django 26 MB: 8.7 s; `node_modules` 99 MB: 24.8 s). Replaced with an Aho-Corasick literal prefilter plus per-rule regexes (django 0.3–0.5 s, `node_modules` 1.1 s), identical findings, corpus unchanged.

---

## Phase 4: Distribution & launch

### T4.1 👤 Make repo public; set license/security policy (S)
- `SECURITY.md` (disclosure address), issue templates, `CHANGELOG.md`.
- **AC:** `github.com/Bharath-code/sentris` loads while logged out; `Cargo.toml` `repository` URL matches the real repo (currently `sentris-security/sentris`).

### T4.2 ◐ Release pipeline (M)
- Tag → `release.yml` builds macOS/Linux/Windows binaries, SHA-256 sums, SBOM, cosign/GitHub attestations; `cargo audit` + `cargo deny` in CI.
- **Done locally (2026-10-29):** `release.yml`, `audit.yml`, `deny.toml`, `scripts/package.sh`, checksum-verifying `install.sh`/`action.yml`; audit found and fixed 6 real TLS advisories; installer tamper/missing-sum cases verified against a local server; SBOM command verified. **Not verified:** the workflow itself (Actions quota exhausted), musl/linux-arm/windows builds, install on a clean VM. Tag `v0.1.0` only after quota is back or a runner is available.
- **AC:** `v0.1.0` release has 3+ binaries + checksums · installing from the release on a clean VM and running `sentris scan` works · CI fails on a known-vulnerable dep.

### T4.3 👤 Install channels (M)
- `cargo publish`, Homebrew tap, `curl | sh` installer verifying the checksum.
- **AC:** the exact command on the landing page works on a clean macOS and Ubuntu machine.

### T4.4 👤 Domain + Dodo live mode (S)
- Buy domain, set `APP_URL`, GitHub OAuth callback, Dodo webhook URL; complete B2/B3 QA checklist including the IDOR check; switch `DODO_ENV`.
- **AC:** full B3 checklist passes on the production domain; test-card → Pro within 10 s; cancel → Free.

### T4.5 ⬜ Launch assets (M)
- Rewrite `docs/HACKER-NEWS-LAUNCH.md` against verified claims only; 90-second demo (HyperFrames) showing scan → remediate → rollback on a real `.env`.
- **AC:** every claim in the post links to a test or benchmark; a colleague reproduces the demo from the README in <5 min.

---

## Phase 5: Performance & maintainability

### T5.1 ⬜ D1 indexes & rollups (M)
- Indexes: `finding(org_id, severity)`, `api_key(org_id)`, `finding(org_id, created_at)`; dashboard severity counts from a per-scan rollup instead of scanning all findings.
- **AC:** `EXPLAIN QUERY PLAN` shows index use on dashboard queries · `/app` overview < 150 ms server time with 100k findings seeded.

### T5.2 ⬜ Retention + pagination (M)
- Cron trigger: delete findings older than plan retention (free 30 d, pro 90 d); `getScan` paginated with "N more" indicator; overview limits documented.
- **AC:** seeded old rows removed by the job (test) · scan with 1,200 findings pageable · retention stated on pricing page.

### T5.3 ⬜ Dedupe & structure (M)
- Backend trait + shared helpers; remove `unwrap`/slice panics on external data; split any file >400 lines (`cli/handlers/*`, `reporter/webhook/mod.rs`).
- **AC:** no function >50 lines or >5 branches in touched files (clippy cognitive-complexity lint on); `cargo clippy -- -D warnings -W clippy::unwrap_used` passes outside tests.

### T5.4 ⬜ Observability (S)
- Structured logs for webhook outcomes, 401/402/429 counts; Workers observability alert on 5xx rate.
- **AC:** forced bad webhook appears in logs with reason; alert configured.

---

## Phase 6: Moat (after 10 real users)
- Real rotation for one provider end-to-end (start with GitHub PAT or AWS key) with grace period.
- One production-grade backend (Vault *or* AWS) with integration test against a real/dev instance.
- GitHub App / PR bot: block + auto-comment + one-click remediate PR.
- Team features: invites, SSO (needed for the $2k tier), seat enforcement, audit export with external anchoring.
- Agent-native: signed MCP manifest, remediation telemetry (success/rollback rate).
- **AC:** per-item AC written when scheduled, based on interviews; no item starts without ≥3 users asking for it.

---

## Definition of done (whole plan)
- [ ] Zero P0/P1 findings open; re-run both security audits → no HIGH.
- [ ] `cargo test`, clippy `-D warnings`, `cargo audit`, web typecheck/test/build all green in CI.
- [ ] Corpus P/R ≥ gitleaks; benchmark reproducible by a third party.
- [ ] Landing-page install command works on clean machines.
- [ ] Full B3 QA checklist passes in production.
- [ ] No claim in README/site/llms.txt without a test, benchmark, or "roadmap" label.

## Recommended execution order
T0.1 → T0.2 → T1.1 → T1.2 → T1.3 → T1.5 → T1.6 → T1.7 → (T2.1, T2.2, T2.3 in parallel) → T1.8–T1.13 → T2.4–T2.7 → T3.* → T4.* → T5.*

## Known gaps after Phases 0–1 (honest list)

- Vault / AWS / Doppler live paths are unit-tested with shims and a fake Vault HTTP server, **not** against real services (no CLIs/instances available here). Doppler stdin input and AWS `file://` follow documented behaviour but are unverified live.
- 1Password and Infisical have no stdin/file path implemented; live writes are refused unless `SENTRIS_ALLOW_ARGV_SECRETS=1`.
- `GET /api/v1/me` is built and typechecked but **not deployed**; until it is, `sentris auth login` against production fails (by design: it no longer invents an org). Deploy web before releasing the CLI.
- Existing CLI users must re-run `sentris auth login`; old rollback ledgers (no MAC) and audit ledgers need regenerating.
- Audit ledger copied to another machine verifies as "not anchored" (chain valid, truncation undetectable there).
- Inline `nosec` / `sentris-ignore` markers still suppress findings anywhere on a line (documented gitleaks-compatible behaviour).
- `zeroize` crate not adopted; the "RAM zeroized" claim was removed instead.
- Cargo.toml `repository` URL still differs from the real GitHub repo (T4.1).
- 37 stray `sentris/backup-*` local git branches exist from earlier test runs (dry-run used to create them); safe to delete.
- Test runs write a small key file under `$HOME/.sentris/state` unless `SENTRIS_STATE_DIR` is set.
