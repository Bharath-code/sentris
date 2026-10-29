# Sentris Web — Beta Launch Tasks

Status as of 2026-10-29 (deployed). Live: https://sentris-web.kumarbharath63.workers.dev · D1 `sentris` (33fe442a-0da2-42d8-a811-78c7c880dda0). Branch: `feat/web-rebuild` (uncommitted). App lives in `web/`.

Legend: ✅ done & verified · 🟡 built, not verified · ⬜ not started · 👤 needs you (account/secret/decision)

## Full-cycle flow (target)

```
Visitor → landing/pricing → GitHub sign-in → dashboard creates org
→ Start trial → Dodo checkout → webhook → org.plan = pro
→ Create API key → `sentris auth login --token … --server …` → `sentris sync .`
→ POST /api/v1/scans → D1 → dashboard shows scans + blast radius
```

| Step | Local | Production |
|---|---|---|
| Landing + pricing render | ✅ | ✅ |
| GitHub sign-in | 🟡 (no local OAuth app) | ✅ (real account → user, session, org created) |
| Dodo checkout → webhook → Pro | 🟡 (no Dodo keys yet) | ⬜ |
| API key → CLI sync → D1 | ✅ (real CLI, seeded key) | ✅ (real CLI, seeded key, cleaned up) |
| Blast radius across repos | ✅ | ✅ |
| Dashboard UI with real session | 🟡 (never rendered signed-in) | ⬜ |

---

## A. Done

### A1 ✅ App foundation
- TanStack Start + Router, React 19, Vite 8, Tailwind 4, Cloudflare Vite plugin, Drizzle + D1.
- **AC met:** `tsc --noEmit` clean · `vite build` passes · `/` and `/pricing` pre-rendered static, `/app` + `/login` stay dynamic.

### A2 ✅ Design system + marketing site
- Tokens (`src/styles.css`), Geist fonts, light/dark, GSAP hero/benchmark/zones motion, reduced-motion respected.
- **AC met:** no horizontal scroll at 390px · no console errors · every CLI command in copy checked against `src/cli/mod.rs`.

### A3 ✅ D1 schema + migration
- Tables: user, session, account, verification (Better Auth), org, api_key, scan, finding. `web/drizzle/0000_init.sql`.
- **AC met:** applies cleanly to local D1.

### A4 ✅ CLI ingest API `POST /api/v1/scans`
- Bearer key → SHA-256 lookup, revoked keys rejected, zod validation, 2 MB cap, batched inserts, blast-radius response.
- **AC met:** real `target/release/sentris sync` from 2 repos → 2 rows, same `zk_` fingerprint, blast radius reported · bad key → 401 · bad payload → 400 · `last_used_at` updated.

### A5 ✅ Entitlement gate
- `canIngest()` deny-by-default; `BETA_FREE_SYNC="true"` opens beta.
- **AC met:** typecheck. ⚠ Not exercised with flag off — see B6.

### A6 🟡 Auth (Better Auth + GitHub)
- `/api/auth/$`, `/login`, `/app` guard, sign-out.
- **Verified:** `/app` without session → 307 `/login`. **Not verified:** actual GitHub round-trip.

### A7 🟡 Billing (Dodo)
- Checkout session (seats, 14-day trial, `metadata.org_id`), customer portal, signed webhook → plan/seats/status.
- **Verified:** unsigned webhook → 401. **Not verified:** real checkout, real webhook payload.

### A8 🟡 Dashboard
- Onboarding (3 steps), stats, blast radius, scans, scan detail, key create/revoke, upgrade + manage billing.
- **Not verified:** never rendered with a signed-in session.

---

## B. Not done — in order

### B1 ✅ Create GitHub OAuth app (prod done; local app optional)
- github.com/settings/developers → New OAuth App. Two apps: local + prod.
  - Local callback: `http://localhost:3000/api/auth/callback/github`
  - Prod callback: `https://sentris-web.<subdomain>.workers.dev/api/auth/callback/github`
- **AC:** client ID/secret in `web/.dev.vars`; local sign-in lands on `/app` and creates one `org` row.

### B2 👤 Dodo Payments test mode setup
- Create product "Sentris Pro": subscription, $8/month, per-seat quantity. Copy `pdt_…` into `wrangler.jsonc` `DODO_PRO_PRODUCT_ID`.
- Create test API key → `DODO_PAYMENTS_API_KEY`.
- **AC:** "Start trial" opens Dodo test checkout with correct seat count and $ total.

### B3 ⬜ Local full-cycle QA (after B1, B2)
- Use `cloudflared tunnel --url http://localhost:3000` so Dodo can reach the webhook; register `<tunnel>/api/webhooks/dodo`, put signing secret in `DODO_PAYMENTS_WEBHOOK_KEY`.
- **AC:**
  - [ ] Sign in with GitHub → onboarding shown
  - [ ] Test-card checkout → within 10 s org shows `Pro · N seats`
  - [ ] Manage billing opens Dodo portal
  - [ ] Cancel in portal → plan returns to Free
  - [ ] Create key → copy login command → `sentris sync .` → scan appears, detail page loads
  - [ ] Revoke key → next sync gets 401
  - [ ] Second account cannot open first account's `/app/scans/<id>` (IDOR check)

### B4 🟡 Provision Cloudflare production — D1 + migration + BETTER_AUTH_SECRET + APP_URL done; 4 secrets wait on B1/B2
- `npx wrangler d1 create sentris` → put `database_id` in `wrangler.jsonc`.
- `npm run db:migrate:remote`
- Secrets: `wrangler secret put` × `BETTER_AUTH_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `DODO_PAYMENTS_API_KEY`, `DODO_PAYMENTS_WEBHOOK_KEY`.
- Set `APP_URL` var to the workers.dev URL.
- **AC:** `wrangler d1 list` shows `sentris` with 8 tables; `wrangler secret list` shows 5 secrets.

### B5 🟡 Deploy + production smoke test — deployed; routes + CLI sync verified; auth/billing wait on B1/B2
- `npm run deploy`; register prod webhook URL in Dodo (test mode first).
- **AC:** `/` 200 + static · `/app` → `/login` · full B3 checklist passes on workers.dev · Workers observability shows no errors.

### B6 ⬜ Tests worth keeping
- Unit test `canIngest` (flag on/off, expired period, cancelled).
- Unit test webhook mapping (active → pro, cancelled → free) with a fixture payload.
- **AC:** `npm test` covers both; fails if gate logic flips.

### B7 ⬜ CLI ↔ cloud fixes (Rust side)
- `sentris auth login` shows fake seats (14/25), fake org name/email → fetch from a `GET /api/v1/me` endpoint (needs adding).
- Default server `https://api.sentris.dev` → change to workers.dev URL until domain bought.
- CLI treats any URL containing `localhost`/`mock` as offline mock → document or remove.
- ✅ **Zero-knowledge gap fixed:** fingerprints = `zk_` + HMAC-SHA256(team secret, secret hash); 256-bit team secret generated by first `auth login`, teammates join with `--team-secret`, never sent to server; `finding_id` (unsalted hash) removed from upload; credentials file `0600`.
  - **AC met:** captured upload has no raw secret, unsalted hash, or team secret · two machines with shared secret correlate in prod · machine without it does not · bad secret rejected.
- **AC:** fresh install + `auth login --token` with no `--server` syncs to prod.

### B8 👤 Distribution
- Repo `github.com/Bharath-code/sentris` is 404 publicly; crate + brew tap don't exist. Site install command (`src/lib/site.ts`) only works once repo is public.
- `llms.txt` lists nonexistent `--safe-rotate`; README claims 6 backends but CLI help lists env/vault/aws/doppler.
- **AC:** the command on the landing page installs a working binary on a clean machine.

### B9 ⬜ Polish (post-validation)
- Team invites / members (seat enforcement is currently cosmetic).
- Email magic-link sign-in (Cloudflare Email Service).
- Rate limiting on `/api/v1/scans` (Workers rate-limit binding).
- Data retention job (cron) for old findings.
- Outside design references per your CLAUDE.md (refero/21st.dev) — not used yet.
- Domain + Dodo live mode (KYC) once beta users validate.
