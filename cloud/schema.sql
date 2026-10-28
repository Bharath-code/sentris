-- ============================================================================
-- SENTRIS ZERO-KNOWLEDGE CLOUD — CLOUDFLARE D1 (SERVERLESS SQLITE) SCHEMA
-- Strict Privacy Invariant: 0 bytes of raw secrets or source code ever stored.
-- Only salted SHA-256 fingerprints (`zk_<hex>`), rule metadata, and billing state.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. Organizations & Dodo Payments MoR Subscription State
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,                              -- e.g. 'org_acme_cyber_ops'
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'pro',                 -- 'free' | 'pro' | 'enterprise'
  billing_interval TEXT NOT NULL DEFAULT 'monthly', -- 'monthly' ($8/seat) | 'annual' ($7/seat)
  seats_purchased INTEGER NOT NULL DEFAULT 5,
  seats_used INTEGER NOT NULL DEFAULT 1,
  dodo_customer_id TEXT,
  dodo_subscription_id TEXT,
  subscription_status TEXT NOT NULL DEFAULT 'active', -- 'trialing' | 'active' | 'on_hold' | 'cancelled'
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 2. API License Tokens (`sp_live_...` hashed with SHA-256 at rest)
CREATE TABLE IF NOT EXISTS api_tokens (
  token_hash TEXT PRIMARY KEY,
  token_preview TEXT NOT NULL,                      -- e.g. 'sp_live_9f8a...3c1d'
  org_id TEXT NOT NULL,
  developer_email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'developer',           -- 'admin' | 'security_lead' | 'developer'
  last_scan_at INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- 3. Zero-Knowledge Scan Sessions (`sentris sync` / `sentris scan --cloud`)
CREATE TABLE IF NOT EXISTS zk_scans (
  scan_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  repo_hash TEXT NOT NULL,                          -- e.g. 'acme/billing-svc' or salted repo hash
  branch TEXT NOT NULL DEFAULT 'main',
  developer_email TEXT NOT NULL,
  files_scanned INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  findings_count INTEGER NOT NULL DEFAULT 0,
  remediated_count INTEGER NOT NULL DEFAULT 0,
  audit_chain_head_hash TEXT,                       -- RFC 2104 HMAC-SHA256 head from local .sentris/audit.log
  created_at INTEGER NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- 4. Zero-Knowledge Finding Fingerprints (Powers Multi-Repo Blast Radius Correlation)
CREATE TABLE IF NOT EXISTS zk_findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  repo_hash TEXT NOT NULL,
  branch TEXT NOT NULL DEFAULT 'main',
  author_email TEXT NOT NULL,
  zk_fingerprint TEXT NOT NULL,                     -- Salted SHA-256 `zk_<64-hex>`
  rule_id TEXT NOT NULL,                            -- e.g. 'stripe-secret-key', 'postgres-connection-uri'
  severity TEXT NOT NULL,                           -- 'Critical' | 'High' | 'Medium' | 'Low'
  redacted_preview TEXT NOT NULL,                   -- e.g. 'sk_live_...f89a' (never raw secret)
  git_zone TEXT NOT NULL DEFAULT 'Zone 1 (Staged Hunk)',
  remediation_status TEXT NOT NULL DEFAULT 'Active',-- 'Active' | 'Remediated (Dual-Key Safe)'
  created_at INTEGER NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES zk_scans(scan_id) ON DELETE CASCADE,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- High-speed composite index for sub-3ms Multi-Repo Blast Radius Correlation
CREATE INDEX IF NOT EXISTS idx_org_zk_fp ON zk_findings(org_id, zk_fingerprint, repo_hash);
CREATE INDEX IF NOT EXISTS idx_org_created ON zk_findings(org_id, created_at DESC);

-- 5. Dodo Payments Webhook Audit Log (Idempotency & India/Global MoR Compliance)
CREATE TABLE IF NOT EXISTS billing_events (
  webhook_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,                         -- 'subscription.active' | 'payment.succeeded' | etc.
  org_id TEXT,
  dodo_subscription_id TEXT,
  amount_cents INTEGER,
  currency TEXT DEFAULT 'USD',
  payload_json TEXT NOT NULL,
  processed_at INTEGER NOT NULL
);

-- Seed Default Beta Organization for Instant Zero-Config Testing
INSERT OR IGNORE INTO organizations (
  id, name, plan, billing_interval, seats_purchased, seats_used,
  dodo_customer_id, dodo_subscription_id, subscription_status, created_at, updated_at
) VALUES (
  'org_acme_cyber_ops',
  'Acme Cyber Operations',
  'pro',
  'monthly',
  20,
  14,
  'cus_dodo_india_global_01',
  'sub_dodo_pro_8usd_01',
  'active',
  1730000000,
  1730000000
);
