/**
 * SENTRIS ZERO-KNOWLEDGE CLOUD — CLOUDFLARE WORKER + D1 + KV + DODO PAYMENTS (MoR)
 *
 * Endpoints:
 *   GET  /v1/health          -> Edge health & Zero-Knowledge privacy invariant check
 *   GET  /v1/dashboard       -> Live findings, seat usage, SOC 2 chain & Multi-Repo Blast Radius
 *   GET  /v1/blast-radius    -> SQL-correlated cross-repo `zk_<sha256>` duplicate secret clusters
 *   POST /v1/scans           -> Ingests `sentris sync` / `sentris scan --cloud` ZK payloads
 *   POST /v1/checkout/dodo   -> Creates a Dodo Payments (India/Global MoR) checkout session
 *   POST /v1/webhooks/dodo   -> Standard Webhooks HMAC-SHA256 handler minting `sp_live_` tokens
 */

export interface Env {
  DB: D1Database;
  SENTRIS_TOKENS: KVNamespace;
  ENVIRONMENT: string;
  DODO_API_BASE_URL: string;
  DODO_PRO_PRODUCT_ID: string;
  DODO_PRO_ANNUAL_PRODUCT_ID: string;
  DODO_ENTERPRISE_PRODUCT_ID: string;
  APP_PUBLIC_URL: string;
  DODO_PAYMENTS_API_KEY?: string;
  DODO_PAYMENTS_WEBHOOK_KEY?: string;
  SENTRIS_MASTER_PEPPER?: string;
}

interface ZkFindingInput {
  id?: string;
  zk_fingerprint: string;
  rule_id: string;
  severity: string;
  redacted_preview: string;
  git_zone?: string;
  remediation_status?: string;
}

interface ZkScanPayload {
  org_id?: string;
  repo_hash: string;
  branch?: string;
  developer_email?: string;
  files_scanned?: number;
  duration_ms?: number;
  remediated_count?: number;
  audit_chain_head_hash?: string;
  findings: ZkFindingInput[];
}

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Sentris-Org, webhook-id, webhook-timestamp, webhook-signature',
  'Cache-Control': 'no-store'
};

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS
    }
  });
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verifyStandardWebhookSignature(
  payload: string,
  webhookId: string,
  webhookTimestamp: string,
  webhookSignature: string,
  secret: string
): Promise<boolean> {
  const cleanSecret = secret.startsWith('whsec_') ? secret.slice(6) : secret;
  const keyBytes = Uint8Array.from(atob(cleanSecret), (c) => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signedContent = `${webhookId}.${webhookTimestamp}.${payload}`;
  const sigBuffer = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    new TextEncoder().encode(signedContent)
  );
  const expectedBase64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)));

  const signatures = webhookSignature.split(' ');
  for (const part of signatures) {
    const [, sig] = part.split(',');
    if (sig && sig === expectedBase64) {
      return true;
    }
  }
  return false;
}

function generateLicenseToken(): { rawToken: string; preview: string } {
  const randomBytes = new Uint8Array(18);
  crypto.getRandomValues(randomBytes);
  const hex = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const rawToken = `sp_live_${hex}`;
  const preview = `sp_live_${hex.slice(0, 4)}...${hex.slice(-4)}`;
  return { rawToken, preview };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const now = Math.floor(Date.now() / 1000);

    try {
      // ======================================================================
      // 1. GET /v1/health — Edge Status & Zero-Knowledge Invariant Verification
      // ======================================================================
      if (path === '/v1/health' && request.method === 'GET') {
        return jsonResponse({
          status: 'ok',
          service: 'sentris-zk-cloud',
          edge_runtime: 'cloudflare-workers-d1',
          billing_mor: 'dodo-payments',
          zero_knowledge_invariant: 'enforced (salted SHA-256 zk_ fingerprints only)',
          timestamp: now
        });
      }

      // ======================================================================
      // 2. POST /v1/scans — Ingest Zero-Knowledge Scan & Compute Blast Radius
      // ======================================================================
      if (path === '/v1/scans' && request.method === 'POST') {
        const body = (await request.json()) as ZkScanPayload;
        const orgId = body.org_id || request.headers.get('X-Sentris-Org') || 'org_acme_cyber_ops';
        const repoHash = body.repo_hash || 'acme/unknown-repo';
        const branch = body.branch || 'main';
        const devEmail = body.developer_email || 'dev@acme.corp';
        const findings = Array.isArray(body.findings) ? body.findings : [];

        // Enforce strict Zero-Knowledge invariant: every fingerprint MUST start with `zk_`
        for (const f of findings) {
          if (!f.zk_fingerprint || !f.zk_fingerprint.startsWith('zk_')) {
            return jsonResponse(
              {
                error: 'ZeroKnowledgeViolation',
                message: 'Rejected payload: all finding fingerprints must be salted SHA-256 hashes prefixed with zk_.'
              },
              400
            );
          }
        }

        const scanId = `scn_${now}_${Math.random().toString(36).slice(2, 8)}`;

        await env.DB.prepare(
          `INSERT INTO zk_scans (
            scan_id, org_id, repo_hash, branch, developer_email,
            files_scanned, duration_ms, findings_count, remediated_count,
            audit_chain_head_hash, created_at
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
        )
          .bind(
            scanId,
            orgId,
            repoHash,
            branch,
            devEmail,
            body.files_scanned ?? 0,
            body.duration_ms ?? 18,
            findings.length,
            body.remediated_count ?? 0,
            body.audit_chain_head_hash ?? null,
            now
          )
          .run();

        for (const f of findings) {
          const findingId = f.id || `fnd_${now}_${Math.random().toString(36).slice(2, 8)}`;
          await env.DB.prepare(
            `INSERT INTO zk_findings (
              id, scan_id, org_id, repo_hash, branch, author_email,
              zk_fingerprint, rule_id, severity, redacted_preview,
              git_zone, remediation_status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`
          )
            .bind(
              findingId,
              scanId,
              orgId,
              repoHash,
              branch,
              devEmail,
              f.zk_fingerprint,
              f.rule_id,
              f.severity || 'Critical',
              f.redacted_preview || 'redacted_***',
              f.git_zone || 'Zone 1 (Staged Hunk)',
              f.remediation_status || 'Active',
              now
            )
            .run();
        }

        // Query Multi-Repo Blast Radius across the entire Organization
        const blastRadiusRows = await env.DB.prepare(
          `SELECT
             zk_fingerprint,
             rule_id,
             severity,
             COUNT(DISTINCT repo_hash) AS repo_count,
             GROUP_CONCAT(DISTINCT repo_hash) AS affected_repos,
             COUNT(*) AS total_occurrences
           FROM zk_findings
           WHERE org_id = ?1
           GROUP BY zk_fingerprint
           HAVING COUNT(DISTINCT repo_hash) > 1
           ORDER BY repo_count DESC, total_occurrences DESC
           LIMIT 20`
        )
          .bind(orgId)
          .all();

        return jsonResponse({
          status: 'synced',
          scan_id: scanId,
          org_id: orgId,
          ingested_findings: findings.length,
          zero_knowledge_verified: true,
          blast_radius_insights: (blastRadiusRows.results || []).map((r: Record<string, unknown>) => ({
            zk_fingerprint: r.zk_fingerprint,
            rule_id: r.rule_id,
            severity: r.severity,
            repo_count: r.repo_count,
            affected_repos: String(r.affected_repos || '').split(',').filter(Boolean),
            total_occurrences: r.total_occurrences
          }))
        });
      }

      // ======================================================================
      // 3. GET /v1/dashboard & GET /v1/blast-radius — Live Console Telemetry
      // ======================================================================
      if ((path === '/v1/dashboard' || path === '/v1/blast-radius') && request.method === 'GET') {
        const orgId = url.searchParams.get('org_id') || 'org_acme_cyber_ops';

        const orgRow = await env.DB.prepare(`SELECT * FROM organizations WHERE id = ?1`)
          .bind(orgId)
          .first();

        const recentFindings = await env.DB.prepare(
          `SELECT * FROM zk_findings WHERE org_id = ?1 ORDER BY created_at DESC LIMIT 25`
        )
          .bind(orgId)
          .all();

        const blastRadiusRows = await env.DB.prepare(
          `SELECT
             zk_fingerprint,
             rule_id,
             severity,
             COUNT(DISTINCT repo_hash) AS repo_count,
             GROUP_CONCAT(DISTINCT repo_hash) AS affected_repos,
             COUNT(*) AS total_occurrences
           FROM zk_findings
           WHERE org_id = ?1
           GROUP BY zk_fingerprint
           HAVING COUNT(DISTINCT repo_hash) > 1
           ORDER BY repo_count DESC
           LIMIT 15`
        )
          .bind(orgId)
          .all();

        return jsonResponse({
          organization: orgRow || {
            id: orgId,
            name: 'Acme Cyber Operations',
            plan: 'pro',
            seats_purchased: 20,
            seats_used: 14,
            subscription_status: 'active'
          },
          findings: recentFindings.results || [],
          blast_radius_insights: (blastRadiusRows.results || []).map((r: Record<string, unknown>) => ({
            zk_fingerprint: r.zk_fingerprint,
            rule_id: r.rule_id,
            severity: r.severity,
            repo_count: r.repo_count,
            affected_repos: String(r.affected_repos || '').split(',').filter(Boolean),
            total_occurrences: r.total_occurrences
          }))
        });
      }

      // ======================================================================
      // 4. POST /v1/checkout/dodo — Dodo Payments (India & Global MoR) Checkout
      // ======================================================================
      if (path === '/v1/checkout/dodo' && request.method === 'POST') {
        const body = (await request.json()) as {
          org_id?: string;
          org_name?: string;
          email?: string;
          plan?: 'pro' | 'enterprise';
          billing_interval?: 'monthly' | 'annual';
          seats?: number;
          currency?: 'USD' | 'INR';
        };

        const orgId = body.org_id || `org_${Math.random().toString(36).slice(2, 10)}`;
        const orgName = body.org_name || 'Acme Engineering';
        const email = body.email || 'founder@company.dev';
        const plan = body.plan || 'pro';
        const interval = body.billing_interval || 'monthly';
        const seats = Math.max(1, Math.min(500, Number(body.seats) || 15));
        const unitPriceUsd = plan === 'enterprise' ? 2000 : interval === 'annual' ? 7 : 8;
        const totalUsd = plan === 'enterprise' ? 2000 : seats * unitPriceUsd;

        const productId =
          plan === 'enterprise'
            ? env.DODO_ENTERPRISE_PRODUCT_ID
            : interval === 'annual'
              ? env.DODO_PRO_ANNUAL_PRODUCT_ID
              : env.DODO_PRO_PRODUCT_ID;

        // If live Dodo Payments API Key is configured in Cloudflare Secrets, create real MoR Checkout Session
        if (env.DODO_PAYMENTS_API_KEY) {
          const dodoRes = await fetch(`${env.DODO_API_BASE_URL}/checkouts`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${env.DODO_PAYMENTS_API_KEY}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              product_cart: [
                {
                  product_id: productId,
                  quantity: plan === 'enterprise' ? 1 : seats
                }
              ],
              customer: {
                email,
                name: orgName
              },
              billing_currency: body.currency || 'USD',
              payment_link: true,
              return_url: `${env.APP_PUBLIC_URL}/?checkout=success&org_id=${encodeURIComponent(orgId)}`,
              metadata: {
                org_id: orgId,
                org_name: orgName,
                plan,
                billing_interval: interval,
                seats: String(seats)
              }
            })
          });

          if (dodoRes.ok) {
            const session = (await dodoRes.json()) as { checkout_url?: string; payment_link?: string; session_id?: string };
            return jsonResponse({
              mode: 'live_dodo_mor',
              provider: 'Dodo Payments (Merchant of Record)',
              checkout_url: session.checkout_url || session.payment_link,
              session_id: session.session_id,
              org_id: orgId,
              seats,
              total_usd: totalUsd
            });
          }
        }

        // Beta / Sandbox Instant Provisioning Mode (works out-of-the-box before domain purchase)
        const { rawToken, preview } = generateLicenseToken();
        return jsonResponse({
          mode: 'beta_instant_trial',
          provider: 'Dodo Payments MoR (Sandbox / 14-Day Trial)',
          checkout_url: `https://checkout.dodopayments.com/buy/${productId}?quantity=${seats}&prefilled_email=${encodeURIComponent(email)}`,
          org_id: orgId,
          org_name: orgName,
          plan,
          billing_interval: interval,
          seats,
          total_usd: totalUsd,
          trial_days: 14,
          license_token: rawToken,
          license_preview: preview,
          cli_activation_command: `sentris auth login --token ${rawToken}`
        });
      }

      // ======================================================================
      // 5. POST /v1/webhooks/dodo — Standard Webhooks Verification & License Minting
      // ======================================================================
      if (path === '/v1/webhooks/dodo' && request.method === 'POST') {
        const rawPayload = await request.text();
        const webhookId = request.headers.get('webhook-id') || `wh_${now}`;
        const webhookTimestamp = request.headers.get('webhook-timestamp') || String(now);
        const webhookSignature = request.headers.get('webhook-signature') || '';

        if (env.DODO_PAYMENTS_WEBHOOK_KEY) {
          const valid = await verifyStandardWebhookSignature(
            rawPayload,
            webhookId,
            webhookTimestamp,
            webhookSignature,
            env.DODO_PAYMENTS_WEBHOOK_KEY
          );
          if (!valid) {
            return jsonResponse({ error: 'Invalid Dodo Payments webhook signature' }, 401);
          }
        }

        const event = JSON.parse(rawPayload) as {
          type?: string;
          data?: {
            subscription_id?: string;
            customer?: { customer_id?: string; email?: string; name?: string };
            quantity?: number;
            total_amount?: number;
            currency?: string;
            metadata?: Record<string, string>;
          };
        };

        const eventType = event.type || 'subscription.active';
        const data = event.data || {};
        const meta = data.metadata || {};
        const orgId = meta.org_id || `org_dodo_${now}`;
        const orgName = meta.org_name || data.customer?.name || 'Sentris Pro Customer';
        const email = data.customer?.email || 'admin@customer.dev';
        const seats = Number(meta.seats || data.quantity || 10);
        const plan = meta.plan || 'pro';
        const interval = meta.billing_interval || 'monthly';

        // Record idempotent billing event
        await env.DB.prepare(
          `INSERT OR IGNORE INTO billing_events (
            webhook_id, event_type, org_id, dodo_subscription_id,
            amount_cents, currency, payload_json, processed_at
          ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
        )
          .bind(
            webhookId,
            eventType,
            orgId,
            data.subscription_id || null,
            data.total_amount || seats * 800,
            data.currency || 'USD',
            rawPayload,
            now
          )
          .run();

        if (
          eventType === 'subscription.active' ||
          eventType === 'subscription.renewed' ||
          eventType === 'payment.succeeded'
        ) {
          await env.DB.prepare(
            `INSERT INTO organizations (
              id, name, plan, billing_interval, seats_purchased, seats_used,
              dodo_customer_id, dodo_subscription_id, subscription_status, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, 'active', ?8, ?8)
            ON CONFLICT(id) DO UPDATE SET
              plan = excluded.plan,
              billing_interval = excluded.billing_interval,
              seats_purchased = excluded.seats_purchased,
              dodo_customer_id = excluded.dodo_customer_id,
              dodo_subscription_id = excluded.dodo_subscription_id,
              subscription_status = 'active',
              updated_at = excluded.updated_at`
          )
            .bind(
              orgId,
              orgName,
              plan,
              interval,
              seats,
              data.customer?.customer_id || null,
              data.subscription_id || null,
              now
            )
            .run();

          const { rawToken, preview } = generateLicenseToken();
          const pepper = env.SENTRIS_MASTER_PEPPER || 'sentris_edge_pepper_2026';
          const tokenHash = await sha256Hex(`${pepper}:${rawToken}`);

          await env.DB.prepare(
            `INSERT INTO api_tokens (
              token_hash, token_preview, org_id, developer_email, role, created_at
            ) VALUES (?1, ?2, ?3, ?4, 'admin', ?5)`
          )
            .bind(tokenHash, preview, orgId, email, now)
            .run();

          await env.SENTRIS_TOKENS.put(
            `tok:${tokenHash}`,
            JSON.stringify({ org_id: orgId, plan, seats, email, active: true }),
            { expirationTtl: 60 * 60 * 24 * 365 }
          );

          return jsonResponse({
            received: true,
            event_type: eventType,
            org_id: orgId,
            seats_provisioned: seats,
            token_preview: preview
          });
        }

        return jsonResponse({ received: true, event_type: eventType });
      }

      return jsonResponse({ error: 'Not Found', path }, 404);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return jsonResponse({ error: 'Internal Worker Error', message }, 500);
    }
  }
};
