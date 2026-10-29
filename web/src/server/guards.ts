// Pure request/billing guards, kept free of Worker imports so node --test can load them

// Content-Length can be absent (chunked) or lie, so count bytes as they stream in
export async function readCapped(request: Request, max: number): Promise<string | null> {
  if (Number(request.headers.get('content-length') ?? 0) > max) return null
  const reader = request.body?.getReader()
  if (!reader) return ''
  const parts: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > max) {
      await reader.cancel()
      return null
    }
    parts.push(value)
  }
  const buf = new Uint8Array(size)
  let o = 0
  for (const p of parts) buf.set(p, (o += p.byteLength) - p.byteLength)
  return new TextDecoder().decode(buf)
}

type BillingState = { dodoSubscriptionId: string | null; billingEventAt: Date | null }

// Drop events older than the last one applied, and never let a different
// (e.g. previously cancelled) subscription's end event downgrade the current one.
export function shouldApply(org: BillingState, subscriptionId: string, ending: boolean, at: Date): boolean {
  const prev = org.billingEventAt?.getTime()
  // Ties fail closed: an end event wins over an activation stamped the same instant
  if (prev !== undefined && (at.getTime() < prev || (at.getTime() === prev && !ending))) return false
  if (ending && org.dodoSubscriptionId && org.dodoSubscriptionId !== subscriptionId) return false
  return true
}

type PlanState = { plan: 'free' | 'pro'; subscriptionStatus: string | null; currentPeriodEnd: Date | null }

// The beta window is a date, not a switch: forgetting to turn it off cannot leave sync free forever
export function betaActive(until: string | undefined, now = Date.now()): boolean {
  const t = until ? Date.parse(until) : NaN
  return Number.isFinite(t) && now < t
}

// Deny by default: only paid/trialing Pro orgs inside their billing period may sync
export function canIngest(org: PlanState, betaUntil: string | undefined, now = Date.now()): boolean {
  if (betaActive(betaUntil, now)) return true
  const paid = org.plan === 'pro' && org.subscriptionStatus === 'active'
  return paid && (!org.currentPeriodEnd || org.currentPeriodEnd.getTime() > now)
}

type Config = { secret?: string; dodoEnv?: string; productId?: string; appUrl?: string }

export function configProblems(c: Config): string[] {
  const out: string[] = []
  if ((c.secret ?? '').length < 32) out.push('BETTER_AUTH_SECRET must be at least 32 characters')
  if (!c.appUrl || !URL.canParse(c.appUrl)) out.push('APP_URL must be an absolute URL')
  if (c.dodoEnv === 'live_mode' && (!c.productId || /REPLACE_ME/i.test(c.productId))) out.push('DODO_PRO_PRODUCT_ID is still a placeholder in live_mode')
  return out
}

const RANK = { low: 1, medium: 2, high: 3, critical: 4 } as const
const NAMES = ['unknown', 'low', 'medium', 'high', 'critical'] as const
export const severityRank = (s: string) => RANK[s.toLowerCase() as keyof typeof RANK] ?? 0
export const severityName = (rank: number) => NAMES[rank] ?? 'unknown'

// Daily caps per org; free also covers the beta window
export const QUOTAS = {
  free: { scans: 100, findings: 10_000 },
  pro: { scans: 2_000, findings: 200_000 },
} as const
export const MAX_ACTIVE_KEYS = 20
const DAY = 864e5

type Usage = { scans: number; findings: number; oldest: number | null }

// Returns seconds to wait, or null when the upload fits
export function quotaRetryAfter(plan: 'free' | 'pro', used: Usage, incomingFindings: number, now = Date.now()): number | null {
  const q = QUOTAS[plan]
  if (used.scans + 1 <= q.scans && used.findings + incomingFindings <= q.findings) return null
  return Math.max(1, Math.ceil(((used.oldest ?? now) + DAY - now) / 1000))
}

// Cookie-authenticated mutations must come from our own origin; Sec-Fetch-Site covers clients that omit Origin
export function sameOrigin(request: Request, appUrl: string): boolean {
  if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') return true
  const origin = request.headers.get('origin')
  if (origin) return origin === new URL(appUrl).origin
  return request.headers.get('sec-fetch-site') === 'same-origin'
}
