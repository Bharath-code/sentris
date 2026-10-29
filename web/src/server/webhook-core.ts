import { z } from 'zod'
import { and, eq, ne } from 'drizzle-orm'
import * as schema from './schema.ts'
import type { Db } from './ingest-core.ts'
import { shouldApply } from './guards.ts'
import { event as logEvent, type Logger } from './log.ts'

export const ACTIVE = new Set(['subscription.active', 'subscription.renewed', 'subscription.updated', 'subscription.plan_changed'])
export const ENDED = new Set(['subscription.cancelled', 'subscription.expired', 'subscription.failed', 'subscription.on_hold'])

const Subscription = z.object({
  subscription_id: z.string().min(1),
  quantity: z.number().int().min(1).max(10_000),
  status: z.string(),
  customer: z.object({ customer_id: z.string().min(1) }),
  next_billing_date: z.string().nullish(),
  metadata: z.record(z.string(), z.unknown()).nullish(),
})

export type WebhookEvent = { id: string | null; type: string; timestamp: string; data: unknown }
type Result = { status: number; body: string }
const ok = (body: string): Result => ({ status: 200, body })

// Malformed or conflicting events get 200 so Dodo stops retrying; only transient failures return 5xx
export async function applyWebhook(db: Db, evt: WebhookEvent, log: Pick<Console, 'error' | 'warn'> = console): Promise<Result> {
  const ending = ENDED.has(evt.type)
  if (!ending && !ACTIVE.has(evt.type)) return ok('ignored')

  if (evt.id && (await db.query.webhookEvent.findFirst({ where: eq(schema.webhookEvent.id, evt.id) }))) return ok('duplicate')

  const sub = Subscription.safeParse(evt.data)
  const at = new Date(evt.timestamp)
  const next = sub.success && sub.data.next_billing_date ? new Date(sub.data.next_billing_date) : null
  if (!sub.success || Number.isNaN(at.getTime()) || (next && Number.isNaN(next.getTime()))) {
    log.error('webhook: malformed payload', { id: evt.id, type: evt.type, issue: sub.success ? 'timestamp/date' : sub.error.issues[0]?.path.join('.') })
    return ok('malformed')
  }
  const s = sub.data

  const orgId = typeof s.metadata?.org_id === 'string' ? s.metadata.org_id : null
  const org = await db.query.org.findFirst({
    where: orgId ? eq(schema.org.id, orgId) : eq(schema.org.dodoSubscriptionId, s.subscription_id),
  })
  if (!org) {
    log.warn('webhook: unknown org', { id: evt.id, subscription: s.subscription_id })
    return ok('unknown org')
  }
  // updated/plan_changed also fire for pending or failed subscriptions, so entitlement follows status, not event type
  const down = ending || s.status !== 'active'
  if (!shouldApply(org, s.subscription_id, down, at)) return ok('stale')

  const taken = await db.query.org.findFirst({
    where: and(eq(schema.org.dodoSubscriptionId, s.subscription_id), ne(schema.org.id, org.id)),
  })
  if (taken) {
    log.error('webhook: ALERT subscription already attached to another org', { id: evt.id, subscription: s.subscription_id, org: org.id, owner: taken.id })
    return ok('conflict')
  }

  const update = db
    .update(schema.org)
    .set({
      billingEventAt: at,
      plan: down ? 'free' : 'pro',
      seats: down ? 1 : s.quantity,
      subscriptionStatus: s.status,
      dodoCustomerId: s.customer.customer_id,
      dodoSubscriptionId: s.subscription_id,
      currentPeriodEnd: next ?? org.currentPeriodEnd,
    })
    .where(eq(schema.org.id, org.id))
  try {
    // Same transaction as the update, so a failed apply is never marked as seen and Dodo's retry still lands
    if (evt.id) await db.batch([update, db.insert(schema.webhookEvent).values({ id: evt.id }).onConflictDoNothing()])
    else await update
  } catch (err) {
    if (/UNIQUE/i.test(String(err))) {
      log.error('webhook: ALERT unique violation applying subscription', { id: evt.id, subscription: s.subscription_id, org: org.id })
      return ok('conflict')
    }
    throw err
  }
  return ok('ok')
}

type Unwrap = (body: string, headers: Record<string, string>) => { type: string; timestamp: string; data: unknown }

// Every delivery ends in exactly one structured log line: outcome for handled ones, reason for rejected ones
export async function handleWebhookRequest(request: Request, deps: { db: Db; unwrap: Unwrap; out?: Logger }): Promise<Response> {
  const out = deps.out ?? console
  const id = request.headers.get('webhook-id')
  const reply = (status: number, outcome: string, extra: Record<string, string> = {}) => {
    logEvent('webhook', status === 200 ? { id, status, outcome, ...extra } : { id, status, reason: outcome, ...extra }, out)
    return new Response(outcome, { status })
  }
  const body = await request.text()
  let evt: ReturnType<Unwrap>
  try {
    evt = deps.unwrap(body, Object.fromEntries(request.headers))
  } catch {
    return reply(401, 'invalid signature')
  }
  try {
    const r = await applyWebhook(deps.db, { id, type: evt.type, timestamp: evt.timestamp, data: evt.data }, out as Pick<Console, 'error' | 'warn'>)
    return reply(r.status, r.body, { type: evt.type })
  } catch (err) {
    out.error(JSON.stringify({ event: 'webhook', id, type: evt.type, status: 503, reason: 'transient failure', error: String(err) }))
    return new Response('retry', { status: 503 })
  }
}
