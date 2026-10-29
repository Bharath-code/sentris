import { z } from 'zod'
import { and, eq, ne } from 'drizzle-orm'
import * as schema from './schema.ts'
import type { Db } from './ingest-core.ts'
import { shouldApply } from './guards.ts'

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
  if (!shouldApply(org, s.subscription_id, ending, at)) return ok('stale')

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
      plan: ending ? 'free' : 'pro',
      seats: ending ? 1 : s.quantity,
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
