import { env } from 'cloudflare:workers'
import DodoPayments from 'dodopayments'
import { eq } from 'drizzle-orm'
import { db, schema } from './db'
import type { Org } from './org'

// Lazy: secrets don't exist at build/prerender time
const dodo = () =>
  new DodoPayments({
    bearerToken: env.DODO_PAYMENTS_API_KEY,
    webhookKey: env.DODO_PAYMENTS_WEBHOOK_KEY,
    environment: env.DODO_ENV === 'live_mode' ? 'live_mode' : 'test_mode',
  })

export async function createCheckout(org: Org, user: { email: string; name: string }, seats: number) {
  const s = await dodo().checkoutSessions.create({
    product_cart: [{ product_id: env.DODO_PRO_PRODUCT_ID, quantity: seats }],
    customer: org.dodoCustomerId ? { customer_id: org.dodoCustomerId } : { email: user.email, name: user.name },
    metadata: { org_id: org.id },
    return_url: `${env.APP_URL}/app?checkout=done`,
    subscription_data: { trial_period_days: 14 },
  })
  if (!s.checkout_url) throw new Error('Dodo returned no checkout URL')
  return s.checkout_url
}

export async function portalLink(org: Org) {
  if (!org.dodoCustomerId) throw new Error('No billing account yet')
  const { link } = await dodo().customers.customerPortal.create(org.dodoCustomerId)
  return link
}

const ACTIVE = new Set(['subscription.active', 'subscription.renewed', 'subscription.updated', 'subscription.plan_changed'])
const ENDED = new Set(['subscription.cancelled', 'subscription.expired', 'subscription.failed', 'subscription.on_hold'])

export async function handleDodoWebhook(request: Request): Promise<Response> {
  const body = await request.text()
  const headers = Object.fromEntries(request.headers)
  let event: ReturnType<DodoPayments['webhooks']['unwrap']>
  try {
    event = dodo().webhooks.unwrap(body, { headers })
  } catch {
    return new Response('invalid signature', { status: 401 })
  }

  // ponytail: the update below is idempotent, so redeliveries are harmless; add an event log if out-of-order delivery bites
  if (!ACTIVE.has(event.type) && !ENDED.has(event.type)) return new Response('ignored', { status: 200 })
  const sub = event.data as Extract<typeof event, { type: 'subscription.active' }>['data']
  const orgId = typeof sub.metadata?.org_id === 'string' ? sub.metadata.org_id : null
  const where = orgId ? eq(schema.org.id, orgId) : eq(schema.org.dodoSubscriptionId, sub.subscription_id)

  await db
    .update(schema.org)
    .set({
      plan: ACTIVE.has(event.type) ? 'pro' : 'free',
      seats: ACTIVE.has(event.type) ? sub.quantity : 1,
      subscriptionStatus: sub.status,
      dodoCustomerId: sub.customer.customer_id,
      dodoSubscriptionId: sub.subscription_id,
      currentPeriodEnd: new Date(sub.next_billing_date),
    })
    .where(where)

  return new Response('ok', { status: 200 })
}
