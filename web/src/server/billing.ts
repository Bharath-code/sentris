import { env } from 'cloudflare:workers'
import DodoPayments from 'dodopayments'
import { db } from './db'
import type { Org } from './org'
import { assertConfig } from './config'
import { applyWebhook } from './webhook-core.ts'

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
    // One trial per org: anyone who has subscribed before pays from day one
    subscription_data: { trial_period_days: org.dodoSubscriptionId ? 0 : 14 },
  })
  if (!s.checkout_url) throw new Error('Dodo returned no checkout URL')
  return s.checkout_url
}

export async function portalLink(org: Org) {
  if (!org.dodoCustomerId) throw new Error('No billing account yet')
  const { link } = await dodo().customers.customerPortal.create(org.dodoCustomerId)
  return link
}

export async function handleDodoWebhook(request: Request): Promise<Response> {
  assertConfig()
  const body = await request.text()
  const headers = Object.fromEntries(request.headers)
  let event: ReturnType<DodoPayments['webhooks']['unwrap']>
  try {
    event = dodo().webhooks.unwrap(body, { headers })
  } catch {
    return new Response('invalid signature', { status: 401 })
  }

  try {
    const { status, body: out } = await applyWebhook(db, { id: request.headers.get('webhook-id'), type: event.type, timestamp: event.timestamp, data: event.data })
    return new Response(out, { status })
  } catch (err) {
    console.error('webhook: transient failure, asking Dodo to retry', err)
    return new Response('retry', { status: 503 })
  }
}
