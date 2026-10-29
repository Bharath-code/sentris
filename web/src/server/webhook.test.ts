import { test } from 'node:test'
import assert from 'node:assert/strict'
import { testDb } from './testdb.ts'
import * as schema from './schema.ts'
import { applyWebhook, type WebhookEvent } from './webhook-core.ts'
import { eq } from 'drizzle-orm'

const quiet = { logs: [] as string[], error(...a: unknown[]) { this.logs.push(String(a[0])) }, warn(...a: unknown[]) { this.logs.push(String(a[0])) } }
const sub = (over: object = {}) => ({
  subscription_id: 'sub_1',
  quantity: 3,
  status: 'active',
  customer: { customer_id: 'cus_1' },
  next_billing_date: '2026-12-01T00:00:00Z',
  metadata: { org_id: 'org1' },
  ...over,
})
const evt = (over: Partial<WebhookEvent> = {}): WebhookEvent => ({ id: 'wh_1', type: 'subscription.active', timestamp: '2026-11-01T00:00:10Z', data: sub(), ...over })

async function setup() {
  const { db } = testDb()
  quiet.logs.length = 0
  for (const [u, o] of [['u1', 'org1'], ['u2', 'org2']] as const) {
    await db.insert(schema.user).values({ id: u, name: u, email: `${u}@x.test` })
    await db.insert(schema.org).values({ id: o, name: o, ownerId: u, zkTag: u.padEnd(8, '0') })
  }
  const org = async (id = 'org1') => (await db.query.org.findFirst({ where: eq(schema.org.id, id) }))!
  return { db, org }
}

test('activation upgrades the org and a cancel downgrades it', async () => {
  const { db, org } = await setup()
  assert.equal((await applyWebhook(db, evt(), quiet)).body, 'ok')
  const o = await org()
  assert.deepEqual([o.plan, o.seats, o.dodoSubscriptionId], ['pro', 3, 'sub_1'])
  await applyWebhook(db, evt({ id: 'wh_2', type: 'subscription.cancelled', timestamp: '2026-11-02T00:00:00Z', data: sub({ status: 'cancelled' }) }), quiet)
  assert.deepEqual([(await org()).plan, (await org()).seats], ['free', 1])
})

test('malformed payloads are acknowledged and logged without touching the org', async () => {
  const { db, org } = await setup()
  for (const data of [sub({ customer: null }), sub({ customer: undefined }), sub({ quantity: 'x' }), sub({ next_billing_date: 'not a date' }), null, 'junk']) {
    const r = await applyWebhook(db, evt({ id: null, data }), quiet)
    assert.deepEqual([r.status, r.body], [200, 'malformed'])
  }
  assert.equal((await applyWebhook(db, evt({ id: null, timestamp: 'yesterday' }), quiet)).body, 'malformed')
  assert.equal((await org()).plan, 'free')
  assert.equal(quiet.logs.length, 7)
})

test('a missing next_billing_date still applies and keeps the stored period end', async () => {
  const { db, org } = await setup()
  await applyWebhook(db, evt(), quiet)
  const end = (await org()).currentPeriodEnd
  await applyWebhook(db, evt({ id: 'wh_2', type: 'subscription.cancelled', timestamp: '2026-11-03T00:00:00Z', data: sub({ next_billing_date: null }) }), quiet)
  assert.equal((await org()).plan, 'free')
  assert.equal((await org()).currentPeriodEnd?.getTime(), end?.getTime())
})

test('a replayed webhook-id is applied once', async () => {
  const { db, org } = await setup()
  await applyWebhook(db, evt(), quiet)
  await db.update(schema.org).set({ plan: 'free' }).where(eq(schema.org.id, 'org1'))
  assert.equal((await applyWebhook(db, evt(), quiet)).body, 'duplicate')
  assert.equal((await org()).plan, 'free', 'replay must not re-upgrade')
})

test('a subscription already attached to another org is refused with an alert, not a retry loop', async () => {
  const { db, org } = await setup()
  await applyWebhook(db, evt(), quiet)
  const r = await applyWebhook(db, evt({ id: 'wh_x', timestamp: '2026-11-05T00:00:00Z', data: sub({ metadata: { org_id: 'org2' } }) }), quiet)
  assert.deepEqual([r.status, r.body], [200, 'conflict'])
  assert.equal((await org('org2')).plan, 'free')
  assert.ok(quiet.logs.some((l) => l.includes('ALERT')))
})

test('transient database failures surface so Dodo retries, and the id is not marked seen', async () => {
  const { db, org } = await setup()
  const broken = Object.create(db, { batch: { value: async () => { throw new Error('D1_ERROR: network connection lost') } } })
  await assert.rejects(applyWebhook(broken, evt(), quiet), /network/)
  assert.equal((await applyWebhook(db, evt(), quiet)).body, 'ok', 'retry after the outage applies')
  assert.equal((await org()).plan, 'pro')
})

test('out-of-order and same-instant events resolve as before', async () => {
  const { db, org } = await setup()
  await applyWebhook(db, evt({ id: 'a', timestamp: '2026-11-01T00:00:20Z' }), quiet)
  assert.equal((await applyWebhook(db, evt({ id: 'b', type: 'subscription.cancelled', timestamp: '2026-11-01T00:00:10Z' }), quiet)).body, 'stale')
  assert.equal((await org()).plan, 'pro')
  assert.equal((await applyWebhook(db, evt({ id: 'c', type: 'subscription.cancelled', timestamp: '2026-11-01T00:00:20Z' }), quiet)).body, 'ok')
  assert.equal((await org()).plan, 'free', 'same-instant cancel wins')
})

test('unrelated event types are ignored', async () => {
  const { db } = await setup()
  assert.equal((await applyWebhook(db, evt({ type: 'payment.succeeded' }), quiet)).body, 'ignored')
})
