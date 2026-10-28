import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readCapped, shouldApply } from './guards.ts'

const chunked = (bytes: number) =>
  new Request('http://x', { method: 'POST', body: new ReadableStream({ start(c) { c.enqueue(new Uint8Array(bytes)); c.close() } }), duplex: 'half' } as RequestInit)

test('readCapped rejects oversized bodies even without content-length', async () => {
  assert.equal(await readCapped(chunked(11), 10), null)
  assert.equal((await readCapped(chunked(10), 10))?.length, 10)
  assert.equal(await readCapped(new Request('http://x', { method: 'POST', body: 'x', headers: { 'content-length': '99' } }), 10), null)
})

test('shouldApply drops stale and foreign-subscription events', () => {
  const t = (s: string) => new Date(`2026-10-29T00:00:${s}Z`)
  const org = { dodoSubscriptionId: 'sub_new', billingEventAt: t('10') }
  assert.equal(shouldApply(org, 'sub_new', false, t('09')), false, 'older event')
  assert.equal(shouldApply(org, 'sub_new', true, t('10')), true, 'same-instant cancel still downgrades')
  assert.equal(shouldApply(org, 'sub_new', false, t('10')), false, 'same-instant activation does not re-upgrade')
  assert.equal(shouldApply(org, 'sub_old', true, t('20')), false, 'old sub cancel must not downgrade')
  assert.equal(shouldApply(org, 'sub_new', true, t('20')), true, 'current sub cancel applies')
  assert.equal(shouldApply(org, 'sub_other', false, t('20')), true, 'new subscription activates')
  assert.equal(shouldApply({ dodoSubscriptionId: null, billingEventAt: null }, 'sub_a', false, t('01')), true)
})
