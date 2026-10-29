import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canIngest, configProblems, quotaRetryAfter, readCapped, sameOrigin, severityName, severityRank, shouldApply } from './guards.ts'

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

const org = (o: Partial<Parameters<typeof canIngest>[0]> = {}) => ({ plan: 'free' as const, subscriptionStatus: null, currentPeriodEnd: null, ...o })
const NOW = Date.parse('2026-11-01T00:00:00Z')

test('canIngest: beta window opens sync only until its date', () => {
  assert.equal(canIngest(org(), '2026-11-30', NOW), true, 'inside beta')
  assert.equal(canIngest(org(), '2026-10-01', NOW), false, 'expired beta falls back to paywall')
  assert.equal(canIngest(org(), undefined, NOW), false, 'no flag')
  assert.equal(canIngest(org(), 'true', NOW), false, 'old boolean value is not a date')
  assert.equal(canIngest(org(), 'garbage', NOW), false)
})

test('canIngest: paid orgs sync, ended or lapsed ones do not', () => {
  const pro = { plan: 'pro' as const, subscriptionStatus: 'active' }
  assert.equal(canIngest(org(pro), undefined, NOW), true)
  assert.equal(canIngest(org({ ...pro, currentPeriodEnd: new Date(NOW + 1000) }), undefined, NOW), true)
  assert.equal(canIngest(org({ ...pro, currentPeriodEnd: new Date(NOW - 1000) }), undefined, NOW), false, 'expired period')
  assert.equal(canIngest(org({ plan: 'free', subscriptionStatus: 'cancelled' }), undefined, NOW), false, 'cancelled')
  assert.equal(canIngest(org({ ...pro, subscriptionStatus: 'on_hold' }), undefined, NOW), false)
})

test('configProblems flags weak secrets and placeholder product ids in live mode', () => {
  const ok = { secret: 'x'.repeat(32), appUrl: 'https://sentris.dev', dodoEnv: 'live_mode', productId: 'pdt_123' }
  assert.deepEqual(configProblems(ok), [])
  assert.equal(configProblems({ ...ok, secret: 'short' }).length, 1)
  assert.equal(configProblems({ ...ok, productId: 'pdt_REPLACE_ME' }).length, 1)
  assert.deepEqual(configProblems({ ...ok, dodoEnv: 'test_mode', productId: 'pdt_REPLACE_ME' }), [], 'placeholder is fine in test mode')
  assert.equal(configProblems({ ...ok, appUrl: 'nope' }).length, 1)
})

test('severity ranks by level, not by text', () => {
  assert.ok(severityRank('critical') > severityRank('medium'), 'text max would pick "medium"')
  assert.equal(severityRank('CRITICAL'), severityRank('critical'))
  assert.equal(severityName(severityRank('High')), 'high')
  assert.equal(severityRank('weird'), 0)
})

test('quotaRetryAfter allows within caps and reports when the window frees up', () => {
  const fits = { scans: 99, findings: 9_000, oldest: NOW }
  assert.equal(quotaRetryAfter('free', fits, 1_000, NOW), null)
  assert.equal(quotaRetryAfter('free', { ...fits, scans: 100 }, 1, NOW), 86_400, 'scan cap')
  assert.equal(quotaRetryAfter('free', fits, 1_001, NOW), 86_400, 'finding cap')
  assert.equal(quotaRetryAfter('free', { scans: 100, findings: 0, oldest: NOW - 86_000_000 }, 1, NOW), 400)
  assert.equal(quotaRetryAfter('pro', { scans: 100, findings: 10_000, oldest: NOW }, 1, NOW), null, 'pro limits are higher')
})

test('sameOrigin rejects cross-site mutations', () => {
  const app = 'https://sentris.dev'
  const post = (h: Record<string, string>) => new Request(`${app}/_serverFn/x`, { method: 'POST', headers: h })
  assert.equal(sameOrigin(post({ origin: app }), app), true)
  assert.equal(sameOrigin(post({ origin: 'https://evil.test' }), app), false)
  assert.equal(sameOrigin(post({}), app), false, 'no origin, no fetch metadata')
  assert.equal(sameOrigin(post({ 'sec-fetch-site': 'same-origin' }), app), true)
  assert.equal(sameOrigin(post({ 'sec-fetch-site': 'cross-site' }), app), false)
  assert.equal(sameOrigin(new Request(`${app}/x`), app), true, 'GET is not a mutation')
})
