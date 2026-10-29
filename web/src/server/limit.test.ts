import { test } from 'node:test'
import assert from 'node:assert/strict'
import { limitedResponse } from './limit.ts'

test('auth flood from one IP is cut off with Retry-After', async () => {
  const seen = new Map<string, number>()
  const limiter = { limit: async ({ key }: { key: string }) => ({ success: (seen.set(key, (seen.get(key) ?? 0) + 1).get(key)!) <= 60 }) }
  for (let i = 0; i < 60; i++) assert.equal(await limitedResponse(limiter, '9.9.9.9'), null)
  const res = await limitedResponse(limiter, '9.9.9.9')
  assert.equal(res?.status, 429)
  assert.equal(res?.headers.get('retry-after'), '60')
  assert.equal(await limitedResponse(limiter, '8.8.8.8'), null, 'other IPs are unaffected')
})
