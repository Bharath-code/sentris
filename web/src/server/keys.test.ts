import { test } from 'node:test'
import assert from 'node:assert/strict'
import { eq } from 'drizzle-orm'
import { testDb } from './testdb.ts'
import * as schema from './schema.ts'
import { createApiKey } from './keys.ts'
import { sha256 } from './crypto.ts'

test('the 21st active key is refused; revoking frees a slot', async () => {
  const { db } = testDb()
  await db.insert(schema.user).values({ id: 'u1', name: 'U', email: 'u@x.test' })
  await db.insert(schema.org).values({ id: 'org1', name: 'T', ownerId: 'u1', zkTag: 'a1b2c3d4' })
  const org = { id: 'org1', zkTag: 'a1b2c3d4' }

  const first = await createApiKey(db, org, 'k0')
  for (let i = 1; i < 20; i++) await createApiKey(db, org, `k${i}`)
  await assert.rejects(createApiKey(db, org, 'k20'), /at most 20/)

  await db.update(schema.apiKey).set({ revokedAt: new Date() }).where(eq(schema.apiKey.hash, await sha256(first.key)))
  assert.match((await createApiKey(db, org, 'again')).key, /^sp_live_a1b2c3d4[0-9a-f]{40}$/)
  assert.equal((await db.query.apiKey.findMany()).length, 21, 'revoked keys stay for audit but do not count')
})
