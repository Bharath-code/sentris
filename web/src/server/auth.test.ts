import { test } from 'node:test'
import assert from 'node:assert/strict'
import { testDb } from './testdb.ts'
import { createAuth } from './auth-core.ts'

const cfg = { appUrl: 'https://sentris.test', secret: 'x'.repeat(40), githubId: 'id', githubSecret: 'secret' }
const signIn = (ip: string) =>
  new Request('https://sentris.test/api/auth/sign-in/social', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://sentris.test', 'cf-connecting-ip': ip },
    body: JSON.stringify({ provider: 'github', callbackURL: '/app' }),
  })

test('sign-in sets hardened cookies', async () => {
  const { db } = testDb()
  const res = await createAuth(cfg, db).handler(signIn('1.1.1.1'))
  assert.equal(res.status, 200)
  const cookies = res.headers.getSetCookie()
  assert.ok(cookies.length > 0, 'state cookie expected')
  for (const c of cookies) {
    assert.match(c, /HttpOnly/i, c)
    assert.match(c, /Secure/i, c)
    assert.match(c, /SameSite=Lax/i, c)
  }
})

test('sign-in flood from one IP is rate limited in the database, other IPs are not', async () => {
  const { db, sqlite } = testDb()
  const auth = createAuth(cfg, db)
  const statuses: number[] = []
  for (let i = 0; i < 12; i++) statuses.push((await auth.handler(signIn('2.2.2.2'))).status)
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(200))
  assert.equal(statuses[10], 429)
  assert.ok(Number((sqlite.prepare('select count(*) c from rate_limit').get() as { c: number }).c) > 0, 'counters live in D1')
  assert.equal((await auth.handler(signIn('3.3.3.3'))).status, 200)
})

test('plain http (local dev) does not demand Secure cookies', async () => {
  const { db } = testDb()
  const res = await createAuth({ ...cfg, appUrl: 'http://localhost:3000' }, db).handler(
    new Request('http://localhost:3000/api/auth/sign-in/social', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({ provider: 'github', callbackURL: '/app' }),
    }),
  )
  assert.ok(res.headers.getSetCookie().every((c) => !/;\s*Secure/i.test(c)))
})
