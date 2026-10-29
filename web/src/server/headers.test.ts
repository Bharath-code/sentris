import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { SECURITY_HEADERS, headersFile, withSecurityHeaders } from './headers.ts'

test('public/_headers matches the Worker header set (regenerate with `npm run headers`)', () => {
  assert.equal(readFileSync(new URL('../../public/_headers', import.meta.url), 'utf8'), headersFile())
})

test('every response, even an immutable redirect, gets the full header set', () => {
  for (const res of [Response.redirect('https://x.test/', 302), new Response('ok'), Response.json({ a: 1 }, { status: 429 })]) {
    const out = withSecurityHeaders(res)
    for (const k of Object.keys(SECURITY_HEADERS)) assert.ok(out.headers.get(k), k)
    assert.equal(out.status, res.status)
  }
})

test('per-user paths are no-store, public pages and explicit cache headers are left alone', () => {
  for (const p of ['/app', '/app/scans/scn_1', '/_serverFn/abc', '/api/v1/me', '/api/auth/get-session']) {
    assert.equal(withSecurityHeaders(new Response('x'), p).headers.get('Cache-Control'), 'private, no-store', p)
  }
  for (const p of ['/', '/pricing', '/login', '/application']) assert.equal(withSecurityHeaders(new Response('x'), p).headers.get('Cache-Control'), null, p)
  const own = withSecurityHeaders(new Response('x', { headers: { 'Cache-Control': 'no-cache' } }), '/api/v1/me')
  assert.equal(own.headers.get('Cache-Control'), 'no-cache')
})

test('CSP forbids framing, plugins, foreign scripts and base injection', () => {
  const csp = SECURITY_HEADERS['Content-Security-Policy']
  for (const d of ["frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'", "default-src 'self'", "connect-src 'self'"]) assert.ok(csp.includes(d), d)
  assert.ok(!/script-src[^;]*https?:/.test(csp), 'no remote script origins')
})
