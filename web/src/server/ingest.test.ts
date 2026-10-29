import { test } from 'node:test'
import assert from 'node:assert/strict'
import { testDb } from './testdb.ts'
import * as schema from './schema.ts'
import { blastRadius, handleScanUpload, type IngestDeps, type Limiter } from './ingest-core.ts'
import { mintKey, sha256 } from './crypto.ts'

const NOW = Date.parse('2026-11-01T12:00:00Z')

// Counts calls per key like the Workers binding does inside one window
const limiter = (max: number): Limiter & { calls: Map<string, number> } => {
  const calls = new Map<string, number>()
  return {
    calls,
    async limit({ key }) {
      const n = (calls.get(key) ?? 0) + 1
      calls.set(key, n)
      return { success: n <= max }
    },
  }
}

async function setup(over: Partial<IngestDeps> = {}, plan: 'free' | 'pro' = 'free') {
  const { db, sqlite } = testDb()
  await db.insert(schema.user).values({ id: 'u1', name: 'U', email: 'u@x.test' })
  await db.insert(schema.org).values({ id: 'org1', name: 'T', ownerId: 'u1', zkTag: 'a1b2c3d4', plan, subscriptionStatus: plan === 'pro' ? 'active' : null })
  const { key, preview } = mintKey('a1b2c3d4')
  await db.insert(schema.apiKey).values({ id: 'k1', orgId: 'org1', name: 'ci', preview, hash: await sha256(key) })
  let reads = 0
  const deps: IngestDeps = { db, appUrl: 'https://app.test', betaUntil: '2026-12-01', ipLimiter: limiter(1e6), keyLimiter: limiter(60), now: () => NOW, ...over }
  const send = (payload: unknown, opts: { token?: string; raw?: string; ip?: string } = {}) =>
    handleScanUpload(
      new Request('https://app.test/api/v1/scans', {
        method: 'POST',
        headers: { authorization: `Bearer ${opts.token ?? key}`, 'cf-connecting-ip': opts.ip ?? '1.1.1.1' },
        body: opts.raw ?? JSON.stringify(payload),
      }),
      deps,
    )
  return { db, sqlite, deps, key, send, reads: () => reads }
}

const finding = (i: number, over: object = {}) => ({
  fingerprint: `zk_${String(i).padStart(12, '0')}`,
  rule_id: 'aws-key',
  severity: 'HIGH',
  file_path: `src/f${i}.ts`,
  line_number: i,
  entropy: 4.5,
  redacted_preview: '[redacted]',
  ...over,
})
const scan = (n: number, over: object = {}) => ({
  scan_id: 'scn_abcd1234',
  repo_name: 'acme/api',
  branch: 'main',
  commit_hash: 'deadbeef',
  files_scanned: 10,
  duration_ms: 12,
  findings: Array.from({ length: n }, (_, i) => finding(i)),
  ...over,
})
type Body = { new_findings_count: number; dashboard_url: string }
const body = async (r: Response) => (await r.json()) as Body
const count = (sqlite: ReturnType<typeof testDb>['sqlite'], table: string) =>
  Number((sqlite.prepare(`select count(*) c from ${table}`).get() as { c: number }).c)

test('uploads a 5000-finding scan within D1 statement limits', async () => {
  const { send, sqlite } = await setup({}, 'pro')
  const res = await send(scan(5000))
  assert.equal(res.status, 200)
  assert.equal(count(sqlite, 'finding'), 5000)
  assert.equal(count(sqlite, 'scan'), 1)
})

test('the same scan uploaded twice is stored once', async () => {
  const { send, sqlite } = await setup()
  const first = await body(await send(scan(3)))
  const again = await send(scan(3))
  const second = await body(again.clone())
  assert.equal(again.status, 200)
  assert.equal(first.new_findings_count, 3)
  assert.equal(second.new_findings_count, 0)
  assert.equal(second.dashboard_url, first.dashboard_url)
  assert.equal(count(sqlite, 'scan'), 1)
  assert.equal(count(sqlite, 'finding'), 3)
})

test('two different scans that share the CLI scan id are both kept', async () => {
  const { send, sqlite } = await setup()
  await send(scan(1))
  await send(scan(2, { repo_name: 'acme/web' }))
  assert.equal(count(sqlite, 'scan'), 2)
})

test('a half-written earlier upload is healed by the retry', async () => {
  const { send, sqlite, db } = await setup()
  await send(scan(3))
  sqlite.exec('delete from finding where rowid = (select min(rowid) from finding)')
  const res = await send(scan(3))
  assert.equal((await body(res)).new_findings_count, 3)
  assert.equal(count(sqlite, 'finding'), 3)
  assert.equal((await db.query.scan.findMany()).length, 1)
})

test('rejects non-finite or oversized numbers', async () => {
  const { send } = await setup()
  const raw = JSON.stringify(scan(1)).replace('"entropy":4.5', '"entropy":1e999')
  assert.equal((await send(null, { raw })).status, 400, 'Infinity entropy')
  assert.equal((await send(scan(1, { files_scanned: 1e12 }))).status, 400)
  assert.equal((await send(scan(1, { findings: [finding(1, { line_number: 1e12 })] }))).status, 400)
})

test('61st request in a minute for one key is 429 with Retry-After', async () => {
  const { send } = await setup()
  let last!: Response
  for (let i = 0; i < 61; i++) last = await send(scan(0, { scan_id: `scn_${i}` }))
  assert.equal(last.status, 429)
  assert.equal(last.headers.get('retry-after'), '60')
})

test('IP limiter runs before any key or database work', async () => {
  const ipLimiter = limiter(2)
  const keyLimiter = limiter(60)
  const { send } = await setup({ ipLimiter, keyLimiter })
  for (let i = 0; i < 2; i++) await send(scan(0), { token: 'garbage' })
  const res = await send(scan(0), { token: 'garbage' })
  assert.equal(res.status, 429)
  assert.equal(keyLimiter.calls.size, 0, 'malformed bearers never reach the key limiter')
})

test('a flood of unknown well-formed keys costs one D1 read each', async () => {
  const { send, sqlite } = await setup()
  const seen: string[] = []
  const orig = sqlite.prepare.bind(sqlite)
  sqlite.prepare = ((sql: string) => (seen.push(sql), orig(sql))) as typeof sqlite.prepare
  const bad = `sp_live_${'0'.repeat(48)}`
  for (let i = 0; i < 10; i++) assert.equal((await send(scan(0), { token: bad })).status, 401)
  assert.equal(seen.length, 10)
  seen.length = 0
  for (let i = 0; i < 10; i++) assert.equal((await send(scan(0), { token: 'nope' })).status, 401)
  assert.equal(seen.length, 0, 'malformed bearer: zero reads')
})

test('org over its daily finding cap gets 429; yesterday does not count', async () => {
  const { send, deps } = await setup()
  assert.equal((await send(scan(5000, { scan_id: 'a' }))).status, 200)
  assert.equal((await send(scan(5000, { scan_id: 'b' }))).status, 200)
  const over = await send(scan(1, { scan_id: 'c' }))
  assert.equal(over.status, 429)
  assert.ok(Number(over.headers.get('retry-after')) > 0)
  deps.now = () => NOW + 25 * 3600_000
  assert.equal((await send(scan(1, { scan_id: 'c' }))).status, 200)
})

test('org over its daily scan cap gets 429', async () => {
  const { send, sqlite } = await setup()
  for (let i = 0; i < 100; i++)
    sqlite.prepare("insert into scan (id,org_id,cli_scan_id,repo,branch,files_scanned,duration_ms,findings_count,created_at) values (?,'org1',?,'r','b',1,1,0,?)").run(`s${i}`, `c${i}`, NOW - 1000)
  assert.equal((await send(scan(0))).status, 429)
})

test('sync is refused with 402 once the beta window has passed', async () => {
  const { send } = await setup({ betaUntil: '2026-10-01' })
  assert.equal((await send(scan(1))).status, 402)
})

test('last_used_at is only rewritten when older than a minute', async () => {
  const { send, deps, db } = await setup()
  await send(scan(0, { scan_id: 'a' }))
  const t1 = (await db.query.apiKey.findFirst())!.lastUsedAt!.getTime()
  deps.now = () => NOW + 30_000
  await send(scan(0, { scan_id: 'b' }))
  assert.equal((await db.query.apiKey.findFirst())!.lastUsedAt!.getTime(), t1)
  deps.now = () => NOW + 61_000
  await send(scan(0, { scan_id: 'c' }))
  assert.equal((await db.query.apiKey.findFirst())!.lastUsedAt!.getTime(), NOW + 61_000)
})

test('blast radius ranks severity by level and splits repos containing commas', async () => {
  const { send, db } = await setup()
  const fp = 'zk_shared000001'
  await send(scan(0, { repo_name: 'a,b', findings: [finding(1, { fingerprint: fp, severity: 'MEDIUM' })], scan_id: 's1' }))
  await send(scan(0, { repo_name: 'c', findings: [finding(2, { fingerprint: fp, severity: 'critical' })], scan_id: 's2' }))
  const [r] = await blastRadius(db, 'org1', [fp])
  assert.equal(r.severity, 'CRITICAL', 'text max would have said MEDIUM')
  assert.deepEqual([...r.affected_repos].sort(), ['a,b', 'c'])
  assert.equal(r.total_occurrences, 2)
})

test('writes a per-scan severity rollup, folding case and chunking many distinct severities', async () => {
  const { send, sqlite } = await setup({}, 'pro')
  const findings = [finding(0, { severity: 'HIGH' }), finding(1, { severity: 'high' }), finding(2, { severity: 'Critical' })]
  assert.equal((await send(scan(0, { findings }))).status, 200)
  const rows = sqlite.prepare('select severity, n from scan_severity order by severity').all() as { severity: string; n: number }[]
  assert.deepEqual(rows.map((r) => [r.severity, r.n]), [['critical', 1], ['high', 2]])

  // 100 distinct severities exceed one INSERT's bound-parameter budget
  const many = Array.from({ length: 100 }, (_, i) => finding(i + 10, { severity: `sev${i}` }))
  assert.equal((await send(scan(0, { scan_id: 'scn_many', findings: many }))).status, 200)
  assert.equal(count(sqlite, 'scan_severity'), 2 + 100)
})
