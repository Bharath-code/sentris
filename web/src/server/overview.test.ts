import { test } from 'node:test'
import assert from 'node:assert/strict'
import { and, desc, eq, gte, sql } from 'drizzle-orm'
import { testDb } from './testdb.ts'
import * as schema from './schema.ts'
import { FINDINGS_PAGE } from './guards.ts'
import { getOverviewData, getScanPage } from './overview-core.ts'
import { purgeExpired } from './retention-core.ts'

const NOW = Date.parse('2026-11-01T12:00:00Z')
const DAY = 864e5

async function seed(opts: { scans: number; perScan: number; plan?: 'free' | 'pro' } = { scans: 1, perScan: 0 }) {
  const { db, sqlite } = testDb()
  await db.insert(schema.user).values({ id: 'u1', name: 'U', email: 'u@x.test' })
  await db.insert(schema.org).values({ id: 'org1', name: 'T', ownerId: 'u1', zkTag: 'a1b2c3d4', plan: opts.plan ?? 'pro' })
  const sevs = ['critical', 'high', 'medium', 'low']
  sqlite.exec('BEGIN')
  const scanIns = sqlite.prepare('insert into scan (id, org_id, cli_scan_id, repo, branch, files_scanned, duration_ms, findings_count, created_at) values (?,?,?,?,?,?,?,?,?)')
  const findIns = sqlite.prepare('insert into finding (id, org_id, scan_id, repo, fingerprint, rule_id, severity, file_path, line, entropy, preview, created_at) values (?,?,?,?,?,?,?,?,?,?,?,?)')
  const rollIns = sqlite.prepare('insert into scan_severity (scan_id, org_id, severity, n, created_at) values (?,?,?,?,?)')
  for (let s = 0; s < opts.scans; s++) {
    const at = NOW - (s % 28) * DAY - s
    scanIns.run(`scn_${s}`, 'org1', `cli_${s}`, `acme/repo${s % 40}`, 'main', 100, 10, opts.perScan, at)
    const per: Record<string, number> = {}
    for (let i = 0; i < opts.perScan; i++) {
      const sev = sevs[(s + i) % 4]
      per[sev] = (per[sev] ?? 0) + 1
      // a quarter of fingerprints repeat across scans so blast radius has real work to do
      const fp = i % 4 === 0 ? `zk_shared${i % 500}` : `zk_${s}_${i}`
      findIns.run(`fnd_${s}_${i}`, 'org1', `scn_${s}`, `acme/repo${s % 40}`, fp, 'aws-key', sev, `src/f${i % 50}.ts`, i, 4.5, '[redacted]', at)
    }
    for (const [sev, n] of Object.entries(per)) rollIns.run(`scn_${s}`, 'org1', sev, n, at)
  }
  sqlite.exec('COMMIT')
  return { db, sqlite }
}

const plan = (sqlite: ReturnType<typeof testDb>['sqlite'], sql: string, params: unknown[]) =>
  (sqlite.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...(params as never[])) as { detail: string }[]).map((r) => r.detail).join(' | ')

test('dashboard queries use indexes and stay fast with 100k findings', async () => {
  const { db, sqlite } = await seed({ scans: 500, perScan: 200 })
  const finds = sqlite.prepare('select count(*) c from finding').get() as { c: number }
  assert.equal(finds.c, 100_000)

  const since = NOW - 30 * DAY
  const rollup = db.select().from(schema.scanSeverity).where(and(eq(schema.scanSeverity.orgId, 'org1'), gte(schema.scanSeverity.createdAt, new Date(since)))).toSQL()
  assert.match(plan(sqlite, rollup.sql, rollup.params), /scan_severity_org_created/)
  const recent = db.query.scan.findMany({ where: eq(schema.scan.orgId, 'org1'), orderBy: desc(schema.scan.createdAt), limit: 25 }).toSQL()
  assert.match(plan(sqlite, recent.sql, recent.params), /scan_org_created/)
  const keys = db.query.apiKey.findMany({ where: eq(schema.apiKey.orgId, 'org1') }).toSQL()
  assert.match(plan(sqlite, keys.sql, keys.params), /api_key_org/)
  const f = schema.finding
  const wide = db.select({ fp: f.fingerprint }).from(f).where(eq(f.orgId, 'org1')).groupBy(f.fingerprint).having(sql`count(distinct ${f.repo}) > 1`).toSQL()
  assert.match(plan(sqlite, wide.sql, wide.params), /COVERING INDEX finding_org_fp_repo/)

  await getOverviewData(db, 'org1', NOW) // warm
  const runs: number[] = []
  for (let i = 0; i < 5; i++) {
    const t = performance.now()
    await getOverviewData(db, 'org1', NOW)
    runs.push(performance.now() - t)
  }
  const median = runs.sort((a, b) => a - b)[2]
  console.log(`overview median over 100k findings: ${median.toFixed(1)} ms`)
  assert.ok(median < 150, `overview took ${median} ms`)
})

test('rollup totals match a direct count of findings in the window', async () => {
  const { db, sqlite } = await seed({ scans: 60, perScan: 40 })
  const d = await getOverviewData(db, 'org1', NOW)
  const direct = sqlite.prepare('select lower(severity) s, count(*) n from finding where created_at >= ? group by 1 order by 1').all(NOW - 30 * DAY) as { s: string; n: number }[]
  const fromRollup = [...d.bySeverity].map((r) => [r.severity, Number(r.n)]).sort()
  assert.deepEqual(fromRollup, direct.map((r) => [r.s, r.n]))
  assert.equal(d.scans.length, 25)
})

test('a 1200-finding scan pages through every finding exactly once, worst first', async () => {
  const { db } = await seed({ scans: 1, perScan: 1200 })
  const seen = new Set<string>()
  let offset = 0
  let first: Awaited<ReturnType<typeof getScanPage>> | undefined
  for (;;) {
    const page = await getScanPage(db, 'org1', 'scn_0', offset)
    first ??= page
    assert.equal(page.total, 1200)
    for (const f of page.findings) {
      assert.ok(!seen.has(f.id), `repeated ${f.id}`)
      seen.add(f.id)
    }
    if (page.findings.length < FINDINGS_PAGE) break
    offset += FINDINGS_PAGE
  }
  assert.equal(seen.size, 1200)
  assert.equal(first!.findings.length, FINDINGS_PAGE)
  assert.equal(first!.findings[0].severity, 'critical')
})

test('another org cannot read a scan page', async () => {
  const { db } = await seed({ scans: 1, perScan: 3 })
  await assert.rejects(getScanPage(db, 'org_other', 'scn_0'), /not found/)
})

test('purge removes scans past plan retention, with findings and rollups, and keeps the rest', async () => {
  const { db, sqlite } = await seed({ scans: 0, perScan: 0 })
  await db.insert(schema.user).values({ id: 'u2', name: 'V', email: 'v@x.test' })
  await db.insert(schema.org).values({ id: 'org2', name: 'F', ownerId: 'u2', zkTag: 'e5f6a7b8', plan: 'free' })
  const mk = async (id: string, org: string, ageDays: number) => {
    const at = new Date(NOW - ageDays * DAY)
    await db.insert(schema.scan).values({ id, orgId: org, cliScanId: id, repo: 'r', branch: 'main', filesScanned: 1, durationMs: 1, findingsCount: 1, createdAt: at })
    await db.insert(schema.finding).values({ id: `f_${id}`, orgId: org, scanId: id, repo: 'r', fingerprint: 'zk_00000000', ruleId: 'x', severity: 'high', filePath: 'a', line: 1, entropy: 1, preview: '[redacted]', createdAt: at })
    await db.insert(schema.scanSeverity).values({ scanId: id, orgId: org, severity: 'high', n: 1, createdAt: at })
  }
  await mk('pro_old', 'org1', 91)
  await mk('pro_mid', 'org1', 60) // inside Pro retention, outside Free's
  await mk('free_old', 'org2', 31)
  await mk('free_new', 'org2', 5)
  await db.insert(schema.webhookEvent).values([{ id: 'wh_old', appliedAt: new Date(NOW - 31 * DAY) }, { id: 'wh_new', appliedAt: new Date(NOW - DAY) }])

  const removed = await purgeExpired(db, NOW)
  assert.deepEqual(removed, { free: 1, pro: 1, webhooks: 1 })
  const ids = (t: string, c: string) => (sqlite.prepare(`select ${c} id from ${t} order by 1`).all() as { id: string }[]).map((r) => r.id)
  assert.deepEqual(ids('scan', 'id'), ['free_new', 'pro_mid'])
  assert.deepEqual(ids('finding', 'scan_id'), ['free_new', 'pro_mid'])
  assert.deepEqual(ids('scan_severity', 'scan_id'), ['free_new', 'pro_mid'])
  assert.deepEqual(ids('webhook_event', 'id'), ['wh_new'])
})

test('purge works through more expired scans than one batch', async () => {
  const { db, sqlite } = await seed({ scans: 0, perScan: 0, plan: 'free' })
  sqlite.exec('BEGIN')
  const ins = sqlite.prepare('insert into scan (id, org_id, cli_scan_id, repo, branch, files_scanned, duration_ms, findings_count, created_at) values (?,?,?,?,?,?,?,?,?)')
  for (let i = 0; i < 350; i++) ins.run(`old_${i}`, 'org1', `c${i}`, 'r', 'main', 1, 1, 0, NOW - 40 * DAY)
  sqlite.exec('COMMIT')
  assert.equal((await purgeExpired(db, NOW)).free, 350)
})
