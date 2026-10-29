import { z } from 'zod'
import { and, count, eq, gte, inArray, isNull, sql } from 'drizzle-orm'
import type { DrizzleD1Database } from 'drizzle-orm/d1'
import * as schema from './schema.ts'
import { parseBearer, randomHex, sha256 } from './crypto.ts'
import { canIngest, quotaRetryAfter, readCapped, severityName } from './guards.ts'

export type Db = DrizzleD1Database<typeof schema>
export type Limiter = { limit(o: { key: string }): Promise<{ success: boolean }> }
export type IngestDeps = { db: Db; appUrl: string; betaUntil?: string; ipLimiter: Limiter; keyLimiter: Limiter; now?: () => number }

// Mirrors CloudScanPayload in src/cloud/client.rs
const Finding = z.object({
  fingerprint: z.string().min(8).max(128),
  rule_id: z.string().max(128),
  severity: z.string().max(32),
  file_path: z.string().max(1024),
  line_number: z.number().int().nonnegative().max(10_000_000),
  entropy: z.number().min(0).max(1000),
  redacted_preview: z.string().max(256).optional(),
})
const Payload = z.object({
  scan_id: z.string().max(64),
  repo_name: z.string().min(1).max(256),
  branch: z.string().max(256),
  commit_hash: z.string().max(64).nullish(),
  files_scanned: z.number().int().nonnegative().max(1e9),
  duration_ms: z.number().nonnegative().max(1e9),
  findings: z.array(Finding).max(5000),
})

const json = (body: unknown, status = 200, headers?: HeadersInit) => Response.json(body, { status, headers })
const fail = (status: number, message: string, headers?: HeadersInit) => json({ success: false, message }, status, headers)
const tooMany = (seconds: number, what: string) =>
  fail(429, `${what} Retry in ${seconds}s.`, { 'retry-after': String(seconds) })
const safeJson = (s: string) => {
  try {
    return JSON.parse(s)
  } catch {
    return null
  }
}

const chunk = <T,>(xs: T[], n: number) =>
  Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n))

// D1 allows 100 bound parameters per statement; a finding row binds 12
const ROWS_PER_INSERT = 8
const ROLLUPS_PER_INSERT = 19
const STATEMENTS_PER_BATCH = 50
const KEY_TOUCH_MS = 60_000

export async function handleScanUpload(request: Request, deps: IngestDeps): Promise<Response> {
  const { db } = deps
  const now = deps.now ?? Date.now

  // Cheapest checks first: nothing below touches D1 until a well-formed key has passed both limiters
  const ip = request.headers.get('cf-connecting-ip') ?? 'unknown'
  if (!(await deps.ipLimiter.limit({ key: ip })).success) return tooMany(60, 'Too many requests.')

  const token = parseBearer(request.headers.get('authorization'))
  if (!token) return fail(401, 'Missing or malformed API key. Run `sentris auth login --token <key> --server <url>`.')

  const hash = await sha256(token)
  if (!(await deps.keyLimiter.limit({ key: hash })).success) return tooMany(60, 'Rate limit exceeded for this API key.')

  const row = await db
    .select({ key: schema.apiKey, org: schema.org })
    .from(schema.apiKey)
    .innerJoin(schema.org, eq(schema.apiKey.orgId, schema.org.id))
    .where(and(eq(schema.apiKey.hash, hash), isNull(schema.apiKey.revokedAt)))
    .get()
  if (!row) return fail(401, 'API key is invalid or revoked.')
  if (!canIngest(row.org, deps.betaUntil, now())) return fail(402, 'Cloud sync requires an active Sentris Pro subscription.')

  const body = await readCapped(request, 2_000_000)
  if (body === null) return fail(413, 'Payload too large.')
  const parsed = Payload.safeParse(safeJson(body))
  if (!parsed.success) return fail(400, `Invalid scan payload: ${parsed.error.issues[0]?.message}`)
  const p = parsed.data
  const orgId = row.org.id

  // The CLI's scan id is a truncated hash of timing stats, so two different scans can share one.
  // Pair it with a digest of the content: identical payloads replay, different scans never collide.
  const fps = [...new Set(p.findings.map((f) => f.fingerprint))]
  const digest = (await sha256(JSON.stringify([p.repo_name, p.branch, p.commit_hash ?? null, p.files_scanned, [...fps].sort()]))).slice(0, 16)
  const idemKey = `${p.scan_id}:${digest}`

  const replay = await replayOf(db, orgId, idemKey, deps)
  if (replay) return replay(p.scan_id)

  const day = new Date(now() - 864e5)
  const used = await db
    .select({
      scans: count(),
      findings: sql<number>`coalesce(sum(${schema.scan.findingsCount}), 0)`,
      oldest: sql<number | null>`min(${schema.scan.createdAt})`,
    })
    .from(schema.scan)
    .where(and(eq(schema.scan.orgId, orgId), gte(schema.scan.createdAt, day)))
    .get()
  const wait = quotaRetryAfter(row.org.plan, used ?? { scans: 0, findings: 0, oldest: null }, p.findings.length, now())
  if (wait !== null) return tooMany(wait, 'Daily scan quota reached.')

  const scanId = `scn_${randomHex(10)}`
  const findings = p.findings.map((f) => ({
    id: `fnd_${randomHex(10)}`,
    orgId,
    scanId,
    repo: p.repo_name,
    fingerprint: f.fingerprint,
    ruleId: f.rule_id,
    severity: f.severity,
    filePath: f.file_path,
    line: f.line_number,
    entropy: f.entropy,
    // Never store key characters, even from older CLIs that still send a partial preview
    preview: '[redacted]',
  }))

  const bySeverity = new Map<string, number>()
  for (const f of findings) {
    const sev = f.severity.toLowerCase()
    bySeverity.set(sev, (bySeverity.get(sev) ?? 0) + 1)
  }
  const createdAt = new Date(now())
  const rollup = [...bySeverity].map(([severity, n]) => ({ scanId, orgId, severity, n, createdAt }))

  const statements = [
    db.insert(schema.scan).values({
      id: scanId,
      orgId,
      cliScanId: idemKey,
      repo: p.repo_name,
      branch: p.branch,
      commitHash: p.commit_hash ?? null,
      filesScanned: p.files_scanned,
      durationMs: Math.round(p.duration_ms),
      findingsCount: findings.length,
      createdAt,
    }),
    ...chunk(rollup, ROLLUPS_PER_INSERT).map((c) => db.insert(schema.scanSeverity).values(c)),
    ...chunk(findings, ROWS_PER_INSERT).map((c) => db.insert(schema.finding).values(c)),
  ]
  try {
    for (const part of chunk(statements, STATEMENTS_PER_BATCH)) await db.batch(part as [(typeof statements)[0], ...typeof statements])
  } catch (err) {
    await discard(db, scanId)
    // A concurrent retry of the same payload won the race: this one is a replay
    const raced = /UNIQUE/i.test(String(err)) ? await replayOf(db, orgId, idemKey, deps) : null
    if (raced) return raced(p.scan_id)
    throw err
  }

  const lastUsed = row.key.lastUsedAt?.getTime()
  if (lastUsed === undefined || now() - lastUsed > KEY_TOUCH_MS)
    await db.update(schema.apiKey).set({ lastUsedAt: new Date(now()) }).where(eq(schema.apiKey.id, row.key.id))

  return json({
    success: true,
    scan_id: p.scan_id,
    dashboard_url: `${deps.appUrl}/app/scans/${scanId}`,
    new_findings_count: findings.length,
    message: `Synced ${findings.length} zero-knowledge finding(s) to Sentris Cloud.`,
    blast_radius_insights: fps.length ? await blastRadius(db, orgId, fps) : [],
  })
}

const discard = async (db: Db, scanId: string) => {
  await db.delete(schema.finding).where(eq(schema.finding.scanId, scanId))
  await db.delete(schema.scan).where(eq(schema.scan.id, scanId))
}

// A completed earlier upload of the same payload. A half-written one (crash between batches) is cleaned so the retry can redo it.
async function replayOf(db: Db, orgId: string, idemKey: string, deps: IngestDeps) {
  const prior = await db.query.scan.findFirst({ where: and(eq(schema.scan.orgId, orgId), eq(schema.scan.cliScanId, idemKey)) })
  if (!prior) return null
  const stored = await db.select({ fp: schema.finding.fingerprint }).from(schema.finding).where(eq(schema.finding.scanId, prior.id))
  if (stored.length !== prior.findingsCount) {
    await discard(db, prior.id)
    return null
  }
  const insights = stored.length ? await blastRadius(db, orgId, [...new Set(stored.map((s) => s.fp))]) : []
  return (cliScanId: string) =>
    json({
      success: true,
      scan_id: cliScanId,
      dashboard_url: `${deps.appUrl}/app/scans/${prior.id}`,
      new_findings_count: 0,
      message: 'This scan was already synced; nothing new to upload.',
      blast_radius_insights: insights,
    })
}

// Same fingerprint in more than one repo = one leaked credential, wider blast radius.
// Step 1 finds the widest fingerprints from the (org, fingerprint, repo) index alone; step 2 reads full rows for just those.
export async function blastRadius(db: Db, orgId: string, fps?: string[]) {
  const f = schema.finding
  const scope = fps ? and(eq(f.orgId, orgId), inArray(f.fingerprint, fps.slice(0, 90))) : eq(f.orgId, orgId)
  const wide = await db
    .select({ fp: f.fingerprint })
    .from(f)
    .where(scope)
    .groupBy(f.fingerprint)
    .having(sql`count(distinct ${f.repo}) > 1`)
    .orderBy(sql`count(distinct ${f.repo}) desc`, f.fingerprint)
    .limit(50)
  if (!wide.length) return []

  const rank = sql<number>`max(case lower(${f.severity}) when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end)`
  const rows = await db
    .select({
      zk_fingerprint: f.fingerprint,
      rule_id: sql<string>`max(${f.ruleId})`,
      rank,
      redacted_preview: sql<string>`max(${f.preview})`,
      repos: sql<string>`json_group_array(distinct ${f.repo})`,
      total_occurrences: sql<number>`count(*)`,
    })
    .from(f)
    .where(and(eq(f.orgId, orgId), inArray(f.fingerprint, wide.map((w) => w.fp))))
    .groupBy(f.fingerprint)
    .orderBy(sql`count(distinct ${f.repo}) desc`, f.fingerprint)
  return rows.map(({ repos, rank, ...r }) => ({ ...r, severity: severityName(rank).toUpperCase(), affected_repos: JSON.parse(repos) as string[] }))
}
