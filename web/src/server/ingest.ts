import { z } from 'zod'
import { and, eq, inArray, isNull, sql } from 'drizzle-orm'
import { env } from 'cloudflare:workers'
import { db, schema } from './db'
import { parseBearer, randomHex, sha256 } from './crypto'
import { canIngest } from './org'

// Mirrors CloudScanPayload in src/cloud/client.rs
const Finding = z.object({
  fingerprint: z.string().min(8).max(128),
  rule_id: z.string().max(128),
  severity: z.string().max(32),
  file_path: z.string().max(1024),
  line_number: z.number().int().nonnegative(),
  entropy: z.number(),
  redacted_preview: z.string().max(256),
})
const Payload = z.object({
  scan_id: z.string().max(64),
  repo_name: z.string().min(1).max(256),
  branch: z.string().max(256),
  commit_hash: z.string().max(64).nullish(),
  files_scanned: z.number().int().nonnegative(),
  duration_ms: z.number().nonnegative(),
  findings: z.array(Finding).max(5000),
})

const json = (body: unknown, status = 200) => Response.json(body, { status })
const fail = (status: number, message: string) => json({ success: false, message }, status)
const chunk = <T,>(xs: T[], n: number) =>
  Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n))

export async function handleScanUpload(request: Request): Promise<Response> {
  const token = parseBearer(request.headers.get('authorization'))
  if (!token) return fail(401, 'Missing or malformed API key. Run `sentris auth login --token <key> --server <url>`.')

  const hash = await sha256(token)
  const row = await db
    .select({ key: schema.apiKey, org: schema.org })
    .from(schema.apiKey)
    .innerJoin(schema.org, eq(schema.apiKey.orgId, schema.org.id))
    .where(and(eq(schema.apiKey.hash, hash), isNull(schema.apiKey.revokedAt)))
    .get()
  if (!row) return fail(401, 'API key is invalid or revoked.')
  if (!canIngest(row.org)) return fail(402, 'Cloud sync requires an active Sentris Pro subscription.')

  if (Number(request.headers.get('content-length') ?? 0) > 2_000_000) return fail(413, 'Payload too large.')
  const parsed = Payload.safeParse(await request.json().catch(() => null))
  if (!parsed.success) return fail(400, `Invalid scan payload: ${parsed.error.issues[0]?.message}`)
  const p = parsed.data
  const orgId = row.org.id
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
    preview: f.redacted_preview,
  }))

  // D1 caps bound parameters per statement at 100; findings have 11 columns
  await db.batch([
    db.insert(schema.scan).values({
      id: scanId,
      orgId,
      cliScanId: p.scan_id,
      repo: p.repo_name,
      branch: p.branch,
      commitHash: p.commit_hash ?? null,
      filesScanned: p.files_scanned,
      durationMs: Math.round(p.duration_ms),
      findingsCount: findings.length,
    }),
    ...chunk(findings, 9).map((c) => db.insert(schema.finding).values(c)),
    db.update(schema.apiKey).set({ lastUsedAt: new Date() }).where(eq(schema.apiKey.id, row.key.id)),
  ])

  const fps = [...new Set(findings.map((f) => f.fingerprint))]
  const insights = fps.length ? await blastRadius(orgId, fps) : []

  return json({
    success: true,
    scan_id: p.scan_id,
    dashboard_url: `${env.APP_URL}/app/scans/${scanId}`,
    new_findings_count: findings.length,
    message: `Synced ${findings.length} zero-knowledge finding(s) to Sentris Cloud.`,
    blast_radius_insights: insights,
  })
}

// Same fingerprint in more than one repo = one leaked credential, wider blast radius
export async function blastRadius(orgId: string, fps?: string[]) {
  const f = schema.finding
  const rows = await db
    .select({
      zk_fingerprint: f.fingerprint,
      rule_id: sql<string>`max(${f.ruleId})`,
      severity: sql<string>`max(${f.severity})`,
      redacted_preview: sql<string>`max(${f.preview})`,
      repos: sql<string>`group_concat(distinct ${f.repo})`,
      total_occurrences: sql<number>`count(*)`,
    })
    .from(f)
    .where(fps ? and(eq(f.orgId, orgId), inArray(f.fingerprint, fps.slice(0, 90))) : eq(f.orgId, orgId))
    .groupBy(f.fingerprint)
    .having(sql`count(distinct ${f.repo}) > 1`)
    .limit(50)
  return rows.map(({ repos, ...r }) => ({ ...r, affected_repos: repos.split(',') }))
}
