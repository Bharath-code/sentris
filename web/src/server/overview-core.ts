import { and, asc, count, desc, eq, gte, isNull, sql } from 'drizzle-orm'
import * as schema from './schema.ts'
import { blastRadius, type Db } from './ingest-core.ts'
import { FINDINGS_PAGE, RECENT_SCANS } from './guards.ts'

const WINDOW_DAYS = 30

// Severity totals come from the per-scan rollup, so cost follows scans in the window, not findings stored
export async function getOverviewData(db: Db, orgId: string, now = Date.now()) {
  const since = new Date(now - WINDOW_DAYS * 864e5)
  const [scans, keys, totals, bySeverity, radius] = await Promise.all([
    db.query.scan.findMany({ where: eq(schema.scan.orgId, orgId), orderBy: desc(schema.scan.createdAt), limit: RECENT_SCANS }),
    db.query.apiKey.findMany({
      where: and(eq(schema.apiKey.orgId, orgId), isNull(schema.apiKey.revokedAt)),
      columns: { hash: false },
      orderBy: desc(schema.apiKey.createdAt),
    }),
    db
      .select({ scans: count(), files: sql<number>`coalesce(sum(${schema.scan.filesScanned}),0)`, findings: sql<number>`coalesce(sum(${schema.scan.findingsCount}),0)` })
      .from(schema.scan)
      .where(and(eq(schema.scan.orgId, orgId), gte(schema.scan.createdAt, since)))
      .get(),
    db
      .select({ severity: schema.scanSeverity.severity, n: sql<number>`sum(${schema.scanSeverity.n})` })
      .from(schema.scanSeverity)
      .where(and(eq(schema.scanSeverity.orgId, orgId), gte(schema.scanSeverity.createdAt, since)))
      .groupBy(schema.scanSeverity.severity),
    blastRadius(db, orgId),
  ])
  return { scans, keys, totals: totals ?? { scans: 0, files: 0, findings: 0 }, bySeverity, radius }
}

const severityOrder = sql`case lower(${schema.finding.severity}) when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end`

// Findings are paged in a stable order (worst first, then location) so "next" never skips or repeats a row
export async function getScanPage(db: Db, orgId: string, id: string, offset = 0) {
  const scan = await db.query.scan.findFirst({ where: and(eq(schema.scan.id, id), eq(schema.scan.orgId, orgId)) })
  if (!scan) throw new Error('Scan not found')
  const findings = await db
    .select()
    .from(schema.finding)
    .where(eq(schema.finding.scanId, scan.id))
    .orderBy(severityOrder, asc(schema.finding.filePath), asc(schema.finding.line), asc(schema.finding.id))
    .limit(FINDINGS_PAGE)
    .offset(offset)
  return { scan, findings, offset, total: scan.findingsCount, pageSize: FINDINGS_PAGE }
}
