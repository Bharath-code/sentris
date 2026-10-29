import { sql } from 'drizzle-orm'
import { RETENTION_DAYS } from './guards.ts'
import type { Db } from './ingest-core.ts'

const BATCH = 100
const MAX_ROUNDS = 200
const WEBHOOK_KEEP_DAYS = 30

// Deleting a scan cascades to its findings and rollup rows, so work is capped per statement and per run;
// whatever is left over is picked up by the next scheduled run.
export async function purgeExpired(db: Db, now = Date.now()) {
  const removed = { free: 0, pro: 0, webhooks: 0 }
  for (const plan of ['free', 'pro'] as const) {
    const cutoff = now - RETENTION_DAYS[plan] * 864e5
    for (let i = 0; i < MAX_ROUNDS; i++) {
      const r = await db.run(sql`DELETE FROM scan WHERE id IN (
        SELECT s.id FROM scan s JOIN org o ON o.id = s.org_id
        WHERE o.plan = ${plan} AND s.created_at < ${cutoff} LIMIT ${BATCH})`)
      const n = Number(r.meta?.changes ?? 0)
      removed[plan] += n
      if (n < BATCH) break
    }
  }
  const w = await db.run(sql`DELETE FROM webhook_event WHERE applied_at < ${now - WEBHOOK_KEEP_DAYS * 864e5}`)
  removed.webhooks = Number(w.meta?.changes ?? 0)
  return removed
}
