import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { db, schema } from './db'
import { randomHex } from './crypto'
import { canIngest as canIngestOrg } from './guards'

export type Org = typeof schema.org.$inferSelect

export async function ensureOrg(u: { id: string; name: string }): Promise<Org> {
  const existing = await db.query.org.findFirst({ where: eq(schema.org.ownerId, u.id) })
  if (existing) return existing
  const [created] = await db
    .insert(schema.org)
    .values({ id: `org_${randomHex(8)}`, name: `${u.name}'s team`, ownerId: u.id, zkTag: randomHex(4) })
    .onConflictDoNothing()
    .returning()
  return created ?? (await db.query.org.findFirst({ where: eq(schema.org.ownerId, u.id) }))!
}

export const canIngest = (org: Org, now = Date.now()) => canIngestOrg(org, env.BETA_FREE_SYNC_UNTIL, now)
