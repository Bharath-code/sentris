import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { db, schema } from './db'
import { randomHex } from './crypto'

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

// Deny by default: only paid/trialing Pro orgs inside their billing period may sync.
// BETA_FREE_SYNC="true" deliberately opens sync to free orgs during the beta.
export function canIngest(org: Org, now = Date.now()): boolean {
  if (env.BETA_FREE_SYNC === 'true') return true
  const paid = org.plan === 'pro' && org.subscriptionStatus === 'active'
  return paid && (!org.currentPeriodEnd || org.currentPeriodEnd.getTime() > now)
}
