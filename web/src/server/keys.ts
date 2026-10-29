import { sql } from 'drizzle-orm'
import type { Db } from './ingest-core.ts'
import { MAX_ACTIVE_KEYS } from './guards.ts'
import { mintKey, randomHex, sha256 } from './crypto.ts'

// The cap is checked inside the INSERT so concurrent requests cannot both slip past it
export async function createApiKey(db: Db, org: { id: string; zkTag: string }, name: string, now = Date.now()) {
  const { key, preview } = mintKey(org.zkTag)
  const res = await db.run(sql`
    INSERT INTO api_key (id, org_id, name, preview, hash, created_at)
    SELECT ${`key_${randomHex(8)}`}, ${org.id}, ${name}, ${preview}, ${await sha256(key)}, ${now}
    WHERE (SELECT count(*) FROM api_key WHERE org_id = ${org.id} AND revoked_at IS NULL) < ${MAX_ACTIVE_KEYS}`)
  if (!res.meta.changes) throw new Error(`You can have at most ${MAX_ACTIVE_KEYS} active API keys. Revoke one first.`)
  return { key }
}
