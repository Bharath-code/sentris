import { and, eq, isNull } from 'drizzle-orm'
import { db, schema } from './db'
import { parseBearer, sha256 } from './crypto'
import { canIngest } from './org'

// Lets the CLI show the real org instead of guessing: `sentris auth login` calls this to validate the key
export async function handleMe(request: Request): Promise<Response> {
  const token = parseBearer(request.headers.get('authorization'))
  if (!token) return Response.json({ message: 'Missing or malformed API key.' }, { status: 401 })

  const row = await db
    .select({ org: schema.org, owner: schema.user })
    .from(schema.apiKey)
    .innerJoin(schema.org, eq(schema.apiKey.orgId, schema.org.id))
    .innerJoin(schema.user, eq(schema.org.ownerId, schema.user.id))
    .where(and(eq(schema.apiKey.hash, await sha256(token)), isNull(schema.apiKey.revokedAt)))
    .get()
  if (!row) return Response.json({ message: 'API key is invalid or revoked.' }, { status: 401 })

  const { org, owner } = row
  return Response.json({
    org_id: `org_${org.zkTag}`,
    org_name: org.name,
    plan: org.plan,
    seats: org.seats,
    sync_enabled: canIngest(org),
    owner_email: owner.email,
  })
}
