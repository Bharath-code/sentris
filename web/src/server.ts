import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { withSecurityHeaders } from '@/server/headers'
import { db } from '@/server/db'
import { purgeExpired } from '@/server/retention-core'
import { event } from '@/server/log'

const entry = createServerEntry({
  async fetch(request) {
    return withSecurityHeaders(await handler.fetch(request))
  },
})

export default {
  ...entry,
  // Daily (see wrangler.jsonc triggers): drop scans past plan retention
  async scheduled(_controller: ScheduledController, _env: unknown, ctx: ExecutionContext) {
    ctx.waitUntil(
      purgeExpired(db).then(
        (removed) => event('retention', { status: 200, ...removed }),
        (err) => {
          event('retention', { status: 500, reason: 'purge failed', error: String(err) })
          throw err
        },
      ),
    )
  },
}
