import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { withSecurityHeaders } from '@/server/headers'

export default createServerEntry({
  async fetch(request) {
    return withSecurityHeaders(await handler.fetch(request))
  },
})
