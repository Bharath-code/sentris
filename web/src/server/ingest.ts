import { env } from 'cloudflare:workers'
import { db } from './db'
import { assertConfig } from './config'
import { event } from './log'
import * as core from './ingest-core.ts'

// One log line per upload: status for the 401/402/429 counts, the server's own message as the reason
export const handleScanUpload = async (request: Request) => {
  assertConfig()
  try {
    const res = await core.handleScanUpload(request, {
      db,
      appUrl: env.APP_URL,
      betaUntil: env.BETA_FREE_SYNC_UNTIL,
      ipLimiter: env.INGEST_IP_LIMITER,
      keyLimiter: env.INGEST_KEY_LIMITER,
    })
    const reason = res.ok ? undefined : ((await res.clone().json().catch(() => null)) as { message?: string } | null)?.message
    event('ingest', { status: res.status, reason })
    return res
  } catch (err) {
    event('ingest', { status: 500, reason: 'unhandled error', error: String(err) })
    throw err
  }
}
