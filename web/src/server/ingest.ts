import { env } from 'cloudflare:workers'
import { db } from './db'
import { assertConfig } from './config'
import * as core from './ingest-core.ts'

export const handleScanUpload = (request: Request) => {
  assertConfig()
  return core.handleScanUpload(request, {
    db,
    appUrl: env.APP_URL,
    betaUntil: env.BETA_FREE_SYNC_UNTIL,
    ipLimiter: env.INGEST_IP_LIMITER,
    keyLimiter: env.INGEST_KEY_LIMITER,
  })
}

export const blastRadius = (orgId: string, fps?: string[]) => core.blastRadius(db, orgId, fps)
