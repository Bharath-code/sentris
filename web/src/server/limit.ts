import type { Limiter } from './ingest-core.ts'

// A 429 when the binding says the key is over its window, else null. Windows are 10 or 60 s.
export async function limitedResponse(limiter: Limiter, key: string, seconds = 60): Promise<Response | null> {
  if ((await limiter.limit({ key })).success) return null
  return new Response('Too many requests', { status: 429, headers: { 'retry-after': String(seconds) } })
}
