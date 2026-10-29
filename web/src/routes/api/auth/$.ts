import { createFileRoute } from '@tanstack/react-router'
import { env } from 'cloudflare:workers'
import { auth } from '@/server/auth'
import { assertConfig } from '@/server/config'
import { limitedResponse } from '@/server/limit'

const handle = async (request: Request) => {
  assertConfig()
  return (await limitedResponse(env.AUTH_IP_LIMITER, request.headers.get('cf-connecting-ip') ?? 'unknown')) ?? auth.handler(request)
}

export const Route = createFileRoute('/api/auth/$')({
  server: { handlers: { GET: ({ request }) => handle(request), POST: ({ request }) => handle(request) } },
})
