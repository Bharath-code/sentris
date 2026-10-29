import { createMiddleware, createServerFn } from '@tanstack/react-start'
import { getRequest, getRequestHeaders } from '@tanstack/react-start/server'
import { redirect } from '@tanstack/react-router'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { env } from 'cloudflare:workers'
import { auth } from '@/server/auth'
import { db, schema } from '@/server/db'
import { ensureOrg } from '@/server/org'
import { assertConfig } from '@/server/config'
import { sameOrigin } from '@/server/guards'
import { createApiKey } from '@/server/keys'
import { getOverviewData, getScanPage } from '@/server/overview-core'
import { createCheckout, portalLink } from '@/server/billing'

export const getViewer = createServerFn({ method: 'GET' }).handler(async () => {
  const s = await auth.api.getSession({ headers: getRequestHeaders() })
  return s ? { name: s.user.name, email: s.user.email, image: s.user.image ?? null } : null
})

const authed = createMiddleware({ type: 'function' }).server(async ({ next }) => {
  assertConfig()
  // Session cookies ride along on cross-site requests, so refuse mutations that did not originate from this app
  if (!sameOrigin(getRequest(), env.APP_URL)) throw new Response('Forbidden', { status: 403 })
  const s = await auth.api.getSession({ headers: getRequestHeaders() })
  if (!s) throw redirect({ to: '/login' })
  const org = await ensureOrg(s.user)
  return next({ context: { user: s.user, org } })
})

export const getOverview = createServerFn({ method: 'GET' })
  .middleware([authed])
  .handler(async ({ context: { org } }) => ({
    org: { name: org.name, plan: org.plan, seats: org.seats, status: org.subscriptionStatus, periodEnd: org.currentPeriodEnd, hasBilling: !!org.dodoCustomerId },
    serverUrl: env.APP_URL,
    ...(await getOverviewData(db, org.id)),
  }))

export const getScan = createServerFn({ method: 'GET' })
  .middleware([authed])
  .validator(z.object({ id: z.string().max(40), offset: z.number().int().min(0).max(1_000_000).default(0) }))
  .handler(({ data, context: { org } }) => getScanPage(db, org.id, data.id, data.offset))

export const createKey = createServerFn({ method: 'POST' })
  .middleware([authed])
  .validator(z.object({ name: z.string().trim().min(1).max(60) }))
  .handler(async ({ data, context: { org } }) => {
    return createApiKey(db, org, data.name)
  })

export const revokeKey = createServerFn({ method: 'POST' })
  .middleware([authed])
  .validator(z.object({ id: z.string().max(40) }))
  .handler(async ({ data, context: { org } }) => {
    await db
      .update(schema.apiKey)
      .set({ revokedAt: new Date() })
      .where(and(eq(schema.apiKey.id, data.id), eq(schema.apiKey.orgId, org.id)))
  })

export const startCheckout = createServerFn({ method: 'POST' })
  .middleware([authed])
  .validator(z.object({ seats: z.number().int().min(1).max(500) }))
  .handler(async ({ data, context: { org, user } }) => ({ url: await createCheckout(org, user, data.seats) }))

export const openPortal = createServerFn({ method: 'POST' })
  .middleware([authed])
  .handler(async ({ context: { org } }) => ({ url: await portalLink(org) }))
