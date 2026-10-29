import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import * as schema from './schema.ts'
import type { Db } from './ingest-core.ts'

export type AuthConfig = { appUrl: string; secret: string; githubId: string; githubSecret: string }

export function createAuth(c: AuthConfig, db: Db, plugins: Parameters<typeof betterAuth>[0]['plugins'] = []) {
  const https = c.appUrl.startsWith('https://')
  return betterAuth({
    baseURL: c.appUrl,
    secret: c.secret,
    database: drizzleAdapter(db, { provider: 'sqlite', schema }),
    socialProviders: { github: { clientId: c.githubId, clientSecret: c.githubSecret } },
    account: { encryptOAuthTokens: true },
    advanced: {
      useSecureCookies: https,
      // lax, not strict: the GitHub redirect back to /callback is a cross-site navigation and must carry the state cookie
      defaultCookieAttributes: { httpOnly: true, secure: https, sameSite: 'lax' },
      ipAddress: { ipAddressHeaders: ['cf-connecting-ip'] },
    },
    // In-memory counters are per isolate and reset constantly on Workers, so keep them in D1
    rateLimit: { enabled: true, storage: 'database', window: 60, max: 100, customRules: { '/sign-in/social': { window: 60, max: 10 } } },
    plugins,
  })
}
