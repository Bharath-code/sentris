import { env } from 'cloudflare:workers'
import { tanstackStartCookies } from 'better-auth/tanstack-start'
import { db } from './db'
import { createAuth } from './auth-core.ts'

export const auth = createAuth(
  { appUrl: env.APP_URL, secret: env.BETTER_AUTH_SECRET, githubId: env.GITHUB_CLIENT_ID, githubSecret: env.GITHUB_CLIENT_SECRET },
  db,
  [tanstackStartCookies()],
)
