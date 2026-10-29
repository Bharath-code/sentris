import { env } from 'cloudflare:workers'
import { betaActive, configProblems } from './guards'

let checked = false

// Lazy: secrets don't exist at build/prerender time, so this runs on the first request instead of at import
export function assertConfig() {
  if (checked) return
  const problems = configProblems({ secret: env.BETTER_AUTH_SECRET, appUrl: env.APP_URL, dodoEnv: env.DODO_ENV, productId: env.DODO_PRO_PRODUCT_ID })
  if (problems.length) throw new Error(`Sentris is misconfigured: ${problems.join('; ')}`)
  if (betaActive(env.BETA_FREE_SYNC_UNTIL)) console.warn(`Beta: free orgs may sync until ${env.BETA_FREE_SYNC_UNTIL}`)
  checked = true
}
