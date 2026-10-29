// Inline scripts stay allowed: TanStack Start streams per-request hydration scripts (and prerendered pages bake
// build-specific ones), so a hash allowlist cannot cover them. Everything else is locked to this origin.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https://avatars.githubusercontent.com",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ')

export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CSP,
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
}

// Per-user HTML, server-function payloads and auth/API responses must never sit in a shared or back/forward cache
const PRIVATE_PATH = /^\/(app|_serverFn|api)(\/|$)/

// Responses from fetch() and Response.redirect() have immutable headers, so copy before setting
export function withSecurityHeaders(res: Response, pathname = ''): Response {
  const out = new Response(res.body, res)
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v)
  if (PRIVATE_PATH.test(pathname) && !out.headers.has('Cache-Control')) out.headers.set('Cache-Control', 'private, no-store')
  return out
}

// Static assets and prerendered pages bypass the Worker, so Cloudflare reads these from public/_headers
export const headersFile = () =>
  `/*\n${Object.entries(SECURITY_HEADERS).map(([k, v]) => `  ${k}: ${v}`).join('\n')}\n`
