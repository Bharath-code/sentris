const hex = (buf: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')

export const randomHex = (bytes: number) => hex(crypto.getRandomValues(new Uint8Array(bytes)))

export const sha256 = async (s: string) =>
  hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))

// sp_live_<zkTag:8><secret:40>. The CLI shows "org_" + chars 8..16 as its org id.
// Not a salt: fingerprints are keyed by a team secret that never reaches this server.
export const mintKey = (zkTag: string) => {
  const key = `sp_live_${zkTag}${randomHex(20)}`
  return { key, preview: `${key.slice(0, 16)}…${key.slice(-4)}` }
}

export const parseBearer = (h: string | null) => {
  const m = h?.match(/^Bearer\s+(sp_live_[0-9a-f]{48})$/)
  return m?.[1] ?? null
}
