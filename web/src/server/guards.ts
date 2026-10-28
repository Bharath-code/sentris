// Pure request/billing guards, kept free of Worker imports so node --test can load them

// Content-Length can be absent (chunked) or lie, so count bytes as they stream in
export async function readCapped(request: Request, max: number): Promise<string | null> {
  if (Number(request.headers.get('content-length') ?? 0) > max) return null
  const reader = request.body?.getReader()
  if (!reader) return ''
  const parts: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > max) {
      await reader.cancel()
      return null
    }
    parts.push(value)
  }
  const buf = new Uint8Array(size)
  let o = 0
  for (const p of parts) buf.set(p, (o += p.byteLength) - p.byteLength)
  return new TextDecoder().decode(buf)
}

type BillingState = { dodoSubscriptionId: string | null; billingEventAt: Date | null }

// Drop events older than the last one applied, and never let a different
// (e.g. previously cancelled) subscription's end event downgrade the current one.
export function shouldApply(org: BillingState, subscriptionId: string, ending: boolean, at: Date): boolean {
  const prev = org.billingEventAt?.getTime()
  // Ties fail closed: an end event wins over an activation stamped the same instant
  if (prev !== undefined && (at.getTime() < prev || (at.getTime() === prev && !ending))) return false
  if (ending && org.dodoSubscriptionId && org.dodoSubscriptionId !== subscriptionId) return false
  return true
}
