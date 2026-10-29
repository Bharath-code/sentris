// One JSON object per line: Workers observability indexes the fields, so counts and alerts can group by event/status/reason.
// Never pass key material, tokens or finding contents here.
export type Fields = Record<string, string | number | boolean | null | undefined>
export type Logger = { info(line: string): void; warn(line: string): void; error(line: string): void }

export const event = (name: string, fields: Fields = {}, out: Logger = console) => {
  const level = typeof fields.status === 'number' && fields.status >= 500 ? 'error' : fields.status === 401 || fields.status === 402 || fields.status === 429 || fields.reason ? 'warn' : 'info'
  out[level](JSON.stringify({ event: name, ...fields }))
}
