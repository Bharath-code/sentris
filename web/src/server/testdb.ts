// D1-shaped wrapper over node:sqlite so server logic runs against the real migrations in tests
import { DatabaseSync } from 'node:sqlite'
import { readdirSync, readFileSync } from 'node:fs'
import { drizzle } from 'drizzle-orm/d1'
import * as schema from './schema.ts'

type Param = string | number | null

class Stmt {
  params: Param[] = []
  sqlite: DatabaseSync
  sql: string
  constructor(sqlite: DatabaseSync, sql: string) {
    this.sqlite = sqlite
    this.sql = sql
  }
  bind(...p: unknown[]) {
    // D1 rejects statements with more than 100 bound parameters; fail the same way here
    if (p.length > 100) throw new Error('D1_ERROR: too many SQL variables')
    this.params = p.map((v) => (v === undefined ? null : (v as Param)))
    return this
  }
  prep(arrays: boolean) {
    const s = this.sqlite.prepare(this.sql)
    s.setReturnArrays(arrays)
    return s
  }
  async all() {
    return { results: this.prep(false).all(...this.params) as Record<string, unknown>[], success: true, meta: {} }
  }
  async raw() {
    return this.prep(true).all(...this.params) as unknown as unknown[][]
  }
  async run() {
    const r = this.sqlite.prepare(this.sql).run(...this.params)
    return { results: [], success: true, meta: { changes: Number(r.changes) } }
  }
  async first() {
    return (await this.all()).results[0] ?? null
  }
}

export function testDb() {
  const sqlite = new DatabaseSync(':memory:')
  sqlite.exec('PRAGMA foreign_keys = ON')
  const dir = new URL('../../drizzle/', import.meta.url)
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort())
    for (const stmt of readFileSync(new URL(f, dir), 'utf8').split('--> statement-breakpoint')) sqlite.exec(stmt)

  const d1 = {
    prepare: (sql: string) => new Stmt(sqlite, sql),
    async batch(stmts: Stmt[]) {
      sqlite.exec('BEGIN')
      try {
        const out = []
        for (const s of stmts) out.push(/^\s*(select|with)/i.test(s.sql) ? await s.all() : await s.run())
        sqlite.exec('COMMIT')
        return out
      } catch (e) {
        sqlite.exec('ROLLBACK')
        throw e
      }
    },
  }
  return { db: drizzle(d1 as unknown as D1Database, { schema }), sqlite }
}
