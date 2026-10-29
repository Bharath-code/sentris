import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { testDb } from './testdb.ts'

test('migrations apply and enforce one scan per (org, cli_scan_id)', () => {
  const { sqlite } = testDb()
  sqlite.exec("insert into user (id,name,email,email_verified,created_at,updated_at) values ('u','n','e',0,0,0)")
  sqlite.exec("insert into org (id,name,owner_id,zk_tag,plan,seats,created_at) values ('o','o','u','tag','free',1,0)")
  const ins = "insert into scan (id,org_id,cli_scan_id,repo,branch,files_scanned,duration_ms,findings_count,created_at) values (?, 'o', 'same', 'r','b',1,1,0,0)"
  sqlite.prepare(ins).run('s1')
  assert.throws(() => sqlite.prepare(ins).run('s2'), /UNIQUE/)
})

test('0002 dedupes scans that were re-synced before the unique index existed', () => {
  const sqlite = new DatabaseSync(':memory:')
  sqlite.exec('PRAGMA foreign_keys = ON')
  const dir = new URL('../../drizzle/', import.meta.url)
  const run = (f: string) => readFileSync(new URL(f, dir), 'utf8').split('--> statement-breakpoint').forEach((s) => sqlite.exec(s))
  run('0000_init.sql')
  run('0001_billing_event_at.sql')
  sqlite.exec("insert into user (id,name,email,email_verified,created_at,updated_at) values ('u','n','e',0,0,0)")
  sqlite.exec("insert into org (id,name,owner_id,zk_tag,plan,seats,created_at) values ('o','o','u','tag','free',1,0)")
  for (const id of ['s1', 's2'])
    sqlite.exec(`insert into scan (id,org_id,cli_scan_id,repo,branch,files_scanned,duration_ms,findings_count,created_at) values ('${id}','o','dup','r','b',1,1,1,0)`)
  for (const id of ['s1', 's2'])
    sqlite.exec(`insert into finding (id,org_id,scan_id,repo,fingerprint,rule_id,severity,file_path,line,entropy,preview,created_at) values ('f${id}','o','${id}','r','fp','r','low','a',1,1,'x',0)`)

  run('0002_hardening.sql')

  assert.deepEqual(sqlite.prepare('select id from scan').all().map((r) => r.id), ['s1'])
  assert.deepEqual(sqlite.prepare('select id from finding').all().map((r) => r.id), ['fs1'])
})
