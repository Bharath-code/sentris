import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mintKey, parseBearer } from './crypto.ts'

test('minted keys keep the org zkTag where the CLI reads its salt', () => {
  const { key } = mintKey('a1b2c3d4')
  assert.equal(key.slice(8, 16), 'a1b2c3d4')
  assert.equal(parseBearer(`Bearer ${key}`), key)
  assert.equal(parseBearer(`Bearer ${key}x`), null)
  assert.equal(parseBearer(null), null)
})
