import { test, expect } from 'bun:test'
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const FIXTURES = join(import.meta.dir, '..', '..', 'fixtures')
const CLI = join(import.meta.dir, '..', 'src', 'cli.ts')
const JWK = join(FIXTURES, 'issuer.jwk')
const receiptVectors = JSON.parse(readFileSync(join(FIXTURES, 'receipt-vectors.json'), 'utf8')) as any[]

const dir = mkdtempSync(join(tmpdir(), 'stvor-cli-'))

function runCli(receipt: unknown): { code: number; out: string } {
  const p = join(dir, `r_${Math.random().toString(36).slice(2)}.json`)
  writeFileSync(p, JSON.stringify(receipt))
  const proc = Bun.spawnSync(['bun', 'run', CLI, p, '--jwk', JWK])
  return { code: proc.exitCode, out: proc.stdout.toString() + proc.stderr.toString() }
}

test('CLI: valid receipt → OK, exit 0', () => {
  const valid = receiptVectors.find((v) => v.name === 'valid-allow')!
  const { code, out } = runCli(valid.receipt)
  expect(code).toBe(0)
  expect(out).toContain('OK')
  expect(out).toContain('decision=ALLOW')
})

test('CLI: tampered receipt → FAIL, exit 1', () => {
  const bad = receiptVectors.find((v) => v.name === 'tampered-to')!
  const { code, out } = runCli(bad.receipt)
  expect(code).toBe(1)
  expect(out).toContain('FAIL')
})

test('CLI: unknown kid → FAIL UNKNOWN_KEY, exit 1', () => {
  const bad = receiptVectors.find((v) => v.name === 'unknown-kid')!
  const { code, out } = runCli(bad.receipt)
  expect(code).toBe(1)
  expect(out).toContain('UNKNOWN_KEY')
})
