import { test, expect } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  verifyReceiptOffline,
  canonicalize,
  canonicalBytes,
  bytesToHex,
  sha256Hex,
  paymentPayloadOf,
  type KeyRegistry,
} from '@stvor/core'

const FIXTURES = join(import.meta.dir, '..', '..', 'fixtures')
const readJson = (name: string) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'))

const keyset = readJson('keyset.json') as KeyRegistry
const issuerJwk = readJson('issuer.jwk')
const canonicalVectors = readJson('canonical-vectors.json') as any[]
const receiptVectors = readJson('receipt-vectors.json') as any[]

test('canonical vectors are reproducible byte-for-byte (serializer self-check)', async () => {
  for (const v of canonicalVectors) {
    const payload = paymentPayloadOf(v.input)
    expect(canonicalize(payload)).toBe(v.canonical)
    expect(bytesToHex(canonicalBytes(payload))).toBe(v.canonicalHex)
    expect(await sha256Hex(canonicalBytes(payload))).toBe(v.sha256)
  }
})

test('receipt vectors verify offline against the keyset', async () => {
  for (const v of receiptVectors) {
    const res = await verifyReceiptOffline(v.receipt, keyset)
    expect(res.ok, `vector ${v.name} expected ${v.expected}`).toBe(v.expected === 'OK')
    if (!res.ok && v.reason) expect(res.reason).toBe(v.reason)
  }
})

test('valid vectors also verify against the single issuer JWK', async () => {
  for (const v of receiptVectors.filter((x) => x.expected === 'OK')) {
    const res = await verifyReceiptOffline(v.receipt, issuerJwk)
    expect(res.ok).toBe(true)
  }
})

test('verification uses ZERO network — works with fetch disabled', async () => {
  const realFetch = globalThis.fetch
  // Any network access during verification is a bug — make it explode.
  globalThis.fetch = (() => {
    throw new Error('network access during offline verification')
  }) as unknown as typeof fetch
  try {
    const valid = receiptVectors.find((v) => v.name === 'valid-allow')!
    const res = await verifyReceiptOffline(valid.receipt, keyset)
    expect(res.ok).toBe(true)
  } finally {
    globalThis.fetch = realFetch
  }
})
