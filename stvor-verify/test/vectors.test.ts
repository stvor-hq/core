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
  jwkThumbprint,
  type KeyRegistry,
} from '@stvor/core'

const FIXTURES = join(import.meta.dir, '..', '..', 'fixtures')
const readJson = (name: string) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'))

const keyset = readJson('keyset.json') as KeyRegistry
const issuerJwk = readJson('issuer.jwk')
const canonicalVectors = readJson('canonical-vectors.json') as any[]
const receiptVectors = readJson('receipt-vectors.json') as any[]
const thumbprintVectors = readJson('thumbprint-vectors.json') as any[]

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
    // agent-committed OK vectors must report the agent signature as valid too
    if (v.agentSignature) expect(res.agentSignature).toBe(v.agentSignature)
  }
})

test('E4/E7: agent-committed vectors verify BOTH signatures from the receipt alone', async () => {
  const ac = receiptVectors.filter((v) => v.name.includes('agent-committed') && v.expected === 'OK')
  expect(ac.length).toBeGreaterThanOrEqual(2) // Ed25519 + P-256
  for (const v of ac) {
    const res = await verifyReceiptOffline(v.receipt, keyset)
    expect(res.ok).toBe(true)
    expect(res.issuerSignature).toBe('valid')
    expect(res.agentSignature).toBe('valid')
    expect(res.receipt!.agentPubkey).toBeDefined() // the embedded key is what makes this possible
  }
})

test('E3: cross-algorithm vector (Ed25519 sig declared P-256) FAILS the agent check', async () => {
  const v = receiptVectors.find((x) => x.name === 'cross-alg-ed25519-sig-as-p256')!
  const res = await verifyReceiptOffline(v.receipt, keyset)
  expect(res.ok).toBe(false)
  expect(res.issuerSignature).toBe('valid') // issuer is fine
  expect(res.agentSignature).toBe('invalid') // the confusion is caught, not probed
})

test('E6: RFC 7638 thumbprint vectors (EC and OKP) reproduce', async () => {
  for (const v of thumbprintVectors) {
    expect(await jwkThumbprint(v.jwk)).toBe(v.thumbprint)
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
    expect((await verifyReceiptOffline(valid.receipt, keyset)).ok).toBe(true)
    // Ed25519 agent-committed too — @noble runs pure-JS, no network, no WebCrypto
    const ed = receiptVectors.find((v) => v.name === 'ed25519-agent-committed-valid')!
    const res = await verifyReceiptOffline(ed.receipt, keyset)
    expect(res.ok).toBe(true)
    expect(res.agentSignature).toBe('valid')
  } finally {
    globalThis.fetch = realFetch
  }
})
