import { test, expect } from 'bun:test'
import {
  canonicalize,
  sha256Hex,
  generateKeyPair,
  signCanonical,
  verifyCanonical,
  hashPaymentPayload,
  paymentPayloadOf,
  signReceipt,
  verifyReceiptOffline,
  kidOf,
  type ReceiptPayload,
  type EcJwk,
  type KeyRegistry,
} from '../src/index.js'

test('RFC 8785: key order and number/string are not the same', async () => {
  // canonical form sorts keys
  expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}')
  // "50.00" (string) and 50 (number) canonicalize differently — this is the whole point
  expect(canonicalize({ amount: '50.00' })).not.toBe(canonicalize({ amount: 50 }))
})

test('amount must be a decimal string, not a float', () => {
  expect(() => paymentPayloadOf({ to: 'x', amount: 50 as unknown as string })).toThrow()
  expect(() => paymentPayloadOf({ to: 'x', amount: '50.00' })).not.toThrow()
  // absent optionals are omitted, never null
  expect(paymentPayloadOf({ to: 'x' })).toEqual({ to: 'x' })
})

test('payment hash is stable and field-sensitive', async () => {
  const a = await hashPaymentPayload({ to: 'alice', amount: '50.00', currency: 'USD' })
  const b = await hashPaymentPayload({ to: 'bob', amount: '50.00', currency: 'USD' })
  const a2 = await hashPaymentPayload({ currency: 'USD', to: 'alice', amount: '50.00' })
  expect(a).toBe(a2) // field order in input does not matter
  expect(a).not.toBe(b) // destination does
})

test('ES256 sign/verify round-trips over canonical bytes', async () => {
  const { privateJwk, publicJwk } = await generateKeyPair()
  const payload = { z: '1', a: '2', nested: { y: true, x: false } }
  const sig = await signCanonical(payload, privateJwk)
  expect(await verifyCanonical(payload, sig, publicJwk)).toBe(true)
  expect(await verifyCanonical({ ...payload, a: 'TAMPERED' }, sig, publicJwk)).toBe(false)
})

async function sampleReceipt(): Promise<{ receipt: any; pub: EcJwk }> {
  const { privateJwk, publicJwk, kid } = await generateKeyPair()
  const payload: ReceiptPayload = {
    receiptId: 'rec_1',
    verificationId: 'ver_1',
    binding: 'committed',
    agentId: 'agent_1',
    to: 'vendor_api_credits',
    amount: '50.00',
    currency: 'USD',
    nonce: 'n1',
    decision: 'ALLOW',
    reason: 'payload matched commitment',
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T00:05:00.000Z',
    kid,
    commitmentId: 'cmt_1',
  }
  const receipt = await signReceipt(payload, privateJwk)
  return { receipt, pub: publicJwk }
}

test('receipt verifies offline with only the JWK', async () => {
  const { receipt, pub } = await sampleReceipt()
  const res = await verifyReceiptOffline(receipt, pub)
  expect(res.ok).toBe(true)
})

test('flipping `to` breaks the receipt', async () => {
  const { receipt, pub } = await sampleReceipt()
  const res = await verifyReceiptOffline({ ...receipt, to: '0xattacker' }, pub)
  expect(res.ok).toBe(false)
  if (!res.ok) expect(res.reason).toBe('BAD_SIGNATURE')
})

test('flipping `amount` breaks the receipt', async () => {
  const { receipt, pub } = await sampleReceipt()
  const res = await verifyReceiptOffline({ ...receipt, amount: '5000.00' }, pub)
  expect(res.ok).toBe(false)
})

test('unknown kid → UNKNOWN_KEY, never a silent pass', async () => {
  const { receipt } = await sampleReceipt()
  const other = await generateKeyPair()
  const res = await verifyReceiptOffline(receipt, other.publicJwk)
  expect(res.ok).toBe(false)
  if (!res.ok) expect(res.reason).toBe('UNKNOWN_KEY')
})

test('keyset resolves the right key by kid across rotation', async () => {
  const { receipt, pub } = await sampleReceipt()
  const rotatedTo = await generateKeyPair()
  const registry: KeyRegistry = {
    keys: [
      { kid: rotatedTo.kid, jwk: rotatedTo.publicJwk, notBefore: '2026-02-01T00:00:00.000Z' },
      { kid: pub.kid!, jwk: pub, notBefore: '2026-01-01T00:00:00.000Z', notAfter: '2026-02-01T00:00:00.000Z' },
    ],
  }
  const res = await verifyReceiptOffline(receipt, registry)
  expect(res.ok).toBe(true) // old receipt still verifies against the retired key in the set
})
