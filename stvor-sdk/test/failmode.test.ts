import { test, expect } from 'bun:test'
import { Stvor, generateKeyPair } from '../src/index.js'
import { signReceipt, kidOf, type ReceiptPayload } from '@stvor/core'

// Points at a closed port so every request is a transport failure fast.
const UNREACHABLE = 'http://127.0.0.1:9'

function client(onError?: 'allow' | 'deny' | 'throw') {
  return new Stvor({ apiKey: 'dev', baseUrl: UNREACHABLE, timeoutMs: 200, maxRetries: 0, onError })
}
const intent = { from: 'agentA', to: 'vendor', amount: '50.00', currency: 'USD' }

test('T8: fail-open (default "allow") → degraded ALLOW, never a real receipt', async () => {
  const res = await client('allow').verify(intent)
  expect(res.decision).toBe('ALLOW')
  expect(res.degraded).toBe(true)
  expect(res.reason).toBe('STVOR_UNREACHABLE')
  expect(res.receipt).toBeNull()
  expect(res.id).toBeNull()
})

test('T8: fail-closed ("deny") → degraded DENY', async () => {
  const res = await client('deny').verify(intent)
  expect(res.decision).toBe('DENY')
  expect(res.degraded).toBe(true)
})

test('T8: "throw" surfaces the transport error', async () => {
  await expect(client('throw').verify(intent)).rejects.toThrow()
})

test('T8: per-call onError overrides the client default', async () => {
  const res = await client('deny').verify(intent, { onError: 'allow' })
  expect(res.decision).toBe('ALLOW')
  expect(res.degraded).toBe(true)
})

test('offline verifyReceipt({ jwk }) makes zero network calls', async () => {
  const { privateJwk, publicJwk, kid } = await generateKeyPair()
  const payload: ReceiptPayload = {
    receiptId: 'rec_x', verificationId: 'ver_x', binding: 'attested', agentId: 'agentA',
    to: 'vendor', amount: '50.00', currency: 'USD', nonce: 'n', decision: 'ALLOW',
    reason: 'ATTESTED_OK', issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T00:05:00.000Z', kid,
  }
  const receipt = await signReceipt(payload, privateJwk)

  const realFetch = globalThis.fetch
  globalThis.fetch = (() => { throw new Error('network used') }) as unknown as typeof fetch
  try {
    const sdk = client('allow')
    expect(await sdk.verifyReceipt(receipt, { jwk: publicJwk })).toBe(true)
    expect(await sdk.verifyReceipt({ ...receipt, to: 'x' }, { jwk: publicJwk })).toBe(false)
  } finally {
    globalThis.fetch = realFetch
  }
})
