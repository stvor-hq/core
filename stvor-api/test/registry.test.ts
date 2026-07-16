import { test, expect } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dir = mkdtempSync(join(tmpdir(), 'stvor-reg-'))
process.env.STVOR_KEYS_FILE = join(dir, 'keys.json')

const { registerCurrentKey, getRegistry } = await import('../src/registry.js')
const { generateKeyPair, signReceipt, verifyReceiptOffline } = await import('@stvor/core')

test('T7: a receipt survives key rotation via the append-only keyset', async () => {
  // Pin a fresh keyset file at call time (env is process-global across test files).
  process.env.STVOR_KEYS_FILE = join(dir, 'keys.json')

  // Key #1 signs a receipt while current.
  const k1 = await generateKeyPair()
  registerCurrentKey(k1.kid, { kty: 'EC', crv: 'P-256', x: k1.publicJwk.x, y: k1.publicJwk.y })
  const receipt = await signReceipt(
    {
      receiptId: 'rec_r', verificationId: 'ver_r', binding: 'attested', agentId: 'a',
      to: 'vendor', amount: '1.00', currency: 'USD', nonce: 'n', decision: 'ALLOW',
      reason: 'ATTESTED_OK', issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-01-01T00:05:00.000Z', kid: k1.kid,
    },
    k1.privateJwk
  )

  // Rotate: key #2 becomes current. Registry retires #1, keeps it.
  const k2 = await generateKeyPair()
  registerCurrentKey(k2.kid, { kty: 'EC', crv: 'P-256', x: k2.publicJwk.x, y: k2.publicJwk.y })

  const reg = getRegistry()
  expect(reg.keys.length).toBe(2)
  const e1 = reg.keys.find((k) => k.kid === k1.kid)!
  const e2 = reg.keys.find((k) => k.kid === k2.kid)!
  expect(e1.notAfter).toBeDefined() // retired
  expect(e2.notAfter).toBeUndefined() // current

  // The year-old receipt still verifies against the published keyset.
  const ok = await verifyReceiptOffline(receipt, reg)
  expect(ok.ok).toBe(true)

  // Sanity: it resolves by kid, not by "any key we hold" — a keyset without #1 fails.
  const onlyK2 = { keys: [e2] }
  const miss = await verifyReceiptOffline(receipt, onlyK2)
  expect(miss.ok).toBe(false)
  if (!miss.ok) expect(miss.reason).toBe('UNKNOWN_KEY')
})
