import { test, expect, beforeAll } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Isolated DB + key files, set BEFORE importing anything that reads them.
const dir = mkdtempSync(join(tmpdir(), 'stvor-flow-'))
process.env.STVOR_DB = join(dir, 'test.db')
process.env.STVOR_SIGNING_KEY_FILE = join(dir, 'signing-key.pem')
process.env.STVOR_KEYS_FILE = join(dir, 'keys.json')
process.env.STVOR_DEV = '1' // local open mode is now opt-in, not inferred
delete process.env.NODE_ENV
delete process.env.STVOR_KEY

const { buildApp } = await import('../src/app.js')
const { store } = await import('../src/store.js')
const { newClientKey } = await import('../src/clientkeys.js')
const {
  generateKeyPair,
  signCanonical,
  commitmentSigningPayload,
  hashPaymentPayload,
  verifyReceiptOffline,
} = await import('@stvor/core')

let app: Awaited<ReturnType<typeof buildApp>>
let issuerJwk: any

beforeAll(async () => {
  // Re-pin our files in case another test file mutated the shared env at eval time.
  process.env.STVOR_KEYS_FILE = join(dir, 'keys.json')
  app = await buildApp({ logger: false, rateLimit: false })
  const res = await app.inject({ method: 'GET', url: '/.well-known/public-key' })
  issuerJwk = res.json()
})

async function post(url: string, body: unknown, key?: string) {
  const headers = key ? { authorization: `Bearer ${key}` } : undefined
  const res = await app.inject({ method: 'POST', url, payload: body as object, headers })
  return { status: res.statusCode, body: res.json() as any }
}
async function get(url: string, key?: string) {
  const headers = key ? { authorization: `Bearer ${key}` } : undefined
  const res = await app.inject({ method: 'GET', url, headers })
  return { status: res.statusCode, body: res.json() as any }
}

test('attested verify returns an inline signed receipt that verifies offline', async () => {
  const { status, body } = await post('/verify', {
    intent: { from: 'agentA', to: 'vendor', amount: '50.00', currency: 'USD' },
  })
  expect(status).toBe(200)
  expect(body.decision).toBe('ALLOW')
  expect(body.binding).toBe('attested')
  expect(body.receipt).toBeDefined()
  expect(body.receipt.to).toBe('vendor')
  expect(body.receipt.amount).toBe('50.00')

  const v = await verifyReceiptOffline(body.receipt, issuerJwk)
  expect(v.ok).toBe(true)
})

test('T1: flipping to / amount / currency breaks the receipt', async () => {
  const { body } = await post('/verify', {
    intent: { from: 'agentA', to: 'vendor', amount: '50.00', currency: 'USD' },
  })
  for (const mut of [{ to: '0xattacker' }, { amount: '5000.00' }, { currency: 'EUR' }]) {
    const res = await verifyReceiptOffline({ ...body.receipt, ...mut }, issuerJwk)
    expect(res.ok).toBe(false)
  }
})

test('T5: numeric amount is rejected (must be a decimal string)', async () => {
  const { status } = await post('/verify', {
    intent: { from: 'agentA', to: 'vendor', amount: 50 },
  })
  expect(status).toBe(400)
})

async function commit(payload: { to: string; amount?: string; currency?: string }, agentId = 'agentA', opts?: { signed?: boolean }) {
  const payloadHash = await hashPaymentPayload(payload)
  const nonce = `n_${Math.random().toString(36).slice(2)}`
  const expiresAt = new Date(Date.now() + 60_000).toISOString()
  const body: any = { agentId, payloadHash, alg: 'sha256', nonce, expiresAt }
  if (opts?.signed) {
    const kp = await generateKeyPair()
    body.agentSignature = await signCanonical(
      commitmentSigningPayload({ agentId, alg: 'sha256', expiresAt, nonce, payloadHash }),
      kp.privateJwk
    )
    body.agentPubkey = kp.publicJwk
  }
  const res = await post('/commitments', body)
  return { ...res, nonce }
}

test('T3: commit A, verify B → DENY PAYLOAD_MISMATCH + signed DENY receipt', async () => {
  const { status, body: c } = await commit({ to: 'alice', amount: '10.00', currency: 'USD' })
  expect(status).toBe(201)

  const { body } = await post('/verify', {
    intent: { from: 'agentA', to: 'MALLORY', amount: '10.00', currency: 'USD' },
    commitmentId: c.commitmentId,
  })
  expect(body.decision).toBe('DENY')
  expect(body.reason).toBe('PAYLOAD_MISMATCH')
  expect(body.receipt.decision).toBe('DENY')
  expect(body.receipt.to).toBe('MALLORY') // the DENY receipt names what was attempted
  const v = await verifyReceiptOffline(body.receipt, issuerJwk)
  expect(v.ok).toBe(true)
})

test('T3: commit A, verify A → ALLOW binding=committed', async () => {
  const { body: c } = await commit({ to: 'alice', amount: '10.00', currency: 'USD' })
  const { body } = await post('/verify', {
    intent: { from: 'agentA', to: 'alice', amount: '10.00', currency: 'USD' },
    commitmentId: c.commitmentId,
  })
  expect(body.decision).toBe('ALLOW')
  expect(body.binding).toBe('committed')
})

test('T3: consumed commitment → DENY COMMITMENT_CONSUMED', async () => {
  const { body: c } = await commit({ to: 'alice', amount: '10.00', currency: 'USD' })
  const p = {
    intent: { from: 'agentA', to: 'alice', amount: '10.00', currency: 'USD' },
    commitmentId: c.commitmentId,
  }
  const first = await post('/verify', p)
  expect(first.body.decision).toBe('ALLOW')
  const second = await post('/verify', p)
  expect(second.body.decision).toBe('DENY')
  expect(second.body.reason).toBe('COMMITMENT_CONSUMED')
})

test('T3: amount mismatch (not just to) → DENY PAYLOAD_MISMATCH', async () => {
  const { body: c } = await commit({ to: 'alice', amount: '10.00', currency: 'USD' })
  const { body } = await post('/verify', {
    intent: { from: 'agentA', to: 'alice', amount: '99.00', currency: 'USD' },
    commitmentId: c.commitmentId,
  })
  expect(body.decision).toBe('DENY')
  expect(body.reason).toBe('PAYLOAD_MISMATCH')
})

test('T3: expired commitment → DENY COMMITMENT_EXPIRED', async () => {
  const { hashPaymentPayload } = await import('@stvor/core')
  const payload = { to: 'alice', amount: '10.00', currency: 'USD' }
  const payloadHash = await hashPaymentPayload(payload)
  // Insert directly with a past expiry (the API refuses to create one already expired).
  store.saveCommitment({
    commitmentId: 'cmt_expired_1',
    agentId: 'agentA',
    payloadHash,
    alg: 'sha256',
    nonce: 'n_expired_1',
    createdAt: new Date(Date.now() - 120_000).toISOString(),
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
    consumed: false,
  })
  const { body } = await post('/verify', {
    intent: { from: 'agentA', to: 'alice', amount: '10.00', currency: 'USD' },
    commitmentId: 'cmt_expired_1',
  })
  expect(body.decision).toBe('DENY')
  expect(body.reason).toBe('COMMITMENT_EXPIRED')
})

test('T4: agent-committed binding when commitment is agent-signed', async () => {
  const { body: c } = await commit({ to: 'alice', amount: '10.00', currency: 'USD' }, 'agentA', { signed: true })
  const { body } = await post('/verify', {
    intent: { from: 'agentA', to: 'alice', amount: '10.00', currency: 'USD' },
    commitmentId: c.commitmentId,
  })
  expect(body.binding).toBe('agent-committed')
  expect(body.receipt.agentSignature).toBeDefined()
  expect(body.receipt.agentKeyThumbprint).toBeDefined()
})

test('T4: invalid agent signature → 400 at /commitments (no silent downgrade)', async () => {
  const agentId = 'agentBad'
  const payload = { to: 'alice', amount: '10.00', currency: 'USD' }
  const payloadHash = await hashPaymentPayload(payload)
  const nonce = 'n_bad'
  const expiresAt = new Date(Date.now() + 60_000).toISOString()
  const kp = await generateKeyPair()
  const { status, body } = await post('/commitments', {
    agentId,
    payloadHash,
    alg: 'sha256',
    nonce,
    expiresAt,
    agentSignature: 'AAAA' + 'B'.repeat(80), // garbage
    agentPubkey: kp.publicJwk,
  })
  expect(status).toBe(400)
  expect(body.error).toBe('INVALID_AGENT_SIGNATURE')
})

test('T2: settlement receipt references the verification receipt and is idempotent', async () => {
  const { body: v } = await post('/verify', {
    intent: { from: 'agentA', to: 'vendor', amount: '7.00', currency: 'USD' },
  })
  const s1 = await post('/receipt', { verificationId: v.id, txHash: '0xabc' })
  expect(s1.status).toBe(201)
  expect(s1.body.txHash).toBe('0xabc')
  expect(s1.body.verificationReceiptId).toBe(v.receipt.receiptId)
  const sv = await verifyReceiptOffline(s1.body, issuerJwk)
  expect(sv.ok).toBe(true)

  // same tx → idempotent 200, same receipt
  const s2 = await post('/receipt', { verificationId: v.id, txHash: '0xabc' })
  expect(s2.status).toBe(200)
  expect(s2.body.receiptId).toBe(s1.body.receiptId)

  // different tx → conflict
  const s3 = await post('/receipt', { verificationId: v.id, txHash: '0xDEAD' })
  expect(s3.status).toBe(409)
})

test('T2: cannot settle a DENY', async () => {
  const { body: c } = await commit({ to: 'alice', amount: '1.00', currency: 'USD' })
  const { body: v } = await post('/verify', {
    intent: { from: 'agentA', to: 'notalice', amount: '1.00', currency: 'USD' },
    commitmentId: c.commitmentId,
  })
  expect(v.decision).toBe('DENY')
  const s = await post('/receipt', { verificationId: v.id, txHash: '0x1' })
  expect(s.status).toBe(422)
})

// --- per-client keys + /stats ---------------------------------------------
// These run LAST. The first one turns on a master key (lazily read), which
// disables open mode — from here on every request needs a valid key.
const MASTER = 'stvor_live_test_master_key'

function issueClient(name: string, env: 'test' | 'live' = 'test') {
  const k = newClientKey(env)
  store.createClient({ keyId: k.keyId, keyHash: k.keyHash, name, env, createdAt: new Date().toISOString() })
  return k
}

test('keys: valid client key authenticates and is attributed', async () => {
  process.env.STVOR_KEY = MASTER // enable auth for the remaining tests
  const k = issueClient('orbserv')
  const { status, body } = await post(
    '/verify',
    { intent: { from: 'agentA', to: 'vendor', amount: '1.00', currency: 'USD' } },
    k.fullKey
  )
  expect(status).toBe(200)
  // Attribution is visible to root via /stats.
  const stats = await get('/stats', MASTER)
  expect(stats.status).toBe(200)
  expect(stats.body.sandbox.byClient.some((c: any) => c.key === k.keyId)).toBe(true)
})

test('keys: missing / bogus key → 401', async () => {
  const none = await post('/verify', { intent: { from: 'a', to: 'b' } })
  expect(none.status).toBe(401)
  const bogus = await post('/verify', { intent: { from: 'a', to: 'b' } }, 'stvor_test_not_a_real_key')
  expect(bogus.status).toBe(401)
})

test('keys: a revoked key → 401', async () => {
  const k = issueClient('to-be-revoked')
  const ok = await post('/verify', { intent: { from: 'a', to: 'b', amount: '1.00' } }, k.fullKey)
  expect(ok.status).toBe(200)
  expect(store.revokeClient(k.keyId)).toBe(true)
  const after = await post('/verify', { intent: { from: 'a', to: 'b', amount: '1.00' } }, k.fullKey)
  expect(after.status).toBe(401)
})

test('/stats: root key → 200 with production + sandbox slices', async () => {
  const { status, body } = await get('/stats', MASTER)
  expect(status).toBe(200)
  for (const slice of [body.production, body.sandbox]) {
    expect(typeof slice.total).toBe('number')
    expect(slice.allow + slice.deny).toBe(slice.total)
    expect(Array.isArray(slice.byReason)).toBe(true)
    expect(Array.isArray(slice.recent)).toBe(true)
  }
  // PAYLOAD_MISMATCH from dev-mode tests lands in sandbox (client_id = dev).
  const mismatch =
    body.production.byReason.some((r: any) => r.key === 'PAYLOAD_MISMATCH') ||
    body.sandbox.byReason.some((r: any) => r.key === 'PAYLOAD_MISMATCH')
  expect(mismatch).toBe(true)
})

test('/stats: a client (non-root) key → 403, not a data leak', async () => {
  const k = issueClient('nosy-partner')
  const res = await get('/stats', k.fullKey)
  expect(res.status).toBe(403)
})

test('/stats: no auth → 401', async () => {
  const res = await get('/stats')
  expect(res.status).toBe(401)
})

test('dashboard: served as data-free HTML shell', async () => {
  const res = await app.inject({ method: 'GET', url: '/dashboard' })
  expect(res.statusCode).toBe(200)
  expect(res.headers['content-type']).toContain('text/html')
  expect(res.body).toContain('Stvor')
})

test('stats are DURABLE: a caught swap survives a working-set sweep', async () => {
  const mm = (s: any) => (s.byReason.find((r: any) => r.key === 'PAYLOAD_MISMATCH') || {}).count || 0
  const before = (await get('/stats', MASTER)).body.production

  // A decision is logged to the durable audit table, not the ephemeral one.
  store.recordEvent({
    decision: 'DENY', reason: 'PAYLOAD_MISMATCH', binding: 'committed',
    clientId: 'durability-probe', createdAt: new Date().toISOString(),
  })
  // Nuke the working set (this is what deleted the metric before the fix).
  store.cleanupExpired()

  const after = (await get('/stats', MASTER)).body.production
  expect(after.total).toBe(before.total + 1)
  expect(mm(after)).toBe(mm(before) + 1) // the caught swap is STILL counted
  expect(after.byClient.some((c: any) => c.key === 'durability-probe')).toBe(true)
})

test('stats recent is counts-only — no payment fields (retention-clean)', async () => {
  const { body } = await get('/stats', MASTER)
  expect(body.production.recent.length).toBeGreaterThan(0)
  expect(body.production.recent.every((r: any) => !('to' in r) && !('amount' in r) && !('currency' in r))).toBe(true)
})

test('stats: sandbox (test env) keys are isolated from production', async () => {
  const k = issueClient('public-sandbox-probe', 'test')
  await post(
    '/verify',
    { intent: { from: 'sandbox', to: 'vendor', amount: '1.00', currency: 'USD' } },
    k.fullKey,
  )
  const { body } = await get('/stats', MASTER)
  expect(body.sandbox.byClient.some((c: any) => c.key === k.keyId)).toBe(true)
  expect(body.production.byClient.some((c: any) => c.key === k.keyId)).toBe(false)
})
