/**
 * Generates the published test vectors in fixtures/. Two audiences:
 *
 *  1. canonical-vectors.json — payment intent → RFC 8785 canonical bytes (hex)
 *     → SHA-256. Key-independent: a partner runs their own serializer against
 *     these to prove byte-for-byte agreement BEFORE the first live call. This
 *     is how you avoid spending a week hunting a one-comma canonicalization bug.
 *
 *  2. receipt-vectors.json — signed Trust Receipts (valid + tampered) with an
 *     expected OK/FAIL, verifiable offline against keyset.json.
 *
 * The issuer key is generated once and reused from fixtures/, so vectors are
 * stable across reruns. Deterministic receipt fields (ids, timestamps) keep
 * the signatures reproducible.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  canonicalize,
  canonicalBytes,
  bytesToHex,
  sha256Hex,
  generateKeyPair,
  signReceipt,
  paymentPayloadOf,
  kidOf,
  type EcJwk,
  type ReceiptPayload,
  type KeyRegistry,
} from '../stvor-core/src/index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(HERE, '..', 'fixtures')
mkdirSync(FIXTURES, { recursive: true })

function readJson<T>(p: string): T | null {
  return existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as T) : null
}
function writeJson(p: string, v: unknown) {
  writeFileSync(p, JSON.stringify(v, null, 2) + '\n')
}

// --- stable issuer key ------------------------------------------------------
const privPath = join(FIXTURES, 'issuer.private.jwk')
let issuerPrivate = readJson<EcJwk>(privPath)
let issuerPublic: EcJwk
let kid: string
if (issuerPrivate) {
  issuerPublic = { kty: 'EC', crv: 'P-256', x: issuerPrivate.x, y: issuerPrivate.y }
  kid = await kidOf(issuerPublic)
} else {
  const kp = await generateKeyPair()
  issuerPrivate = kp.privateJwk
  issuerPublic = kp.publicJwk
  kid = kp.kid
  writeJson(privPath, issuerPrivate)
}
issuerPublic = { ...issuerPublic, kid, use: 'sig', alg: 'ES256' }
writeJson(join(FIXTURES, 'issuer.jwk'), issuerPublic)

const keyset: KeyRegistry = {
  keys: [{ kid, jwk: issuerPublic, notBefore: '2026-01-01T00:00:00.000Z' }],
}
writeJson(join(FIXTURES, 'keyset.json'), keyset)

// --- canonicalization vectors ----------------------------------------------
const canonicalInputs: { name: string; input: Record<string, unknown> }[] = [
  { name: 'simple', input: { to: 'vendor_api_credits', amount: '50.00', currency: 'USD' } },
  { name: 'key-order-irrelevant', input: { currency: 'USD', amount: '50.00', to: 'vendor_api_credits' } },
  { name: 'with-chain-asset', input: { to: '0xabc', amount: '1.5', currency: 'USDC', chain: 'base', asset: 'erc20' } },
  { name: 'amount-omitted', input: { to: 'alice' } },
  { name: 'unicode', input: { to: 'café', amount: '10.00', currency: 'EUR' } },
]

const canonicalVectors = await Promise.all(
  canonicalInputs.map(async ({ name, input }) => {
    const payload = paymentPayloadOf(input as any)
    const canonical = canonicalize(payload)
    const hex = bytesToHex(canonicalBytes(payload))
    const sha256 = await sha256Hex(canonicalBytes(payload))
    return { name, input, canonical, canonicalHex: hex, sha256 }
  })
)
writeJson(join(FIXTURES, 'canonical-vectors.json'), canonicalVectors)

// --- receipt vectors --------------------------------------------------------
const basePayload: ReceiptPayload = {
  receiptId: 'rec_vector0001',
  verificationId: 'ver_vector0001',
  binding: 'committed',
  agentId: 'agent_demo',
  to: 'vendor_api_credits',
  amount: '50.00',
  currency: 'USD',
  nonce: 'nonce_demo_0001',
  decision: 'ALLOW',
  reason: 'PAYLOAD_MATCH',
  issuedAt: '2026-01-01T00:00:00.000Z',
  expiresAt: '2026-01-01T00:05:00.000Z',
  kid,
  commitmentId: 'cmt_vector0001',
}
const validReceipt = await signReceipt(basePayload, issuerPrivate)

const denyReceipt = await signReceipt(
  { ...basePayload, receiptId: 'rec_vector0002', decision: 'DENY', reason: 'PAYLOAD_MISMATCH', to: '0xattacker_swapped_this' },
  issuerPrivate
)

const receiptVectors = [
  { name: 'valid-allow', receipt: validReceipt, expected: 'OK' },
  { name: 'valid-deny', receipt: denyReceipt, expected: 'OK' },
  { name: 'tampered-to', receipt: { ...validReceipt, to: '0xattacker' }, expected: 'FAIL', reason: 'BAD_SIGNATURE' },
  { name: 'tampered-amount', receipt: { ...validReceipt, amount: '5000.00' }, expected: 'FAIL', reason: 'BAD_SIGNATURE' },
  { name: 'tampered-decision', receipt: { ...denyReceipt, decision: 'ALLOW' }, expected: 'FAIL', reason: 'BAD_SIGNATURE' },
  { name: 'tampered-expiry', receipt: { ...validReceipt, expiresAt: '2030-01-01T00:00:00.000Z' }, expected: 'FAIL', reason: 'BAD_SIGNATURE' },
  { name: 'unknown-kid', receipt: { ...validReceipt, kid: 'key_deadbeefdeadbeef' }, expected: 'FAIL', reason: 'UNKNOWN_KEY' },
]
writeJson(join(FIXTURES, 'receipt-vectors.json'), receiptVectors)

console.log(`Wrote vectors to ${FIXTURES}`)
console.log(`  issuer kid: ${kid}`)
console.log(`  canonical vectors: ${canonicalVectors.length}`)
console.log(`  receipt vectors:   ${receiptVectors.length}`)
