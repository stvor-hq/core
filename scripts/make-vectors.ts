/**
 * Generates the published test vectors in fixtures/. Audiences:
 *
 *  1. canonical-vectors.json — payment intent → RFC 8785 canonical bytes (hex)
 *     → SHA-256. Key-independent: a partner runs their own serializer against
 *     these to prove byte-for-byte agreement BEFORE the first live call.
 *
 *  2. receipt-vectors.json — signed Trust Receipts (valid + tampered, P-256 and
 *     Ed25519 agent-committed) with an expected OK/FAIL, verifiable offline
 *     against keyset.json. Includes the cross-algorithm confusion case.
 *
 *  3. thumbprint-vectors.json — RFC 7638 thumbprints for EC and OKP keys.
 *
 * The issuer key is generated once and reused from fixtures/. Agent keys are
 * fresh per run but each vector is self-consistent.
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
  signCanonical,
  commitmentSigningPayload,
  hashPaymentPayload,
  jwkThumbprint,
  paymentPayloadOf,
  kidOf,
  type EcJwk,
  type ReceiptPayload,
  type KeyRegistry,
  type SigAlg,
} from '../stvor-core/src/index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(HERE, '..', 'fixtures')
mkdirSync(FIXTURES, { recursive: true })

const readJson = <T,>(p: string): T | null =>
  existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as T) : null
const writeJson = (p: string, v: unknown) => writeFileSync(p, JSON.stringify(v, null, 2) + '\n')

// --- stable issuer key ------------------------------------------------------
const privPath = join(FIXTURES, 'issuer.private.jwk')
let issuerPrivate = readJson<EcJwk>(privPath)
let issuerPublic: EcJwk
let kid: string
if (issuerPrivate) {
  issuerPublic = { kty: 'EC', crv: 'P-256', x: issuerPrivate.x, y: issuerPrivate.y }
  kid = await kidOf(issuerPublic)
} else {
  const kp = await generateKeyPair('ES256')
  issuerPrivate = kp.privateJwk as EcJwk
  issuerPublic = kp.publicJwk as EcJwk
  kid = kp.kid
  writeJson(privPath, issuerPrivate)
}
issuerPublic = { ...issuerPublic, kid, use: 'sig', alg: 'ES256' }
writeJson(join(FIXTURES, 'issuer.jwk'), issuerPublic)

const keyset: KeyRegistry = { keys: [{ kid, jwk: issuerPublic, notBefore: '2026-01-01T00:00:00.000Z' }] }
writeJson(join(FIXTURES, 'keyset.json'), keyset)

// --- canonicalization vectors ----------------------------------------------
const canonicalInputs = [
  { name: 'simple', input: { to: 'vendor_api_credits', amount: '50.00', currency: 'USD' } },
  { name: 'key-order-irrelevant', input: { currency: 'USD', amount: '50.00', to: 'vendor_api_credits' } },
  { name: 'with-chain-asset', input: { to: '0xabc', amount: '1.5', currency: 'USDC', chain: 'base', asset: 'erc20' } },
  { name: 'amount-omitted', input: { to: 'alice' } },
  { name: 'unicode', input: { to: 'café', amount: '10.00', currency: 'EUR' } },
]
const canonicalVectors = await Promise.all(
  canonicalInputs.map(async ({ name, input }) => {
    const payload = paymentPayloadOf(input as any)
    return {
      name,
      input,
      canonical: canonicalize(payload),
      canonicalHex: bytesToHex(canonicalBytes(payload)),
      sha256: await sha256Hex(canonicalBytes(payload)),
    }
  })
)
writeJson(join(FIXTURES, 'canonical-vectors.json'), canonicalVectors)

// --- attested / committed receipt vectors ----------------------------------
const basePayload: ReceiptPayload = {
  receiptId: 'rec_vector0001', verificationId: 'ver_vector0001', binding: 'committed',
  agentId: 'agent_demo', to: 'vendor_api_credits', amount: '50.00', currency: 'USD',
  nonce: 'nonce_demo_0001', decision: 'ALLOW', reason: 'PAYLOAD_MATCH',
  issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-01T00:05:00.000Z', kid,
  commitmentId: 'cmt_vector0001',
}
const validReceipt = await signReceipt(basePayload, issuerPrivate)
const denyReceipt = await signReceipt(
  { ...basePayload, receiptId: 'rec_vector0002', decision: 'DENY', reason: 'PAYLOAD_MISMATCH', to: '0xattacker_swapped_this' },
  issuerPrivate
)

// --- agent-committed receipt builder ---------------------------------------
const PAYMENT = { to: 'vendor_api_credits', amount: '50.00', currency: 'USD' }
const ENV_BASE = {
  agentId: 'agent_demo', alg: 'sha256' as const,
  expiresAt: '2026-01-01T00:05:00.000Z', nonce: 'nonce_ac_0001',
}

async function agentCommitted(receiptId: string, agentAlg: SigAlg) {
  const agent = await generateKeyPair(agentAlg)
  const payloadHash = await hashPaymentPayload(PAYMENT)
  const envelope = commitmentSigningPayload({ ...ENV_BASE, payloadHash })
  const agentSignature = await signCanonical(envelope, agent.privateJwk)
  const payload: ReceiptPayload = {
    receiptId, verificationId: 'ver_ac', binding: 'agent-committed', agentId: 'agent_demo',
    to: PAYMENT.to, amount: PAYMENT.amount, currency: PAYMENT.currency, nonce: ENV_BASE.nonce,
    decision: 'ALLOW', reason: 'PAYLOAD_MATCH',
    issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-01T00:05:00.000Z', kid,
    commitmentId: 'cmt_ac', agentPubkey: agent.publicJwk, agentSigAlg: agentAlg,
    agentCommitment: envelope, agentKeyThumbprint: await jwkThumbprint(agent.publicJwk), agentSignature,
  }
  return { receipt: await signReceipt(payload, issuerPrivate), agent, envelope, payload }
}

const edAC = await agentCommitted('rec_ac_ed', 'EdDSA')
const p256AC = await agentCommitted('rec_ac_p256', 'ES256')

// forged agent signature: issuer valid, but agent sig is from a DIFFERENT key
const otherEd = await generateKeyPair('EdDSA')
const forgedAgentSig = await signCanonical(edAC.envelope, otherEd.privateJwk)
const forgedAgentReceipt = await signReceipt(
  { ...edAC.payload, receiptId: 'rec_ac_forged', agentSignature: forgedAgentSig },
  issuerPrivate
)

// cross-algorithm confusion: Ed25519 signature bytes, but a P-256 key declared
const p256Key = await generateKeyPair('ES256')
const crossAlgReceipt = await signReceipt(
  {
    ...edAC.payload, receiptId: 'rec_ac_crossalg',
    agentPubkey: p256Key.publicJwk, agentSigAlg: 'ES256', agentSignature: edAC.receipt.agentSignature!,
    agentKeyThumbprint: await jwkThumbprint(p256Key.publicJwk),
  },
  issuerPrivate
)

const receiptVectors = [
  { name: 'valid-allow', receipt: validReceipt, expected: 'OK' },
  { name: 'valid-deny', receipt: denyReceipt, expected: 'OK' },
  { name: 'tampered-to', receipt: { ...validReceipt, to: '0xattacker' }, expected: 'FAIL', reason: 'BAD_ISSUER_SIGNATURE' },
  { name: 'tampered-amount', receipt: { ...validReceipt, amount: '5000.00' }, expected: 'FAIL', reason: 'BAD_ISSUER_SIGNATURE' },
  { name: 'tampered-decision', receipt: { ...denyReceipt, decision: 'ALLOW' }, expected: 'FAIL', reason: 'BAD_ISSUER_SIGNATURE' },
  { name: 'unknown-kid', receipt: { ...validReceipt, kid: 'key_deadbeefdeadbeef' }, expected: 'FAIL', reason: 'UNKNOWN_KEY' },
  // agent-committed
  { name: 'ed25519-agent-committed-valid', receipt: edAC.receipt, expected: 'OK', agentSignature: 'valid' },
  { name: 'p256-agent-committed-valid', receipt: p256AC.receipt, expected: 'OK', agentSignature: 'valid' },
  { name: 'agent-committed-tampered-to', receipt: { ...edAC.receipt, to: '0xattacker' }, expected: 'FAIL', reason: 'BAD_ISSUER_SIGNATURE' },
  { name: 'agent-committed-forged-agent-sig', receipt: forgedAgentReceipt, expected: 'FAIL', reason: 'BAD_AGENT_SIGNATURE' },
  { name: 'cross-alg-ed25519-sig-as-p256', receipt: crossAlgReceipt, expected: 'FAIL', reason: 'BAD_AGENT_SIGNATURE' },
]
writeJson(join(FIXTURES, 'receipt-vectors.json'), receiptVectors)

// --- RFC 7638 thumbprint vectors -------------------------------------------
const okpKey = await generateKeyPair('EdDSA')
const thumbprintVectors = [
  { kty: 'EC', jwk: { kty: issuerPublic.kty, crv: issuerPublic.crv, x: issuerPublic.x, y: issuerPublic.y }, thumbprint: await jwkThumbprint(issuerPublic) },
  { kty: 'OKP', jwk: okpKey.publicJwk, thumbprint: await jwkThumbprint(okpKey.publicJwk) },
]
writeJson(join(FIXTURES, 'thumbprint-vectors.json'), thumbprintVectors)

console.log(`Wrote vectors to ${FIXTURES}`)
console.log(`  issuer kid: ${kid}`)
console.log(`  canonical:  ${canonicalVectors.length}`)
console.log(`  receipt:    ${receiptVectors.length} (incl. Ed25519 + P-256 agent-committed, cross-alg)`)
console.log(`  thumbprint: ${thumbprintVectors.length}`)
