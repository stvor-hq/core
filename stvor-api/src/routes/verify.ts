import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import { timingSafeEqual } from 'node:crypto'
import {
  AMOUNT_REGEX,
  hashPaymentPayload,
  paymentPayloadOf,
  signReceipt,
  type Binding,
  type Decision,
  type ReceiptPayload,
} from '@stvor/core'
import { store } from '../store.js'
import { evaluate } from '../trust.js'
import { requireApiKey } from '../auth.js'
import { getIssuer } from '../crypto.js'
import type { Intent, Verification, Commitment } from '../types.js'

const VERIFICATION_TTL_MS = 5 * 60 * 1000

const IntentSchema = z.object({
  from: z.string().min(1),
  to: z.string().min(1),
  amount: z.string().regex(AMOUNT_REGEX, 'amount must be a decimal string, e.g. "50.00"').optional(),
  currency: z.string().optional(),
  chain: z.string().optional(),
  asset: z.string().optional(),
  payload: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
})

const VerifyBodySchema = z.object({
  intent: IntentSchema,
  agentId: z.string().min(1).optional(),
  nonce: z.string().min(1).optional(),
  commitmentId: z.string().min(1).optional(),
  policy: z.object({ minTrustScore: z.number().min(0).max(1).optional() }).optional(),
})

interface Outcome {
  decision: Decision
  reason: string
  binding: Binding
  agentKeyThumbprint?: string
  agentSignature?: string
}

/** Constant-time equality of two SHA-256 hex digests. */
function hashEq(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  return ba.length === bb.length && timingSafeEqual(ba, bb)
}

/**
 * The full decision, given a live intent and (optionally) a prior commitment.
 * Commitment consumption is atomic (single-use) and happens only on a genuine
 * match — that is what makes "committed" mean the executed payment equals the
 * one that was frozen earlier.
 */
async function decide(
  intent: Intent,
  agentId: string,
  commitment: Commitment | null,
  commitmentIdRequested: string | undefined,
  minTrustScore: number | undefined
): Promise<Outcome> {
  if (commitmentIdRequested && !commitment) {
    return { decision: 'DENY', reason: 'COMMITMENT_NOT_FOUND', binding: 'attested' }
  }

  if (commitment) {
    const binding: Binding = commitment.agentSignature ? 'agent-committed' : 'committed'
    const carry = { agentKeyThumbprint: commitment.agentKeyThumbprint, agentSignature: commitment.agentSignature }

    if (commitment.agentId !== agentId) {
      return { decision: 'DENY', reason: 'AGENT_MISMATCH', binding, ...carry }
    }
    if (new Date() > new Date(commitment.expiresAt)) {
      return { decision: 'DENY', reason: 'COMMITMENT_EXPIRED', binding, ...carry }
    }
    if (commitment.consumed) {
      return { decision: 'DENY', reason: 'COMMITMENT_CONSUMED', binding, ...carry }
    }

    const liveHash = await hashPaymentPayload(paymentPayloadOf(intent))
    if (!hashEq(liveHash, commitment.payloadHash)) {
      return { decision: 'DENY', reason: 'PAYLOAD_MISMATCH', binding, ...carry }
    }

    // Payload matches — claim the single-use commitment atomically. Losing this
    // race (someone already consumed it) is a replay, so it must DENY.
    if (!store.consumeCommitment(commitment.commitmentId)) {
      return { decision: 'DENY', reason: 'COMMITMENT_CONSUMED', binding, ...carry }
    }
    return { decision: 'ALLOW', reason: 'PAYLOAD_MATCH', binding, ...carry }
  }

  // No commitment: attested. Structural guards + optional (stub) trust gate.
  const result = evaluate(
    { from: intent.from, to: intent.to, amount: intent.amount ? Number(intent.amount) : undefined },
    minTrustScore ?? 0
  )
  return {
    decision: result.decision,
    reason: result.decision === 'ALLOW' ? 'ATTESTED_OK' : upperReason(result.reason),
    binding: 'attested',
  }
}

function upperReason(reason: string): string {
  if (/below threshold/i.test(reason)) return 'TRUST_BELOW_THRESHOLD'
  if (/from/i.test(reason)) return 'MISSING_FROM'
  if (/to/i.test(reason)) return 'MISSING_TO'
  if (/negative/i.test(reason)) return 'NEGATIVE_AMOUNT'
  return 'DENIED'
}

export async function verifyRoutes(app: FastifyInstance) {
  app.post('/verify', { preHandler: requireApiKey }, async (req, reply) => {
    const parsed = VerifyBodySchema.safeParse(req.body)
    if (!parsed.success) {
      return reply.code(400).send({ error: 'Invalid request', details: parsed.error.flatten() })
    }
    const { intent, commitmentId, policy } = parsed.data
    const agentId = parsed.data.agentId ?? intent.from

    const commitment = commitmentId ? store.getCommitment(commitmentId) : null

    let outcome: Outcome
    try {
      outcome = await decide(intent, agentId, commitment, commitmentId, policy?.minTrustScore)
    } catch (err) {
      return reply.code(400).send({ error: 'Invalid intent', details: String(err) })
    }

    const issuer = await getIssuer()
    const now = new Date()
    const issuedAt = now.toISOString()
    const expiresAt = new Date(now.getTime() + VERIFICATION_TTL_MS).toISOString()
    const verificationId = `ver_${nanoid(12)}`
    const receiptId = `rec_${nanoid(12)}`
    const nonce = commitment?.nonce ?? parsed.data.nonce ?? nanoid(16)

    const payloadFields = paymentPayloadOf(intent)
    const receiptPayload: ReceiptPayload = {
      receiptId,
      verificationId,
      binding: outcome.binding,
      agentId,
      to: payloadFields.to,
      amount: payloadFields.amount,
      currency: payloadFields.currency,
      chain: payloadFields.chain,
      asset: payloadFields.asset,
      nonce,
      decision: outcome.decision,
      reason: outcome.reason,
      issuedAt,
      expiresAt,
      kid: issuer.kid,
      commitmentId: commitment ? commitment.commitmentId : undefined,
      agentKeyThumbprint: outcome.agentKeyThumbprint,
      agentSignature: outcome.agentSignature,
    }
    const receipt = await signReceipt(receiptPayload, issuer.privateJwk)

    const verification: Verification = {
      id: verificationId,
      decision: outcome.decision,
      reason: outcome.reason,
      binding: outcome.binding,
      clientId: req.clientId ?? 'unknown',
      agentId,
      to: payloadFields.to,
      amount: payloadFields.amount,
      currency: payloadFields.currency,
      chain: payloadFields.chain,
      asset: payloadFields.asset,
      nonce,
      commitmentId: commitment?.commitmentId,
      receipt,
      createdAt: issuedAt,
      expiresAt,
      settled: false,
    }
    store.saveVerification(verification)

    // Durable audit: one row per decision, kept forever, counts only (no
    // to/amount). This is what /stats counts — so a caught swap survives long
    // after its short-lived verification row is swept.
    store.recordEvent({
      decision: outcome.decision,
      reason: outcome.reason,
      binding: outcome.binding,
      clientId: verification.clientId,
      createdAt: issuedAt,
    })

    return reply.code(200).send({
      id: verificationId,
      decision: outcome.decision,
      reason: outcome.reason,
      binding: outcome.binding,
      receipt,
      expiresAt,
    })
  })

  app.get<{ Params: { id: string } }>('/verify/:id', { preHandler: requireApiKey }, async (req, reply) => {
    const v = store.getVerification(req.params.id)
    if (!v) return reply.code(404).send({ error: 'Verification not found' })
    return reply.code(200).send({
      id: v.id,
      decision: v.decision,
      reason: v.reason,
      binding: v.binding,
      intent: {
        from: v.agentId,
        to: v.to,
        amount: v.amount,
        currency: v.currency,
        chain: v.chain,
        asset: v.asset,
      },
      receipt: v.receipt,
      createdAt: v.createdAt,
      expiresAt: v.expiresAt,
      settled: v.settled,
    })
  })
}
