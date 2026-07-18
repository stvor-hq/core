import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import { signReceipt, type ReceiptPayload } from '@stvor/core'
import { store } from '../store.js'
import { getIssuer } from '../crypto.js'
import { requireApiKey } from '../auth.js'
import type { Settlement } from '../types.js'

const ReceiptBodySchema = z.object({
  verificationId: z.string().min(1),
  txHash: z.string().min(1),
})

/**
 * Optional SECOND step. /verify already returned a signed verification receipt;
 * this attaches an on-chain txHash after settlement and mints a settlement
 * receipt referencing it. Idempotent per verification (one tx per decision).
 */
export async function receiptRoutes(app: FastifyInstance) {
  app.post('/receipt', { preHandler: requireApiKey }, async (req, reply) => {
    const parsed = ReceiptBodySchema.safeParse(req.body)
    if (!parsed.success) {
      return reply.code(400).send({ error: 'Invalid request', details: parsed.error.flatten() })
    }
    const { verificationId, txHash } = parsed.data

    // Fast idempotency path.
    const existing = store.getSettlement(verificationId)
    if (existing) {
      if (existing.txHash === txHash) return reply.code(200).send(existing.receipt)
      return reply.code(409).send({
        error: 'Verification already settled with a different transaction',
        receiptId: existing.receipt.receiptId,
      })
    }

    const v = store.getVerification(verificationId)
    if (!v) return reply.code(404).send({ error: 'Verification not found' })
    if (v.decision !== 'ALLOW') {
      return reply.code(422).send({ error: 'Cannot settle a DENY decision' })
    }
    if (new Date() > new Date(v.expiresAt)) {
      return reply.code(410).send({ error: 'Verification expired' })
    }

    const issuer = await getIssuer()
    const issuedAt = new Date().toISOString()
    const settlementReceiptId = `rec_${nanoid(12)}`

    const payload: ReceiptPayload = {
      receiptId: settlementReceiptId,
      verificationId,
      binding: v.binding,
      agentId: v.agentId,
      to: v.to,
      amount: v.amount,
      currency: v.currency,
      chain: v.chain,
      asset: v.asset,
      nonce: v.nonce,
      decision: 'ALLOW',
      reason: 'SETTLED',
      issuedAt,
      expiresAt: v.expiresAt,
      kid: issuer.kid,
      commitmentId: v.commitmentId,
      // Carry the FULL agent-committed proof forward, so the settlement receipt
      // is independently verifiable exactly like the verification receipt.
      agentPubkey: v.receipt.agentPubkey,
      agentSigAlg: v.receipt.agentSigAlg,
      agentCommitment: v.receipt.agentCommitment,
      agentKeyThumbprint: v.receipt.agentKeyThumbprint,
      agentSignature: v.receipt.agentSignature,
      txHash,
      verificationReceiptId: v.receipt.receiptId,
    }
    const receipt = await signReceipt(payload, issuer.privateJwk)

    const settlement: Settlement = { verificationId, txHash, receipt, issuedAt }
    const result = store.issueSettlement(settlement)

    if (result.status === 'conflict') {
      return reply.code(409).send({
        error: 'Verification already settled with a different transaction',
        receiptId: result.existing.receipt.receiptId,
      })
    }
    return reply.code(result.status === 'issued' ? 201 : 200).send(result.settlement.receipt)
  })
}
