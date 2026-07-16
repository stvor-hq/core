import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import {
  verifyCanonical,
  commitmentSigningPayload,
  jwkThumbprint,
  type EcJwk,
} from '@stvor/core'
import { store } from '../store.js'
import { requireApiKey } from '../auth.js'
import type { Commitment } from '../types.js'

const JwkSchema = z
  .object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: z.string().min(1),
    y: z.string().min(1),
  })
  .passthrough()

const CommitmentBodySchema = z
  .object({
    agentId: z.string().min(1),
    payloadHash: z.string().regex(/^[0-9a-f]{64}$/i, 'payloadHash must be 64 hex chars (SHA-256)'),
    alg: z.literal('sha256'),
    nonce: z.string().min(1),
    expiresAt: z.string().datetime(),
    agentSignature: z.string().min(1).optional(),
    agentPubkey: JwkSchema.optional(),
  })
  .refine((b) => !b.agentSignature || b.agentPubkey, {
    message: 'agentPubkey is required when agentSignature is present',
    path: ['agentPubkey'],
  })

/**
 * A commitment freezes the payment invariants (via payloadHash) at intent time,
 * BEFORE execution. When it carries the agent's own signature, the resulting
 * receipt proves — to any third party, without trusting Stvor or the integrator
 * — that the executed payment matched what the agent itself committed to.
 */
export async function commitmentRoutes(app: FastifyInstance) {
  app.post('/commitments', { preHandler: requireApiKey }, async (req, reply) => {
    const parsed = CommitmentBodySchema.safeParse(req.body)
    if (!parsed.success) {
      return reply.code(400).send({ error: 'Invalid request', details: parsed.error.flatten() })
    }
    const { agentId, payloadHash, alg, nonce, expiresAt, agentSignature, agentPubkey } = parsed.data

    if (new Date(expiresAt) <= new Date()) {
      return reply.code(400).send({ error: 'expiresAt must be in the future' })
    }

    let agentKeyThumbprint: string | undefined
    if (agentSignature) {
      const signingPayload = commitmentSigningPayload({ agentId, alg, expiresAt, nonce, payloadHash })
      let valid = false
      try {
        valid = await verifyCanonical(signingPayload, agentSignature, agentPubkey as EcJwk)
      } catch {
        valid = false
      }
      // Invalid agent signature is a hard reject — never a silent downgrade to
      // a weaker binding. The caller asked for agent-committed; give it or fail.
      if (!valid) {
        return reply.code(400).send({ error: 'INVALID_AGENT_SIGNATURE' })
      }
      agentKeyThumbprint = await jwkThumbprint(agentPubkey as EcJwk)
    }

    const commitment: Commitment = {
      commitmentId: `cmt_${nanoid(12)}`,
      agentId,
      payloadHash: payloadHash.toLowerCase(),
      alg,
      nonce,
      agentSignature,
      agentPubkey: agentSignature ? (agentPubkey as EcJwk) : undefined,
      agentKeyThumbprint,
      createdAt: new Date().toISOString(),
      expiresAt,
      consumed: false,
    }

    try {
      store.saveCommitment(commitment)
    } catch (err) {
      if (String(err).includes('UNIQUE')) {
        return reply.code(409).send({ error: 'A commitment with this (agentId, nonce) already exists' })
      }
      throw err
    }

    return reply.code(201).send({ commitmentId: commitment.commitmentId, expiresAt })
  })
}
