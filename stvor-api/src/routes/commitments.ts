import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { nanoid } from 'nanoid'
import {
  verifyCanonical,
  commitmentSigningPayload,
  jwkThumbprint,
  algForJwk,
  type AgentJwk,
} from '@stvor/core'
import { store } from '../store.js'
import { requireApiKey } from '../auth.js'
import type { Commitment } from '../types.js'

const SUPPORTED = ['EC/P-256 (ES256)', 'OKP/Ed25519 (EdDSA)']

// Loose JWK — the agent key is whatever the agent already holds. We do NOT
// reject unknown types here; algForJwk gives the specific UNSUPPORTED_AGENT_KEY.
const JwkSchema = z
  .object({ kty: z.string().min(1), crv: z.string().min(1), x: z.string().min(1) })
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
 * Freezes the payment invariants (via payloadHash) BEFORE execution. When it
 * carries the agent's own signature, the receipt proves — to any third party,
 * from the receipt + Stvor's key alone — that the executed payment matched what
 * the agent itself committed to. The agent key type is whatever the agent has
 * (Ed25519 on Solana, P-256 elsewhere); Stvor adapts, never demands its own.
 */
export async function commitmentRoutes(app: FastifyInstance) {
  app.post('/commitments', { preHandler: requireApiKey }, async (req, reply) => {
    const parsed = CommitmentBodySchema.safeParse(req.body)
    if (!parsed.success) {
      return reply.code(400).send({ error: 'Invalid request', details: parsed.error.flatten() })
    }
    const { agentId, payloadHash, alg, nonce, expiresAt, agentSignature } = parsed.data
    const agentPubkey = parsed.data.agentPubkey as AgentJwk | undefined

    if (new Date(expiresAt) <= new Date()) {
      return reply.code(400).send({ error: 'expiresAt must be in the future' })
    }

    let agentKeyThumbprint: string | undefined
    if (agentSignature && agentPubkey) {
      // Reject unsupported key types explicitly — distinct from a bad signature.
      try {
        algForJwk(agentPubkey)
      } catch {
        return reply.code(400).send({ error: 'UNSUPPORTED_AGENT_KEY', supported: SUPPORTED })
      }

      const signingPayload = commitmentSigningPayload({ agentId, alg, expiresAt, nonce, payloadHash })
      let valid = false
      try {
        // Dispatches on the DECLARED kty/crv only — never probes the bytes.
        valid = await verifyCanonical(signingPayload, agentSignature, agentPubkey)
      } catch {
        valid = false
      }
      // Invalid agent signature is a hard reject — never a silent downgrade.
      if (!valid) {
        return reply.code(400).send({ error: 'INVALID_AGENT_SIGNATURE' })
      }
      agentKeyThumbprint = await jwkThumbprint(agentPubkey)
    }

    const commitment: Commitment = {
      commitmentId: `cmt_${nanoid(12)}`,
      agentId,
      payloadHash: payloadHash.toLowerCase(),
      alg,
      nonce,
      agentSignature,
      agentPubkey: agentSignature ? publicOnly(agentPubkey!) : undefined,
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

/** Strip any private member before storing/embedding the agent key. */
function publicOnly(jwk: AgentJwk): AgentJwk {
  return jwk.kty === 'OKP'
    ? { kty: 'OKP', crv: 'Ed25519', x: jwk.x }
    : { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
}
