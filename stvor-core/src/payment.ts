import { canonicalize, sha256Hex } from './canonical.js'

/**
 * Amounts are decimal STRINGS on the wire — "50.00", never 50.0. Floats do
 * not survive canonicalization across languages; strings do.
 */
export const AMOUNT_REGEX = /^(0|[1-9]\d*)(\.\d+)?$/

/**
 * The payment invariants — the exact set of fields a commitment freezes and a
 * receipt binds. Nothing that legally changes between intent and execution
 * (gas, timestamps, slippage, rail nonces) belongs here: over-committing
 * produces false DENYs on honest payments, which is how systems like this die.
 */
export interface PaymentPayload {
  to: string
  amount?: string
  currency?: string
  chain?: string
  asset?: string
}

/**
 * Extracts the payment invariants from a larger intent, omitting absent
 * fields entirely (never null — keeps the canonical form stable).
 */
export function paymentPayloadOf(intent: {
  to: string
  amount?: string
  currency?: string
  chain?: string
  asset?: string
}): PaymentPayload {
  if (!intent.to || typeof intent.to !== 'string') {
    throw new Error('payment payload requires a non-empty "to"')
  }
  if (intent.amount !== undefined) {
    if (typeof intent.amount !== 'string' || !AMOUNT_REGEX.test(intent.amount)) {
      throw new Error('amount must be a decimal string, e.g. "50.00" (never a JSON number)')
    }
  }
  const p: PaymentPayload = { to: intent.to }
  if (intent.amount !== undefined) p.amount = intent.amount
  if (intent.currency !== undefined) p.currency = intent.currency
  if (intent.chain !== undefined) p.chain = intent.chain
  if (intent.asset !== undefined) p.asset = intent.asset
  return p
}

/** SHA-256 hex over the RFC 8785 canonical payment payload. This is `payloadHash`. */
export async function hashPaymentPayload(payload: PaymentPayload): Promise<string> {
  return sha256Hex(canonicalize(paymentPayloadOf(payload)))
}

/**
 * What an agent signs when it commits: the commitment envelope, not the raw
 * payment (the payment is already inside via payloadHash).
 */
export interface CommitmentSigningPayload {
  agentId: string
  alg: 'sha256'
  expiresAt: string
  nonce: string
  payloadHash: string
}

/** Builds the exact object whose canonical bytes the agent signs. */
export function commitmentSigningPayload(c: {
  agentId: string
  alg: 'sha256'
  expiresAt: string
  nonce: string
  payloadHash: string
}): CommitmentSigningPayload {
  return {
    agentId: c.agentId,
    alg: c.alg,
    expiresAt: c.expiresAt,
    nonce: c.nonce,
    payloadHash: c.payloadHash,
  }
}
