import { signCanonical, verifyCanonical, type SigAlg } from './signing.js'
import { resolveKey, type EcJwk, type AgentJwk, type KeyRegistry } from './keys.js'
import type { CommitmentSigningPayload } from './payment.js'

export type Decision = 'ALLOW' | 'DENY'

/**
 * What the receipt proves. Contract-frozen:
 *
 * - `attested`        — Stvor signed these parameters as seen at verify time.
 *                       Says nothing about any prior intent. Does not catch a swap.
 * - `committed`       — the live payload matched a commitment Stvor received
 *                       earlier. Catches destination swap. Still requires trusting
 *                       that the committer (the integrator) posted a genuine
 *                       commitment.
 * - `agent-committed` — the commitment carried a signature from the agent's OWN
 *                       key (embedded in the receipt). Proves the executed
 *                       payment matched what the agent itself committed to,
 *                       verifiable by a third party from the receipt + Stvor's
 *                       published key alone — no trust in the integrator or Stvor.
 */
export type Binding = 'attested' | 'committed' | 'agent-committed'

/**
 * The signed payload. The receipt document is exactly this object plus a
 * `signature` field. Everything here is inside the issuer signature.
 * Absent optional fields are omitted entirely, never null.
 */
export interface ReceiptPayload {
  receiptId: string
  verificationId: string
  binding: Binding
  agentId: string
  to: string
  amount?: string
  currency?: string
  chain?: string
  asset?: string
  nonce: string
  decision: Decision
  reason: string
  issuedAt: string
  expiresAt: string
  kid: string
  commitmentId?: string
  // --- agent-committed proof (all inside the issuer signature) ---
  /** The agent's FULL public key. Without this, `agent-committed` could not be
   *  verified from the receipt alone — a thumbprint is a hash, and you cannot
   *  verify a signature against a hash. This is the field that makes the
   *  neutrality claim true: receipt + Stvor's key = complete verification. */
  agentPubkey?: AgentJwk
  /** JOSE alg of the agent signature, so the verifier never guesses. */
  agentSigAlg?: SigAlg
  /** The exact envelope the agent signed. Carried explicitly because a DENY
   *  receipt's to/amount are the ATTEMPTED payload, which does NOT hash to the
   *  committed payloadHash — so the verifier cannot recompute it. */
  agentCommitment?: CommitmentSigningPayload
  /** RFC 7638 thumbprint of the agent key — convenience only. */
  agentKeyThumbprint?: string
  /** The agent's signature over JCS(agentCommitment). */
  agentSignature?: string
  /** Settlement receipts only. */
  txHash?: string
  /** Settlement receipts only: the verification receipt this settles. */
  verificationReceiptId?: string
}

export interface TrustReceipt extends ReceiptPayload {
  signature: string
}

export interface ReceiptVerifyResult {
  ok: boolean
  binding?: Binding
  issuerSignature: 'valid' | 'invalid' | 'unknown_key'
  agentSignature: 'valid' | 'invalid' | 'not_applicable'
  reason?: string
  detail?: string
  receipt?: TrustReceipt
}

/** Signs a receipt payload; returns the full receipt document (payload + signature). */
export async function signReceipt(
  payload: ReceiptPayload,
  issuerPrivateJwk: EcJwk
): Promise<TrustReceipt> {
  const clean = stripUndefined(payload)
  const signature = await signCanonical(clean, issuerPrivateJwk)
  return { ...clean, signature } as TrustReceipt
}

/**
 * Offline receipt verification. ZERO network, ZERO other input — the caller
 * supplies only the issuer key material (a JWK or the published keyset); the
 * agent's key is embedded in the receipt. For `agent-committed`, BOTH signatures
 * are checked: Stvor's over the whole receipt, and the agent's over its
 * commitment envelope. Time-independent: a receipt is historical evidence.
 */
export async function verifyReceiptOffline(
  receipt: unknown,
  keys: EcJwk | KeyRegistry
): Promise<ReceiptVerifyResult> {
  const fail = (
    reason: string,
    detail: string,
    over: Partial<ReceiptVerifyResult> = {}
  ): ReceiptVerifyResult => ({
    ok: false,
    issuerSignature: 'invalid',
    agentSignature: 'not_applicable',
    reason,
    detail,
    ...over,
  })

  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return fail('MALFORMED', 'receipt must be a JSON object')
  }
  const { signature, ...payload } = receipt as Record<string, unknown>
  if (typeof signature !== 'string' || signature.length === 0) {
    return fail('MALFORMED', 'missing signature')
  }
  if (typeof payload.kid !== 'string' || payload.kid.length === 0) {
    return fail('MALFORMED', 'missing kid')
  }
  const binding = payload.binding as Binding | undefined

  // 1. Issuer signature over the whole receipt.
  const issuerKey = resolveKey(keys, payload.kid)
  if (!issuerKey) {
    return fail('UNKNOWN_KEY', `no key in keyset for kid ${payload.kid}`, {
      binding,
      issuerSignature: 'unknown_key',
    })
  }
  let issuerValid: boolean
  try {
    issuerValid = await verifyCanonical(payload, signature, issuerKey)
  } catch (err) {
    return fail('MALFORMED', String(err), { binding })
  }
  if (!issuerValid) {
    return fail('BAD_ISSUER_SIGNATURE', 'issuer signature does not match receipt contents', { binding })
  }

  // 2. Agent signature (agent-committed only), from the EMBEDDED agent key.
  if (binding === 'agent-committed') {
    const agentPubkey = payload.agentPubkey as AgentJwk | undefined
    const agentSignature = payload.agentSignature as string | undefined
    const agentCommitment = payload.agentCommitment as CommitmentSigningPayload | undefined
    if (!agentPubkey || !agentSignature || !agentCommitment) {
      return {
        ok: false,
        binding,
        issuerSignature: 'valid',
        agentSignature: 'invalid',
        reason: 'AGENT_PROOF_MISSING',
        detail: 'agent-committed receipt is missing agentPubkey / agentSignature / agentCommitment',
      }
    }
    let agentValid: boolean
    try {
      agentValid = await verifyCanonical(agentCommitment, agentSignature, agentPubkey)
    } catch (err) {
      agentValid = false
      void err
    }
    if (!agentValid) {
      return {
        ok: false,
        binding,
        issuerSignature: 'valid',
        agentSignature: 'invalid',
        reason: 'BAD_AGENT_SIGNATURE',
        detail: 'agent signature does not match the committed envelope',
      }
    }
    return {
      ok: true,
      binding,
      issuerSignature: 'valid',
      agentSignature: 'valid',
      receipt: receipt as TrustReceipt,
    }
  }

  return {
    ok: true,
    binding,
    issuerSignature: 'valid',
    agentSignature: 'not_applicable',
    receipt: receipt as TrustReceipt,
  }
}

function stripUndefined(obj: object): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = v
  }
  return out
}
