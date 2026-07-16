import { signCanonical, verifyCanonical } from './signing.js'
import { resolveKey, type EcJwk, type KeyRegistry } from './keys.js'

export type Decision = 'ALLOW' | 'DENY'

/**
 * What the receipt proves. These definitions are contract-frozen:
 *
 * - `attested`        — Stvor signed these parameters as seen at verify time.
 *                       Says nothing about any prior intent. Does not catch a swap.
 * - `committed`       — the live payload matched a commitment Stvor received
 *                       earlier. Catches destination swap. Still requires trusting
 *                       that the committer (the integrator) posted a genuine
 *                       commitment.
 * - `agent-committed` — the commitment carried a signature from the agent's own
 *                       key, verified by Stvor. Proves the executed payment
 *                       matched what the agent itself committed to, verifiable by
 *                       a third party without trusting the integrator or Stvor.
 */
export type Binding = 'attested' | 'committed' | 'agent-committed'

/**
 * The signed payload. The receipt document is exactly this object plus a
 * `signature` field — a verifier strips `signature`, canonicalizes the rest
 * (RFC 8785), and checks ES256 against the key named by `kid`. No field
 * mapping, no partial coverage: everything in the receipt is signed.
 *
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
  /** RFC 7638 thumbprint of the agent key, when binding = "agent-committed". */
  agentKeyThumbprint?: string
  /** The agent's own signature over the canonical commitment, carried through. */
  agentSignature?: string
  /** Settlement receipts only. */
  txHash?: string
  /** Settlement receipts only: the verification receipt this settles. */
  verificationReceiptId?: string
}

export interface TrustReceipt extends ReceiptPayload {
  signature: string
}

export type ReceiptVerifyResult =
  | { ok: true; receipt: TrustReceipt }
  | { ok: false; reason: 'MALFORMED' | 'UNKNOWN_KEY' | 'BAD_SIGNATURE'; detail?: string }

/** Signs a receipt payload; returns the full receipt document (payload + signature). */
export async function signReceipt(
  payload: ReceiptPayload,
  issuerPrivateJwk: EcJwk
): Promise<TrustReceipt> {
  const signature = await signCanonical(stripUndefined(payload), issuerPrivateJwk)
  return { ...stripUndefined(payload), signature } as TrustReceipt
}

/**
 * Offline receipt verification. Zero network calls — the caller supplies the
 * issuer key material (a single JWK or the published keyset). Deliberately
 * time-independent: a receipt is historical evidence, so wall-clock expiry of
 * the verification window does not invalidate it as an artifact.
 */
export async function verifyReceiptOffline(
  receipt: unknown,
  keys: EcJwk | KeyRegistry
): Promise<ReceiptVerifyResult> {
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { ok: false, reason: 'MALFORMED', detail: 'receipt must be a JSON object' }
  }
  const { signature, ...payload } = receipt as Record<string, unknown>
  if (typeof signature !== 'string' || signature.length === 0) {
    return { ok: false, reason: 'MALFORMED', detail: 'missing signature' }
  }
  if (typeof payload.kid !== 'string' || payload.kid.length === 0) {
    return { ok: false, reason: 'MALFORMED', detail: 'missing kid' }
  }

  const jwk = resolveKey(keys, payload.kid)
  if (!jwk) {
    return { ok: false, reason: 'UNKNOWN_KEY', detail: `no key in keyset for kid ${payload.kid}` }
  }

  let valid: boolean
  try {
    valid = await verifyCanonical(payload, signature, jwk)
  } catch (err) {
    return { ok: false, reason: 'MALFORMED', detail: String(err) }
  }
  if (!valid) {
    return { ok: false, reason: 'BAD_SIGNATURE', detail: 'signature does not match receipt contents' }
  }
  return { ok: true, receipt: receipt as TrustReceipt }
}

function stripUndefined(obj: object): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = v
  }
  return out
}
