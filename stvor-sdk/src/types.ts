import type {
  EcJwk,
  OkpJwk,
  AgentJwk,
  KeyRegistry,
  TrustReceipt,
  Binding,
  Decision,
  SigAlg,
  ReceiptVerifyResult,
} from '@stvor/core'

export type {
  EcJwk,
  OkpJwk,
  AgentJwk,
  KeyRegistry,
  TrustReceipt,
  Binding,
  Decision,
  SigAlg,
  ReceiptVerifyResult,
}

/** allow | deny → a degraded decision on Stvor transport failure; throw → surface the error. */
export type FailMode = 'allow' | 'deny' | 'throw'

export interface StvorConfig {
  apiKey: string
  baseUrl?: string // defaults to https://api.stvor.xyz
  timeoutMs?: number // per-request timeout, default 10000
  maxRetries?: number // retries on network error / 429 / 5xx, default 2
  /** Default fail mode for verify() when Stvor is unreachable. Pilot default: "allow". */
  onError?: FailMode
}

export interface Intent {
  from: string
  to: string
  amount?: string // decimal string, e.g. "50.00" — never a number
  currency?: string
  chain?: string
  asset?: string
  payload?: string
  metadata?: Record<string, unknown>
}

export interface VerifyOptions {
  commitmentId?: string
  agentId?: string
  nonce?: string
  policy?: { minTrustScore?: number }
  /** Override the client default for this call. */
  onError?: FailMode
  timeoutMs?: number
}

export interface VerificationResult {
  id: string | null
  decision: Decision
  reason: string
  binding: Binding
  receipt: TrustReceipt | null
  expiresAt: string | null
  /** true when this decision came from the fail mode, not from Stvor. */
  degraded?: boolean
}

export interface CommitOptions {
  agentId?: string // defaults to payment-derived agent; usually the payer
  nonce?: string
  expiresAt?: string // ISO; default now + 5 min
  /** Provide to produce an agent-committed binding: Stvor verifies this signature.
   *  Ed25519 (OKP) or P-256 (EC) — whatever the agent already holds. */
  agentPrivateJwk?: AgentJwk
  agentPubkey?: AgentJwk
}

export interface CommitResult {
  commitmentId: string
  expiresAt: string
}

export interface PaymentPayloadInput {
  to: string
  amount?: string
  currency?: string
  chain?: string
  asset?: string
}

export class StvorError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body: unknown
  ) {
    super(message)
    this.name = 'StvorError'
  }
}
