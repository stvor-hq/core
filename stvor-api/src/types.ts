import type { Binding, Decision, TrustReceipt, AgentJwk } from '@stvor/core'

export type { Binding, Decision, TrustReceipt }

/** Live payment intent. `amount` is a decimal STRING, never a JSON number. */
export interface Intent {
  from: string
  to: string
  amount?: string
  currency?: string
  chain?: string
  asset?: string
  payload?: string
  metadata?: Record<string, unknown>
}

/**
 * The stored decision. Carries every field the receipt binds — the receipt is
 * minted from THIS record, never from a later request body, so an attacker
 * cannot declare A and receipt B.
 */
export interface Client {
  keyId: string
  keyHash: string
  name: string
  env: 'test' | 'live'
  createdAt: string
  revokedAt?: string
}

export interface Verification {
  id: string
  decision: Decision
  reason: string
  binding: Binding
  /** Which API client made this call (key_id), or 'root'/'dev'. */
  clientId: string
  agentId: string
  to: string
  amount?: string
  currency?: string
  chain?: string
  asset?: string
  nonce: string
  commitmentId?: string
  /** The signed verification receipt, stored so re-reads are byte-identical. */
  receipt: TrustReceipt
  createdAt: string
  expiresAt: string
  settled: boolean
}

export interface Commitment {
  commitmentId: string
  agentId: string
  payloadHash: string
  alg: 'sha256'
  nonce: string
  /** Present only when the agent signed the commitment (binding: agent-committed). */
  agentSignature?: string
  /** The agent's own key — Ed25519 (OKP) or P-256 (EC), whatever it holds. */
  agentPubkey?: AgentJwk
  agentKeyThumbprint?: string
  createdAt: string
  expiresAt: string
  consumed: boolean
}

/** A settlement receipt: the ALLOW verification receipt plus an on-chain txHash. */
export interface Settlement {
  verificationId: string
  txHash: string
  receipt: TrustReceipt
  issuedAt: string
}
