import {
  generateKeyPair,
  hashPaymentPayload,
  signCanonical,
  commitmentSigningPayload,
  verifyReceiptOffline,
  type EcJwk,
  type AgentJwk,
  type KeyRegistry,
  type TrustReceipt,
  type ReceiptVerifyResult,
} from '@stvor/core'
import {
  StvorError,
  type StvorConfig,
  type Intent,
  type VerifyOptions,
  type VerificationResult,
  type CommitOptions,
  type CommitResult,
  type PaymentPayloadInput,
  type FailMode,
} from './types.js'

const DEFAULT_BASE_URL = 'https://api.stvor.xyz'

/** Exponential backoff with jitter: ~250ms, ~500ms, ~1s ... */
function backoff(attempt: number): number {
  const base = 250 * 2 ** attempt
  return base + Math.random() * base * 0.25
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export class Stvor {
  private readonly baseUrl: string
  private readonly headers: Record<string, string>
  private readonly timeoutMs: number
  private readonly maxRetries: number
  private readonly onError: FailMode
  private _keys?: KeyRegistry

  constructor(config: StvorConfig) {
    if (!config.apiKey) throw new Error('Stvor: apiKey is required')
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '')
    this.timeoutMs = config.timeoutMs ?? 10_000
    this.maxRetries = config.maxRetries ?? 2
    this.onError = config.onError ?? 'allow'
    this.headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`,
    }
  }

  /**
   * Transport. Throws StvorError for deterministic 4xx (never retried), and for
   * transport failure (timeout / network / exhausted 5xx|429) with status 0 so
   * callers can distinguish "Stvor said no" from "Stvor was unreachable".
   */
  private async request<T>(method: string, path: string, body?: unknown, timeoutMs?: number): Promise<T> {
    let lastErr: unknown
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs ?? this.timeoutMs)
      try {
        const res = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers: this.headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        })
        if ((res.status === 429 || res.status >= 500) && attempt < this.maxRetries) {
          const retryAfter = Number(res.headers.get('retry-after'))
          await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : backoff(attempt))
          continue
        }
        const data = await res.json().catch(() => ({}))
        if (!res.ok) {
          throw new StvorError((data as { error?: string }).error ?? `HTTP ${res.status}`, res.status, data)
        }
        return data as T
      } catch (err) {
        if (err instanceof StvorError) throw err
        lastErr = err
        if (attempt < this.maxRetries) {
          await sleep(backoff(attempt))
          continue
        }
      } finally {
        clearTimeout(timer)
      }
    }
    throw new StvorError(`Stvor unreachable: ${String(lastErr)}`, 0, lastErr)
  }

  /**
   * Posts a commitment freezing the payment invariants BEFORE execution. If an
   * agent private key is supplied, signs the commitment so the resulting receipt
   * is agent-committed (third-party verifiable without trusting Stvor).
   */
  async commit(payment: PaymentPayloadInput, opts: CommitOptions = {}): Promise<CommitResult> {
    const agentId = opts.agentId ?? payment.to // caller should usually pass agentId explicitly
    const payloadHash = await hashPaymentPayload(payment)
    const nonce = opts.nonce ?? crypto.randomUUID()
    const expiresAt = opts.expiresAt ?? new Date(Date.now() + 5 * 60 * 1000).toISOString()

    const body: Record<string, unknown> = { agentId, payloadHash, alg: 'sha256', nonce, expiresAt }

    if (opts.agentPrivateJwk) {
      body.agentSignature = await signCanonical(
        commitmentSigningPayload({ agentId, alg: 'sha256', expiresAt, nonce, payloadHash }),
        opts.agentPrivateJwk
      )
      body.agentPubkey = opts.agentPubkey ?? publicPart(opts.agentPrivateJwk)
    }
    return this.request<CommitResult>('POST', '/commitments', body)
  }

  /**
   * Pre-execution verification. On a Stvor transport failure applies the fail
   * mode (default "allow"): payments do not halt because Stvor blipped, but the
   * skip is explicit — degraded:true, receipt:null — so it is logged, counted
   * and never mistaken for a real ALLOW. A DENY or a 4xx is NOT a transport
   * failure and always passes through unchanged.
   */
  async verify(intent: Intent, options: VerifyOptions = {}): Promise<VerificationResult> {
    const onError = options.onError ?? this.onError
    const timeoutMs = options.timeoutMs ?? this.timeoutMs
    const payload = {
      intent,
      commitmentId: options.commitmentId,
      agentId: options.agentId,
      nonce: options.nonce,
      policy: options.policy,
    }
    try {
      return await this.request<VerificationResult>('POST', '/verify', payload, timeoutMs)
    } catch (err) {
      // Deterministic API rejection (4xx) → surface it; not a degraded path.
      if (err instanceof StvorError && err.status !== 0) throw err
      if (onError === 'throw') throw err
      return {
        id: null,
        decision: onError === 'allow' ? 'ALLOW' : 'DENY',
        reason: 'STVOR_UNREACHABLE',
        binding: 'attested',
        receipt: null,
        expiresAt: null,
        degraded: true,
      }
    }
  }

  /** Attach an on-chain txHash after settlement → signed settlement receipt. */
  async settle(verificationId: string, txHash: string): Promise<TrustReceipt> {
    return this.request<TrustReceipt>('POST', '/receipt', { verificationId, txHash })
  }

  /** Deprecated alias for settle(). */
  async receipt(verificationId: string, txHash: string): Promise<TrustReceipt> {
    return this.settle(verificationId, txHash)
  }

  /** The published append-only keyset (cached). */
  async keyset(): Promise<KeyRegistry> {
    if (this._keys) return this._keys
    const res = await fetch(`${this.baseUrl}/.well-known/stvor-keys.json`)
    if (!res.ok) throw new StvorError('Failed to fetch keyset', res.status, {})
    this._keys = (await res.json()) as KeyRegistry
    return this._keys
  }

  /**
   * Verifies a Trust Receipt. With `{ jwk }` or `{ keys }` this is fully offline
   * — zero network calls, the "anyone can verify with just the math" guarantee.
   * Without key material it fetches the published keyset once and verifies by
   * the receipt's kid (so rotation does not break old receipts).
   */
  async verifyReceipt(
    receipt: TrustReceipt,
    opts?: { jwk?: EcJwk; keys?: KeyRegistry }
  ): Promise<boolean> {
    return (await this.verifyReceiptDetailed(receipt, opts)).ok
  }

  /**
   * Full structured verification result: which signatures checked out. For an
   * `agent-committed` receipt this reports BOTH the issuer and the embedded
   * agent signature — the complete proof, offline, from the receipt + key alone.
   */
  async verifyReceiptDetailed(
    receipt: TrustReceipt,
    opts?: { jwk?: EcJwk; keys?: KeyRegistry }
  ): Promise<ReceiptVerifyResult> {
    const keys = opts?.jwk ?? opts?.keys ?? (await this.keyset())
    return verifyReceiptOffline(receipt, keys)
  }
}

/** Public members only — Ed25519 (OKP) or P-256 (EC). */
function publicPart(jwk: AgentJwk): AgentJwk {
  return jwk.kty === 'OKP'
    ? { kty: 'OKP', crv: 'Ed25519', x: jwk.x }
    : { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
}

export { generateKeyPair }
