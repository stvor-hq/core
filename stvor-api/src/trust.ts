import type { Decision } from './types.js'

/** Minimal shape the stub reads — decoupled from the wire Intent on purpose. */
interface TrustInput {
  from?: string
  to?: string
  amount?: number
}

interface TrustComponents {
  escrow: number      // 0–1: whether funds are held in escrow
  quality: number     // 0–1: historical delivery quality
  reliability: number // 0–1: uptime / on-time completion rate
}

interface TrustResult {
  score: number
  decision: Decision
  reason: string
  components: TrustComponents
}

// ATS-1 formula: 0.4·escrow + 0.4·quality + 0.2·reliability
function computeScore(c: TrustComponents): number {
  return +(0.4 * c.escrow + 0.4 * c.quality + 0.2 * c.reliability).toFixed(4)
}

export function evaluate(intent: TrustInput, minTrustScore = 0.3): TrustResult {
  // structural guards
  if (!intent.from?.trim()) {
    return { score: 0, decision: 'DENY', reason: 'Missing intent.from', components: { escrow: 0, quality: 0, reliability: 0 } }
  }
  if (!intent.to?.trim()) {
    return { score: 0, decision: 'DENY', reason: 'Missing intent.to', components: { escrow: 0, quality: 0, reliability: 0 } }
  }
  if (intent.amount !== undefined && intent.amount < 0) {
    return { score: 0, decision: 'DENY', reason: 'Negative amount', components: { escrow: 0, quality: 0, reliability: 0 } }
  }

  // MVP: baseline trust for unknown agents
  // In production this pulls from on-chain registry + historical data
  const components: TrustComponents = {
    escrow: 0.5,      // neutral — no escrow data yet
    quality: 0.5,     // neutral — no delivery history yet
    reliability: 0.6, // slightly optimistic default
  }

  const score = computeScore(components)
  const decision: Decision = score >= minTrustScore ? 'ALLOW' : 'DENY'
  const reason = decision === 'ALLOW'
    ? `Trust score ${score} meets threshold ${minTrustScore}`
    : `Trust score ${score} below threshold ${minTrustScore}`

  return { score, decision, reason, components }
}
