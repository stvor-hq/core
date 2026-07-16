import { randomBytes } from 'node:crypto'
import type { Intent } from '@stvor/sdk'

/**
 * A stand-in for OrbWallet — the partner's agentic payment runtime.
 * In reality `.send()` signs and broadcasts an on-chain transaction; here it
 * simulates that and returns a tx hash. The point of the example is the
 * integration *surface*, not the chain.
 */
export class OrbWallet {
  constructor(public readonly address: string) {}

  async send(_intent: Intent): Promise<string> {
    // simulate signing + broadcasting
    await new Promise((r) => setTimeout(r, 40))
    return '0x' + randomBytes(32).toString('hex')
  }
}
