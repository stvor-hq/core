import { createHash, randomBytes } from 'node:crypto'

export type KeyEnv = 'test' | 'live'

export interface NewClientKey {
  /** The full secret — shown to the operator ONCE, never stored. */
  fullKey: string
  /** Public, non-secret id shown in the dashboard. */
  keyId: string
  /** SHA-256(fullKey), hex — this is what we persist. */
  keyHash: string
}

/**
 * Mints a client key. The `stvor_test_` / `stvor_live_` prefix is not cosmetic:
 * GitHub-style secret scanners key off it, so a leaked key is caught fast.
 */
export function newClientKey(env: KeyEnv): NewClientKey {
  const secret = randomBytes(24).toString('base64url')
  const fullKey = `stvor_${env}_${secret}`
  return {
    fullKey,
    keyId: `ck_${randomBytes(5).toString('hex')}`,
    keyHash: hashKey(fullKey),
  }
}

export function hashKey(fullKey: string): string {
  return createHash('sha256').update(fullKey).digest('hex')
}
