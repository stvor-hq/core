import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { kidOf, type EcJwk } from '@stvor/core'
import { registerCurrentKey } from './registry.js'
import { devMode } from './auth.js'

export interface Issuer {
  privateJwk: EcJwk
  publicJwk: EcJwk
  kid: string
}

const DEV_KEY_PATH = process.env.STVOR_SIGNING_KEY_FILE ?? '.stvor/signing-key.pem'

let _issuer: Issuer | null = null

/**
 * Loads the signing key, in priority order:
 *   1. STVOR_SIGNING_KEY env (raw PKCS8 PEM, or base64-encoded PEM)
 *   2. a PEM file on disk (dev — survives restart)
 *   3. generate + persist a dev key (blocked in production)
 *
 * Every API instance behind a load balancer loads the SAME key, so the public
 * key published at /.well-known is stable across the fleet.
 */
function loadOrCreatePrivateKey(): KeyObject {
  const envKey = process.env.STVOR_SIGNING_KEY?.trim()
  if (envKey) {
    const pem = envKey.includes('BEGIN') ? envKey : Buffer.from(envKey, 'base64').toString('utf8')
    return createPrivateKey(pem)
  }

  if (existsSync(DEV_KEY_PATH)) {
    return createPrivateKey(readFileSync(DEV_KEY_PATH, 'utf8'))
  }

  // No key material and not explicitly in dev → fail closed. Autogenerating a
  // key here would silently produce an ephemeral signer whose receipts stop
  // verifying on the next restart — worse than not booting.
  if (!devMode()) {
    throw new Error('STVOR_SIGNING_KEY must be set (no STVOR_DEV). Generate one with: bun run keygen')
  }

  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string
  mkdirSync(dirname(DEV_KEY_PATH), { recursive: true })
  writeFileSync(DEV_KEY_PATH, pem, { mode: 0o600 })
  console.warn(
    `[stvor] generated dev signing key at ${DEV_KEY_PATH} — set STVOR_SIGNING_KEY in production`
  )
  return privateKey
}

/**
 * The issuer identity. Exported as JWKs so signing goes through @stvor/core —
 * the SAME code path a third party runs offline. Nothing Stvor-specific in the
 * signature: what we sign, anyone verifies.
 */
export async function getIssuer(): Promise<Issuer> {
  if (_issuer) return _issuer

  const privateKeyObj = loadOrCreatePrivateKey()
  const publicKeyObj = createPublicKey(privateKeyObj)

  const priv = privateKeyObj.export({ format: 'jwk' }) as EcJwk // { crv, d, kty, x, y }
  const pub = publicKeyObj.export({ format: 'jwk' }) as EcJwk // { crv, kty, x, y }
  const kid = await kidOf(pub)

  const privateJwk: EcJwk = { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y, d: priv.d }
  const publicJwk: EcJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, kid, use: 'sig', alg: 'ES256' }

  _issuer = { privateJwk, publicJwk, kid }
  registerCurrentKey(kid, { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y })
  return _issuer
}

/** Public JWK for /.well-known/public-key (current key). */
export async function getPublicKeyJwk(): Promise<EcJwk> {
  return (await getIssuer()).publicJwk
}
