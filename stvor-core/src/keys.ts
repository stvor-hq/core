import { canonicalize, sha256Hex, b64uToBytes, bytesToB64u, bytesToHex } from './canonical.js'

/** P-256 key as JWK. `d` present only on private keys. */
export interface EcJwk {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
  d?: string
  kid?: string
  use?: string
  alg?: string
}

export interface KeyRegistryEntry {
  kid: string
  jwk: EcJwk
  notBefore: string
  notAfter?: string
}

/** Append-only issuer keyset served at /.well-known/stvor-keys.json. */
export interface KeyRegistry {
  keys: KeyRegistryEntry[]
}

/** RFC 7638 JWK thumbprint (EC members crv,kty,x,y in lexicographic order), base64url. */
export async function jwkThumbprint(jwk: Pick<EcJwk, 'kty' | 'crv' | 'x' | 'y'>): Promise<string> {
  const canonical = canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  const hex = await sha256Hex(canonical)
  return bytesToB64u(hexToBytes(hex))
}

/** Stvor key id format: `key_` + first 16 chars of the RFC 7638 thumbprint. */
export async function kidOf(jwk: Pick<EcJwk, 'kty' | 'crv' | 'x' | 'y'>): Promise<string> {
  return `key_${(await jwkThumbprint(jwk)).slice(0, 16)}`
}

/**
 * Resolves the verification key for a receipt `kid` from either a single JWK
 * or a keyset (registry). Returns null when the kid is unknown — verification
 * must then fail with UNKNOWN_KEY, never fall back to "whatever key we have".
 */
export function resolveKey(source: EcJwk | KeyRegistry, kid: string): EcJwk | null {
  if (isRegistry(source)) {
    for (const entry of source.keys) {
      if (entry.kid === kid || entry.jwk?.kid === kid) return entry.jwk
    }
    return null
  }
  if (source.kid && source.kid !== kid) return null
  return source
}

function isRegistry(source: EcJwk | KeyRegistry): source is KeyRegistry {
  return Array.isArray((source as KeyRegistry).keys)
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

export { b64uToBytes, bytesToB64u, bytesToHex }
