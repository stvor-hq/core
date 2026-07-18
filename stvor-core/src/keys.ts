import { canonicalize, sha256Hex, b64uToBytes, bytesToB64u, bytesToHex } from './canonical.js'

/** P-256 key as JWK. `d` present only on private keys. Stvor's issuer key type. */
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

/** Ed25519 key as JWK (RFC 8037 OKP). `d` present only on private keys. */
export interface OkpJwk {
  kty: 'OKP'
  crv: 'Ed25519'
  x: string
  d?: string
  kid?: string
  use?: string
  alg?: string
}

/**
 * An AGENT key. Whatever the agent already holds — Ed25519 on Solana,
 * P-256 elsewhere. The agent never mints a key type just for Stvor. (Stvor's
 * own issuer key stays EC/P-256; see EcJwk.)
 */
export type AgentJwk = EcJwk | OkpJwk

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

/**
 * RFC 7638 JWK thumbprint, base64url. The required members and their order are
 * NORMATIVE and differ by key type:
 *   EC  → {crv, kty, x, y}
 *   OKP → {crv, kty, x}
 * (RFC 8785 sorts the keys lexicographically, matching RFC 7638's ordering.)
 */
export async function jwkThumbprint(jwk: AgentJwk): Promise<string> {
  const members =
    jwk.kty === 'OKP'
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
  const hex = await sha256Hex(canonicalize(members))
  return bytesToB64u(hexToBytes(hex))
}

/** Stvor key id format: `key_` + first 16 chars of the RFC 7638 thumbprint. */
export async function kidOf(jwk: AgentJwk): Promise<string> {
  return `key_${(await jwkThumbprint(jwk)).slice(0, 16)}`
}

/**
 * Resolves the issuer verification key for a receipt `kid` from either a single
 * JWK or the keyset. Returns null when the kid is unknown — verification must
 * then fail with UNKNOWN_KEY, never fall back to "whatever key we have".
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
