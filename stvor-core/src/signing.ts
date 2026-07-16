import { canonicalBytes, b64uToBytes, bytesToB64u } from './canonical.js'
import { kidOf, type EcJwk } from './keys.js'

/**
 * One signature scheme, everywhere: ECDSA P-256 / SHA-256 (ES256) with raw
 * IEEE-P1363 signatures (r‖s, exactly 64 bytes) — the JWA/RFC 7518 format,
 * which is also what WebCrypto natively produces and consumes. Frozen.
 */
const EC_IMPORT: EcKeyImportParams = { name: 'ECDSA', namedCurve: 'P-256' }
const EC_SIGN: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' }

async function importPrivate(jwk: EcJwk): Promise<CryptoKey> {
  if (!jwk.d) throw new Error('signing key JWK must include "d" (private scalar)')
  const { kty, crv, x, y, d } = jwk
  return crypto.subtle.importKey('jwk', { kty, crv, x, y, d }, EC_IMPORT, false, ['sign'])
}

async function importPublic(jwk: EcJwk): Promise<CryptoKey> {
  const { kty, crv, x, y } = jwk
  return crypto.subtle.importKey('jwk', { kty, crv, x, y }, EC_IMPORT, false, ['verify'])
}

/** Signs the RFC 8785 canonical form of `payload`. Returns base64url(r‖s). */
export async function signCanonical(payload: object, privateJwk: EcJwk): Promise<string> {
  const key = await importPrivate(privateJwk)
  const sig = await crypto.subtle.sign(EC_SIGN, key, canonicalBytes(payload) as BufferSource)
  return bytesToB64u(new Uint8Array(sig))
}

/** Verifies a base64url(r‖s) signature over the RFC 8785 canonical form of `payload`. */
export async function verifyCanonical(
  payload: object,
  signatureB64u: string,
  publicJwk: EcJwk
): Promise<boolean> {
  let sig: Uint8Array
  try {
    sig = b64uToBytes(signatureB64u)
  } catch {
    return false
  }
  if (sig.length !== 64) return false // ES256/P1363 is exactly r(32)‖s(32)
  const key = await importPublic(publicJwk)
  return crypto.subtle.verify(
    EC_SIGN,
    key,
    sig as BufferSource,
    canonicalBytes(payload) as BufferSource
  )
}

export interface GeneratedKeyPair {
  privateJwk: EcJwk
  publicJwk: EcJwk
  kid: string
}

/** Generates a fresh P-256 keypair (e.g. an agent identity key). */
export async function generateKeyPair(): Promise<GeneratedKeyPair> {
  const pair = await crypto.subtle.generateKey(EC_IMPORT, true, ['sign', 'verify'])
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as EcJwk
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as EcJwk
  const kid = await kidOf(publicJwk)
  return {
    privateJwk: { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y, d: privateJwk.d },
    publicJwk: { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y, kid },
    kid,
  }
}
