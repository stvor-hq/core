import { ed25519 } from '@noble/curves/ed25519.js'
import { canonicalBytes, b64uToBytes, bytesToB64u } from './canonical.js'
import { kidOf, type EcJwk, type OkpJwk, type AgentJwk } from './keys.js'

/** JOSE signature algorithm. */
export type SigAlg = 'ES256' | 'EdDSA'

/**
 * Algorithm registry, keyed on the JWK — NOT an `if (ed25519)` fork. The key
 * type is whatever the caller already holds; Stvor dispatches. Issuer receipts
 * stay ES256/P-256 (WebCrypto). Agents may be Ed25519 (Solana) or P-256.
 *
 *   EC  / P-256     → ES256  (WebCrypto)
 *   OKP / Ed25519   → EdDSA  (@noble, pure-JS so the browser verifier works
 *                             offline on any engine, where WebCrypto Ed25519
 *                             support is uneven)
 *   EC  / secp256k1 → ES256K (slot reserved, not built)
 */
export function algForJwk(jwk: { kty?: string; crv?: string }): SigAlg {
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256'
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA'
  if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') {
    throw new Error('UNSUPPORTED_AGENT_KEY: EC/secp256k1 (ES256K) is reserved but not implemented')
  }
  throw new Error(
    `UNSUPPORTED_AGENT_KEY: kty=${jwk.kty} crv=${jwk.crv} (supported: EC/P-256 → ES256, OKP/Ed25519 → EdDSA)`
  )
}

// --- ES256 (P-256, WebCrypto) ----------------------------------------------
const EC_IMPORT: EcKeyImportParams = { name: 'ECDSA', namedCurve: 'P-256' }
const EC_SIGN: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' }

async function signES256(bytes: Uint8Array, jwk: EcJwk): Promise<string> {
  if (!jwk.d) throw new Error('signing key JWK must include "d" (private scalar)')
  const { kty, crv, x, y, d } = jwk
  const key = await crypto.subtle.importKey('jwk', { kty, crv, x, y, d }, EC_IMPORT, false, ['sign'])
  const sig = await crypto.subtle.sign(EC_SIGN, key, bytes as BufferSource)
  return bytesToB64u(new Uint8Array(sig))
}

async function verifyES256(bytes: Uint8Array, sig: Uint8Array, jwk: EcJwk): Promise<boolean> {
  if (sig.length !== 64) return false // ES256/IEEE-P1363 is exactly r(32)‖s(32)
  const { kty, crv, x, y } = jwk
  const key = await crypto.subtle.importKey('jwk', { kty, crv, x, y }, EC_IMPORT, false, ['verify'])
  return crypto.subtle.verify(EC_SIGN, key, sig as BufferSource, bytes as BufferSource)
}

// --- EdDSA (Ed25519, @noble) ------------------------------------------------
function signEd25519(bytes: Uint8Array, jwk: OkpJwk): string {
  if (!jwk.d) throw new Error('signing key JWK must include "d" (private seed)')
  return bytesToB64u(ed25519.sign(bytes, b64uToBytes(jwk.d)))
}

function verifyEd25519(bytes: Uint8Array, sig: Uint8Array, jwk: OkpJwk): boolean {
  if (sig.length !== 64) return false
  try {
    return ed25519.verify(sig, bytes, b64uToBytes(jwk.x))
  } catch {
    return false
  }
}

/** Signs the RFC 8785 canonical form of `payload` with the key's own algorithm. */
export async function signCanonical(payload: object, privateJwk: AgentJwk): Promise<string> {
  const bytes = canonicalBytes(payload)
  return algForJwk(privateJwk) === 'EdDSA'
    ? signEd25519(bytes, privateJwk as OkpJwk)
    : signES256(bytes, privateJwk as EcJwk)
}

/**
 * Verifies a base64url signature over the RFC 8785 canonical form of `payload`.
 * Dispatch is ONLY on the declared key type. An Ed25519 signature and an ES256
 * IEEE-P1363 signature are BOTH 64 raw bytes — indistinguishable by shape — so
 * we never probe the bytes to guess the algorithm. A cross-algorithm attempt
 * (Ed25519 bytes against a declared P-256 key) simply fails.
 */
export async function verifyCanonical(
  payload: object,
  signatureB64u: string,
  publicJwk: AgentJwk
): Promise<boolean> {
  let alg: SigAlg
  try {
    alg = algForJwk(publicJwk)
  } catch {
    return false // unsupported key type → not verifiable, never a silent pass
  }
  let sig: Uint8Array
  try {
    sig = b64uToBytes(signatureB64u)
  } catch {
    return false
  }
  const bytes = canonicalBytes(payload)
  return alg === 'EdDSA'
    ? verifyEd25519(bytes, sig, publicJwk as OkpJwk)
    : verifyES256(bytes, sig, publicJwk as EcJwk)
}

export interface GeneratedKeyPair {
  privateJwk: AgentJwk
  publicJwk: AgentJwk
  kid: string
}

/** Generates a fresh agent keypair. Default P-256; pass 'EdDSA' for Ed25519. */
export async function generateKeyPair(alg: SigAlg = 'ES256'): Promise<GeneratedKeyPair> {
  if (alg === 'EdDSA') {
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const pub = ed25519.getPublicKey(seed)
    const publicJwk: OkpJwk = { kty: 'OKP', crv: 'Ed25519', x: bytesToB64u(pub) }
    const kid = await kidOf(publicJwk)
    return {
      privateJwk: { kty: 'OKP', crv: 'Ed25519', x: bytesToB64u(pub), d: bytesToB64u(seed) },
      publicJwk: { ...publicJwk, kid },
      kid,
    }
  }
  const pair = await crypto.subtle.generateKey(EC_IMPORT, true, ['sign', 'verify'])
  const priv = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as EcJwk
  const pub = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as EcJwk
  const publicJwk: EcJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y }
  const kid = await kidOf(publicJwk)
  return {
    privateJwk: { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y, d: priv.d },
    publicJwk: { ...publicJwk, kid },
    kid,
  }
}
