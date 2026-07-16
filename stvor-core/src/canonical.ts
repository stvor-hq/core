import jcs from 'canonicalize'

/**
 * RFC 8785 (JSON Canonicalization Scheme) via the `canonicalize` library.
 * This is THE canonical form for everything Stvor signs or hashes. A one-byte
 * divergence between two serializers means every verify fails — so nobody
 * hand-rolls this, and test vectors in fixtures/ pin the exact bytes.
 */
export function canonicalize(value: unknown): string {
  const out = jcs(value)
  if (typeof out !== 'string') {
    throw new Error('canonicalize: value is not JSON-serializable')
  }
  return out
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value))
}

/** SHA-256 over raw bytes (or the UTF-8 bytes of a string), as lowercase hex. */
export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource)
  return bytesToHex(new Uint8Array(digest))
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return hex
}

/** base64url -> bytes, portable across browser / Node / Bun (no Buffer). */
export function b64uToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

/** bytes -> base64url, portable across browser / Node / Bun (no Buffer). */
export function bytesToB64u(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
