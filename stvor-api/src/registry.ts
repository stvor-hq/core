import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { EcJwk, KeyRegistry, KeyRegistryEntry } from '@stvor/core'

/** Read lazily so the path always reflects current config (and stays testable). */
function keysPath(): string {
  return process.env.STVOR_KEYS_FILE ?? '.stvor/keys.json'
}

/**
 * Append-only, file-backed key registry. Served verbatim at
 * /.well-known/stvor-keys.json. Rotation appends a new entry and closes the
 * previous one's validity window — it never removes a key, so a receipt signed
 * a year ago still resolves its kid and verifies. That durability is the whole
 * point: proof must survive a dispute long after the key stops signing.
 */
function load(): KeyRegistry {
  const path = keysPath()
  if (!existsSync(path)) return { keys: [] }
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as KeyRegistry
    return parsed?.keys ? parsed : { keys: [] }
  } catch {
    return { keys: [] }
  }
}

function persist(reg: KeyRegistry): void {
  const path = keysPath()
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(reg, null, 2), { mode: 0o600 })
}

/**
 * Ensures the current signing key is present in the registry. If a different
 * key was previously current, closes its window (notAfter = now). Idempotent.
 */
export function registerCurrentKey(kid: string, publicJwk: EcJwk): KeyRegistry {
  const reg = load()
  if (reg.keys.some((k) => k.kid === kid)) return reg

  const now = new Date().toISOString()
  for (const entry of reg.keys) {
    if (!entry.notAfter) entry.notAfter = now // retire the previously-open key
  }
  const entry: KeyRegistryEntry = { kid, jwk: { ...publicJwk, kid }, notBefore: now }
  reg.keys.push(entry)
  persist(reg)
  return reg
}

export function getRegistry(): KeyRegistry {
  return load()
}
