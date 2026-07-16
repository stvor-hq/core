import { createHash, timingSafeEqual } from 'node:crypto'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { store } from './store.js'

/** Read lazily so config changes (and tests) are honored without re-import. */
function masterKey(): string | undefined {
  return process.env.STVOR_KEY?.trim() || undefined
}

/**
 * Open mode is OPT-IN, never inferred. Safety must not hinge on NODE_ENV being
 * present: if it silently isn't, we must still fail closed, not fling the API
 * open. So the ONLY way to run without auth (or to autogenerate a signing key)
 * is to explicitly set STVOR_DEV=1 — which production never does.
 */
export function devMode(): boolean {
  return process.env.STVOR_DEV === '1'
}

declare module 'fastify' {
  interface FastifyRequest {
    /** The authenticated caller: a client key_id, or 'root' (master key) / 'dev'. */
    clientId?: string
  }
}

/**
 * Fail-closed guard, independent of NODE_ENV. Refuse to boot open unless
 * STVOR_DEV=1 is explicitly set. Call once at boot, before listen().
 */
export function assertAuthConfig(): void {
  if (!masterKey() && !store.hasClients() && !devMode()) {
    throw new Error(
      'Refusing to run open: set STVOR_KEY (or issue a client key). Local dev only: STVOR_DEV=1.'
    )
  }
}

/** Resolve the caller to a clientId, or null if unauthenticated. No side effects. */
function resolveClient(req: FastifyRequest): string | null {
  const master = masterKey()
  const header = req.headers.authorization ?? ''
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : ''

  // Open mode: explicitly enabled AND no credentials configured.
  if (!master && !store.hasClients() && devMode()) return 'dev'

  if (token) {
    // Per-client keys: look up by SHA-256 of the token (GitHub-style). We never
    // store the key itself; an indexed hash lookup has no timing oracle over a
    // full 256-bit digest.
    const client = store.getClientByHash(createHash('sha256').update(token).digest('hex'))
    if (client && !client.revokedAt) return client.keyId
    // Master key → 'root' (your own calls, /stats, admin).
    if (master) {
      const actual = createHash('sha256').update(token).digest()
      const expected = createHash('sha256').update(master).digest()
      if (timingSafeEqual(actual, expected)) return 'root'
    }
  }
  return null
}

/** Any authenticated caller (partner or root). */
export async function requireApiKey(req: FastifyRequest, reply: FastifyReply) {
  const id = resolveClient(req)
  if (!id) return reply.code(401).send({ error: 'Invalid or missing API key' })
  req.clientId = id
}

/**
 * Root only — the master key (or local dev). Guards cross-client data like
 * /stats: a partner's own key must NOT read every client's traffic.
 */
export async function requireRoot(req: FastifyRequest, reply: FastifyReply) {
  const id = resolveClient(req)
  if (!id) return reply.code(401).send({ error: 'Invalid or missing API key' })
  req.clientId = id
  if (id !== 'root' && id !== 'dev') {
    return reply.code(403).send({ error: 'Root key required' })
  }
}
