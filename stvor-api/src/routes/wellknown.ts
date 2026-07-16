import type { FastifyInstance } from 'fastify'
import { getPublicKeyJwk } from '../crypto.js'
import { getRegistry } from '../registry.js'

export async function wellknownRoutes(app: FastifyInstance) {
  // Current signing key.
  app.get('/.well-known/public-key', async (_req, reply) => {
    return reply.code(200).send(await getPublicKeyJwk())
  })

  // Append-only keyset — lets a receipt verify by its `kid` long after the key
  // that signed it has been rotated out of active use.
  app.get('/.well-known/stvor-keys.json', async (_req, reply) => {
    return reply.code(200).send(getRegistry())
  })
}
