import Fastify, { type FastifyInstance } from 'fastify'
import cors from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'
import { verifyRoutes } from './routes/verify.js'
import { receiptRoutes } from './routes/receipt.js'
import { commitmentRoutes } from './routes/commitments.js'
import { statsRoutes } from './routes/stats.js'
import { wellknownRoutes } from './routes/wellknown.js'
import { assertAuthConfig } from './auth.js'
import { getIssuer } from './crypto.js'

export interface BuildOptions {
  logger?: boolean
  rateLimit?: boolean
}

/**
 * Builds the Fastify app without listening — so tests drive it via `.inject()`
 * and production drives it via `.listen()`. Same wiring either way.
 */
export async function buildApp(opts: BuildOptions = {}): Promise<FastifyInstance> {
  // Fail-closed: refuse to boot an open server in production.
  assertAuthConfig()

  // Warm the issuer key: fail fast on bad key material, and register the
  // current key in the append-only keyset before serving any request.
  await getIssuer()

  const app = Fastify({
    logger: opts.logger ?? true,
    bodyLimit: 64 * 1024, // 64 KB — intents are small; caps payload-flood DoS
  })

  await app.register(cors, { origin: true })

  if (opts.rateLimit ?? true) {
    await app.register(rateLimit, {
      max: Number(process.env.STVOR_RATE_MAX ?? 120),
      timeWindow: process.env.STVOR_RATE_WINDOW ?? '1 minute',
    })
  }

  await app.register(commitmentRoutes)
  await app.register(verifyRoutes)
  await app.register(receiptRoutes)
  await app.register(statsRoutes)
  await app.register(wellknownRoutes)

  app.get('/health', async () => ({ status: 'ok', version: '0.2.0' }))

  return app
}
