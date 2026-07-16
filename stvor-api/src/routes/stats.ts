import type { FastifyInstance } from 'fastify'
import { store } from '../store.js'
import { requireRoot } from '../auth.js'
import { DASHBOARD_HTML } from './dashboard-html.js'

export async function statsRoutes(app: FastifyInstance) {
  // Cross-client counters — ROOT ONLY. A partner's own key must not be able to
  // read every client's traffic (reasons, per-client breakdown, last 20).
  app.get('/stats', { preHandler: requireRoot }, async () => store.stats())

  // The dashboard page is a data-free HTML shell — it must load without a
  // Bearer (the browser can't send one before you paste the key). The real
  // gate is /stats above: paste a non-root key and it returns 403.
  app.get('/dashboard', async (_req, reply) => {
    return reply.type('text/html; charset=utf-8').send(DASHBOARD_HTML)
  })
}
