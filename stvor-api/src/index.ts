import { buildApp } from './app.js'
import { store } from './store.js'

const app = await buildApp()

// TTL sweep: drop expired, unused verifications and commitments every 60s.
const cleanup = setInterval(() => {
  try {
    const removed = store.cleanupExpired()
    if (removed > 0) app.log.info({ removed }, 'cleaned expired records')
  } catch (err) {
    app.log.error(err, 'cleanup failed')
  }
}, 60_000)
cleanup.unref()

async function shutdown(signal: string) {
  app.log.info({ signal }, 'shutting down')
  clearInterval(cleanup)
  await app.close()
  store.close()
  process.exit(0)
}
process.on('SIGINT', () => void shutdown('SIGINT'))
process.on('SIGTERM', () => void shutdown('SIGTERM'))

const port = Number(process.env.PORT ?? 3000)
const host = process.env.HOST ?? '0.0.0.0'

try {
  await app.listen({ port, host })
  console.log(`Stvor API running on http://${host}:${port}`)
} catch (err) {
  app.log.error(err)
  process.exit(1)
}
