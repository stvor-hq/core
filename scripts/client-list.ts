/**
 * List issued API keys (metadata only — secrets are never stored).
 *   fly ssh console -C "bun run /app/scripts/client-list.ts"
 */
import { store } from '../stvor-api/src/store.js'

const clients = store.listClients()
if (clients.length === 0) {
  console.log('No client keys issued yet.')
} else {
  for (const c of clients) {
    const state = c.revokedAt ? `revoked ${c.revokedAt}` : 'active'
    console.log(`${c.keyId}  ${c.env.padEnd(4)}  ${state.padEnd(28)}  ${c.name}`)
  }
}
store.close()
