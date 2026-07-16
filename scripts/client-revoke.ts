/**
 * Revoke an API key by its public keyId. Subsequent calls with it get 401.
 *   fly ssh console -C "bun run /app/scripts/client-revoke.ts --keyId ck_..."
 */
import { store } from '../stvor-api/src/store.js'

const i = process.argv.indexOf('--keyId')
const keyId = i >= 0 ? process.argv[i + 1] : undefined
if (!keyId) {
  console.error('Usage: client-revoke.ts --keyId <ck_...>')
  process.exit(2)
}

const ok = store.revokeClient(keyId)
console.log(ok ? `Revoked ${keyId}` : `No active key ${keyId} (already revoked or unknown)`)
store.close()
process.exit(ok ? 0 : 1)
