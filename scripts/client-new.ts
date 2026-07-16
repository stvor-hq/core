/**
 * Issue an API key for a partner. Run where the DB lives (on the Fly machine:
 * `fly ssh console -C "bun run /app/scripts/client-new.ts --name orbserv --env test"`).
 *
 * Prints the secret to stdout ONCE. It is not recoverable — copy it now.
 */
import { newClientKey, type KeyEnv } from '../stvor-api/src/clientkeys.js'
import { store } from '../stvor-api/src/store.js'

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag)
  return i >= 0 ? process.argv[i + 1] : undefined
}

const name = arg('--name')
const env = (arg('--env') ?? 'test') as KeyEnv
if (!name) {
  console.error('Usage: client-new.ts --name <partner> [--env test|live]')
  process.exit(2)
}
if (env !== 'test' && env !== 'live') {
  console.error(`--env must be "test" or "live", got "${env}"`)
  process.exit(2)
}

const { fullKey, keyId, keyHash } = newClientKey(env)
store.createClient({ keyId, keyHash, name, env, createdAt: new Date().toISOString() })

console.error(`\nIssued key for "${name}" (${env})`)
console.error(`  keyId: ${keyId}   (public — shown in the dashboard)`)
console.error(`  secret (copy now, not stored, not recoverable):\n`)
console.log(fullKey)
store.close()
