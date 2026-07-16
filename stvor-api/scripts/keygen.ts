import { generateKeyPairSync } from 'node:crypto'

// Generates a P-256 signing key for production. Store the PEM as a secret and
// expose it to the API as STVOR_SIGNING_KEY (raw PEM or base64-encoded PEM).
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string

console.log(pem.trim())
console.error('\n# Set as secret, e.g.:')
console.error('#   export STVOR_SIGNING_KEY="$(cat key.pem)"')
console.error('# or base64 for single-line env storage:')
console.error(`#   export STVOR_SIGNING_KEY="${Buffer.from(pem).toString('base64')}"`)
