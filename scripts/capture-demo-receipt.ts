/**
 * Capture a production DENY receipt for the marketing demo fixture.
 *
 *   STVOR_API=https://api.stvor.xyz STVOR_KEY=stvor_test_... bun run scripts/capture-demo-receipt.ts
 */
import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Stvor, generateKeyPair } from '../stvor-sdk/src/index.js'

const baseUrl = process.env.STVOR_API ?? 'https://api.stvor.xyz'
const apiKey = process.env.STVOR_KEY
if (!apiKey) {
  console.error('Set STVOR_KEY.')
  process.exit(2)
}

const COMMITTED_TO = '0x4c1b82f71a9e3d0c8b5e6f2a1d4c7b9e0f3a8c1d'
const SWAPPED_TO = '0x8f3a2c91d4e7b0a6c5d8f1e2a4b7c9d0e3f6a8c1d'
const payment = { to: COMMITTED_TO, amount: '50000.00', currency: 'USDC' }

const stvor = new Stvor({ apiKey, baseUrl, onError: 'throw' })
const agentId = 'agent_demo_blocked'
// Ed25519 — matches what a real Solana agent (e.g. OrbServ) holds, so the demo
// fixture never diverges in key type from the live agent-committed flow.
const agentKey = await generateKeyPair('EdDSA')

const commitment = await stvor.commit(payment, {
  agentId,
  agentPrivateJwk: agentKey.privateJwk,
  agentPubkey: agentKey.publicJwk,
})

const verify = await stvor.verify(
  { from: agentId, ...payment, to: SWAPPED_TO },
  { commitmentId: commitment.commitmentId, agentId },
)

if (verify.decision !== 'DENY' || verify.reason !== 'PAYLOAD_MISMATCH') {
  console.error('Expected DENY / PAYLOAD_MISMATCH, got', verify)
  process.exit(1)
}

const keyset = await stvor.keyset()
const offline = verify.receipt ? await stvor.verifyReceipt(verify.receipt, { keys: keyset }) : false
if (!offline) {
  console.error('Receipt failed offline verification')
  process.exit(1)
}

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(HERE, '..', 'fixtures')
mkdirSync(FIXTURES, { recursive: true })

const demo = {
  name: 'demo-deny-blocked-attack',
  description:
    'Agent committed USDC 50000.00 to vendor 0x4c1b82f7…; execution attempted swapped destination. DENY + offline-verifiable receipt.',
  committed: payment,
  attempted: { ...payment, to: SWAPPED_TO },
  receipt: verify.receipt,
  binding: verify.binding,
  keyset,
  expected: 'OK',
}

writeFileSync(join(FIXTURES, 'demo-deny-receipt.json'), JSON.stringify(demo, null, 2) + '\n')
console.log('Wrote fixtures/demo-deny-receipt.json')
console.log('  kid:', verify.receipt?.kid)
console.log('  binding:', verify.binding)
console.log('  to (attempted):', verify.receipt?.to)
