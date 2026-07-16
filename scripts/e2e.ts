/**
 * External acceptance — run the OrbServ path against a PUBLIC deployment.
 *
 *   STVOR_API=https://api.stvor.xyz STVOR_KEY=stvor_test_... bun run scripts/e2e.ts
 *
 * Exits non-zero if any check fails, so it doubles as a post-deploy smoke test.
 */
import { Stvor, generateKeyPair, type Intent } from '../stvor-sdk/src/index.js'

const baseUrl = process.env.STVOR_API
const apiKey = process.env.STVOR_KEY
if (!baseUrl || !apiKey) {
  console.error('Set STVOR_API and STVOR_KEY.')
  process.exit(2)
}

let failures = 0
function check(name: string, ok: boolean, detail = '') {
  console.log(`  ${ok ? '✅' : '❌'} ${name}${detail ? ` — ${detail}` : ''}`)
  if (!ok) failures++
}

const stvor = new Stvor({ apiKey, baseUrl, onError: 'throw' })
const agentId = 'e2e_agent_001'

async function main() {
  console.log(`\n═══ Stvor external acceptance @ ${baseUrl} ═══\n`)

  // 0. Published keyset is reachable and non-empty.
  const keyset = await stvor.keyset()
  check('GET /.well-known/stvor-keys.json has keys', (keyset.keys?.length ?? 0) > 0)

  const agentKey = await generateKeyPair()
  const payment = { to: 'vendor_api_credits', amount: '5000.00', currency: 'USD' }

  // 1. Happy path: agent-committed → ALLOW → settle → offline verify.
  console.log('\n▶ legitimate payment')
  const c1 = await stvor.commit(payment, {
    agentId,
    agentPrivateJwk: agentKey.privateJwk,
    agentPubkey: agentKey.publicJwk,
  })
  const intent: Intent = { from: agentId, ...payment }
  const v1 = await stvor.verify(intent, { commitmentId: c1.commitmentId, agentId })
  check('verify → ALLOW', v1.decision === 'ALLOW', v1.reason)
  check('binding → agent-committed', v1.binding === 'agent-committed')
  const settled = await stvor.settle(v1.id!, '0xdeadbeef')
  check('settlement receipt verifies offline', await stvor.verifyReceipt(settled, { keys: keyset }))

  // 2. Destination-swap → DENY + signed DENY receipt verifiable offline.
  console.log('\n▶ destination-swap attack')
  const c2 = await stvor.commit(payment, {
    agentId,
    agentPrivateJwk: agentKey.privateJwk,
    agentPubkey: agentKey.publicJwk,
  })
  const swapped: Intent = { from: agentId, ...payment, to: '0xattacker_swapped_this' }
  const v2 = await stvor.verify(swapped, { commitmentId: c2.commitmentId, agentId })
  check('verify → DENY', v2.decision === 'DENY', v2.reason)
  check('reason → PAYLOAD_MISMATCH', v2.reason === 'PAYLOAD_MISMATCH')
  check('DENY receipt names the attempted destination', v2.receipt?.to === '0xattacker_swapped_this')
  check('DENY receipt verifies offline', !!v2.receipt && (await stvor.verifyReceipt(v2.receipt, { keys: keyset })))

  console.log('')
  if (failures === 0) console.log('ALL CHECKS PASSED ✅\n')
  else console.log(`${failures} CHECK(S) FAILED ❌\n`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('e2e crashed:', err)
  process.exit(1)
})
