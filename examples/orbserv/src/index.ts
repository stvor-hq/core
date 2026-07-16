/**
 * Orbserv reference integration — the real thing a payment partner writes.
 *
 * The flow that makes a receipt mean something:
 *
 *   1. commit()  — freeze {to, amount, currency}, signed by the AGENT's key,
 *                  BEFORE any funds move.
 *   2. verify()  — Stvor checks the live payment against that commitment.
 *                  A swapped destination → DENY + a signed DENY receipt.
 *   3. send()    — execute on OrbWallet's own rails (only if ALLOW).
 *   4. settle()  — attach the txHash → settlement receipt.
 *   5. verifyReceipt() — offline, against the published keyset. No trust in
 *                  Stvor's server, only in the signature.
 *
 * Run:  bun run example:orbserv   (with the API running on :3000)
 */
import { Stvor, generateKeyPair, type Intent, type TrustReceipt, type KeyRegistry } from '@stvor/sdk'
import { OrbWallet } from './orbwallet.js'

const stvor = new Stvor({
  apiKey: process.env.STVOR_KEY ?? 'dev',
  baseUrl: process.env.STVOR_API ?? 'http://localhost:3000',
  onError: 'allow', // pilot default: a Stvor blip must not halt payments
})

const wallet = new OrbWallet('orb1agent001xyz')
const agentId = wallet.address

// The agent's own identity key. In production this is long-lived and held by
// the agent runtime; here we mint one per run for the demo.
let agentKey: Awaited<ReturnType<typeof generateKeyPair>>
let keyset: KeyRegistry

/** The integration surface: commit → verify → send → settle → verify offline. */
async function settle(payment: Intent, opts?: { swapTo?: string }): Promise<TrustReceipt | null> {
  // 1. Freeze the payment invariants, signed by the agent, before moving funds.
  const commitment = await stvor.commit(
    { to: payment.to, amount: payment.amount, currency: payment.currency },
    { agentId, agentPrivateJwk: agentKey.privateJwk, agentPubkey: agentKey.publicJwk }
  )

  // An attacker (or a bug) swaps the destination between intent and execution.
  const live: Intent = opts?.swapTo ? { ...payment, to: opts.swapTo } : payment

  // 2. Verify the live payment against the commitment.
  const decision = await stvor.verify(live, { commitmentId: commitment.commitmentId, agentId })
  console.log(`  verify()        → ${decision.decision} / ${decision.reason} [${decision.binding}]`)

  if (decision.decision !== 'ALLOW') {
    // Even a block is provable: a signed DENY receipt naming what was attempted.
    if (decision.receipt) {
      const ok = await stvor.verifyReceipt(decision.receipt, { keys: keyset })
      console.log(`  DENY receipt    → to=${decision.receipt.to} verified offline: ${ok ? '✅' : '❌'}`)
    }
    console.log('  ⛔ blocked — no funds moved\n')
    return null
  }

  // 3. Execute on OrbWallet's own rails.
  const txHash = await wallet.send(live)
  console.log(`  wallet.send()   → ${txHash.slice(0, 18)}…`)

  // 4. Attach the txHash → settlement receipt.
  const receipt = await stvor.settle(decision.id!, txHash)
  console.log(`  settle()        → ${receipt.receiptId}`)

  // 5. Verify offline against the published keyset — trust the math, not the API.
  const authentic = await stvor.verifyReceipt(receipt, { keys: keyset })
  console.log(`  verifyReceipt() → ${authentic ? 'AUTHENTIC ✅' : 'INVALID ❌'}\n`)
  return receipt
}

async function main() {
  console.log('\n═══ Orbserv × Stvor reference integration ═══\n')
  agentKey = await generateKeyPair()
  keyset = await stvor.keyset() // fetched once; every receipt below verifies offline against it

  console.log('▶ Case 1: legitimate payment (commit → verify → settle)')
  const receipt = await settle({ from: agentId, to: 'vendor_api_credits', amount: '5000.00', currency: 'USD' })

  console.log('▶ Case 2: destination-swap attack — committed to vendor, executed to attacker')
  await settle(
    { from: agentId, to: 'vendor_api_credits', amount: '5000.00', currency: 'USD' },
    { swapTo: '0xattacker_swapped_this' }
  )

  console.log('▶ Case 3: tamper defense — flip a field on a valid settlement receipt')
  if (receipt) {
    const forged = { ...receipt, to: '0xattacker' }
    const stillValid = await stvor.verifyReceipt(forged, { keys: keyset })
    console.log(`  verifyReceipt(forged) → ${stillValid ? 'AUTHENTIC ❌ (bad!)' : 'REJECTED ✅'}\n`)
  }

  console.log('Done. That was the full integration surface.\n')
}

main().catch((err) => {
  console.error('Integration failed:', err)
  process.exit(1)
})
