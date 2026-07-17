# Orbserv × Stvor — reference integration

A runnable example of a payment runtime (OrbWallet) integrating Stvor. The
integration binds intent to execution: **commit** the payment before funds move,
**verify** the live payment against that commitment, and mint a signed Trust
Receipt anyone can check **offline** — for an ALLOW *and* for a DENY.

```
commit → verify → wallet.send → settle → verifyReceipt (offline)
```

## Run it (≈5 minutes)

From the repo root:

```bash
bun install

# terminal 1 — start the Stvor API
bun run --cwd stvor-api dev

# terminal 2 — run the integration
bun run example:orbserv
```

Expected output:

```
▶ Case 1: legitimate payment (commit → verify → settle)
  verify()        → ALLOW / PAYLOAD_MATCH [agent-committed]
  wallet.send()   → 0xcdc01939538f7ee8…
  settle()        → rec_h6TV4UFIMna9
  verifyReceipt() → AUTHENTIC ✅

▶ Case 2: destination-swap attack — committed to vendor, executed to attacker
  verify()        → DENY / PAYLOAD_MISMATCH [agent-committed]
  DENY receipt    → to=0xattacker_swapped_this verified offline: ✅
  ⛔ blocked — no funds moved

▶ Case 3: tamper defense — flip a field on a valid settlement receipt
  verifyReceipt(forged) → REJECTED ✅
```

## The whole integration

```ts
import { Stvor, generateKeyPair } from '@stvor/client'

const stvor = new Stvor({ apiKey: process.env.STVOR_KEY, onError: 'allow' })
const agentKey = await generateKeyPair() // the agent's own identity key

// 1. Commit the payment invariants BEFORE moving funds — signed by the agent.
const { commitmentId } = await stvor.commit(
  { to, amount: '5000.00', currency: 'USD' },
  { agentId, agentPrivateJwk: agentKey.privateJwk }
)

// 2. Verify the live payment against the commitment. A swapped `to` → DENY.
const decision = await stvor.verify({ from: agentId, to, amount: '5000.00', currency: 'USD' },
  { commitmentId, agentId })
if (decision.decision !== 'ALLOW') return // signed DENY receipt in decision.receipt

// 3. Pay on your own rails.
const txHash = await wallet.send(intent)

// 4. Attach the txHash → settlement receipt.
const receipt = await stvor.settle(decision.id, txHash)

// 5. Anyone verifies it offline against the published keyset — no call to Stvor.
await stvor.verifyReceipt(receipt, { keys: await stvor.keyset() }) // → true
```

`amount` is always a **decimal string** (`"5000.00"`), never a number. See
[`../../CONTRACT.md`](../../CONTRACT.md) for the full wire contract and
[`../../fixtures/`](../../fixtures/) for the published test vectors.

## Config

| Env | Default | Purpose |
|-----|---------|---------|
| `STVOR_API` | `http://localhost:3000` | API base URL |
| `STVOR_KEY` | `dev` | API key (required in production) |
