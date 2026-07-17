# Stvor Wire Contract v0.2

**Status: frozen for the OrbServ pilot.** Changes after this point are additive
only (new optional fields, new endpoints) — never a rename, a removal, or a
change to what is signed. Build against this document; it is the source of truth
where it and any marketing page disagree.

What Stvor gives you is a **Trust Receipt**: an ES256-signed statement binding a
specific payment (`to`, `amount`, `currency`, …) to a decision (ALLOW/DENY),
verifiable by anyone, offline, with only the published key — long after the fact.

---

## 1. Transport

| | |
|---|---|
| Base URL | `https://api.stvor.xyz` (pilot: your deployment’s origin) |
| Path scheme | **flat, no version prefix** — `POST /verify`, not `/api/v1/verify` |
| Auth | `Authorization: Bearer <STVOR_KEY>`. Required in production (the server refuses to boot without it). |
| Content type | `application/json` |
| Body limit | 64 KB |
| Rate limit | 120 req/min per client (default; configurable) |

## 2. Canonicalization & formats — read this first

Everything Stvor hashes or signs is serialized with **RFC 8785 (JSON
Canonicalization Scheme)**. Your serializer must produce byte-identical output.
Do not hand-roll it — use a JCS library and check it against
[`fixtures/canonical-vectors.json`](fixtures/) before your first live call.

- **`amount` is a decimal string** — `"50.00"`, never the JSON number `50` or
  `50.0`. The API rejects a numeric `amount` with `400`. Floats do not survive
  canonicalization across languages; strings do.
- **Absent optional fields are omitted**, never sent as `null`. `null` changes
  the canonical bytes and breaks the signature.
- The **payment payload** — the exact set of fields a commitment freezes and a
  receipt binds — is:

  ```json
  { "to": "...", "amount": "50.00", "currency": "USD", "chain": "...", "asset": "..." }
  ```

  Only `to` is required. Nothing that legally changes between intent and
  execution (gas, timestamps, slippage, rail nonces) is in here — committing
  such a field would produce false DENYs on honest payments.

  `payloadHash = SHA-256( JCS(payment payload) )`, lowercase hex.

## 3. What a receipt proves — the `binding` field

`binding` is inside the signature. It is the honest scope of the proof:

- **`attested`** — Stvor signed these parameters as seen at verify time. Says
  nothing about any prior intent. Does **not** catch a swap.
- **`committed`** — the live payload matched a commitment Stvor received
  earlier. **Catches destination swap.** Still requires trusting that the
  committer (the integrator) posted a genuine commitment.
- **`agent-committed`** — the commitment carried a signature from the agent’s
  own key, verified by Stvor. Proves the executed payment matched what *the
  agent itself* committed to, verifiable by a third party **without trusting the
  integrator or Stvor**.

## 4. Endpoints

### `POST /commitments`

Freeze a payment before execution. Optionally sign it with the agent’s key to
get `agent-committed`.

```jsonc
// request
{
  "agentId": "orb1agent001xyz",
  "payloadHash": "<64 hex chars>",       // SHA-256 of JCS(payment payload)
  "alg": "sha256",
  "nonce": "unique-per-agent",
  "expiresAt": "2026-07-16T12:00:00.000Z",
  "agentSignature": "<base64url r‖s>",   // optional
  "agentPubkey": { "kty":"EC","crv":"P-256","x":"…","y":"…" } // required iff agentSignature present
}
// 201
{ "commitmentId": "cmt_…", "expiresAt": "2026-07-16T12:00:00.000Z" }
```

- `agentSignature`, when present, is ES256 over `JCS({agentId, alg, expiresAt, nonce, payloadHash})`.
  An **invalid** signature is rejected with `400 INVALID_AGENT_SIGNATURE` — never
  silently downgraded to a weaker binding.
- `(agentId, nonce)` is unique. A duplicate returns `409`.

### `POST /verify`

The decision. Returns a signed receipt inline for **both** ALLOW and DENY.

```jsonc
// request
{
  "intent": { "from":"orb1agent001xyz", "to":"vendor", "amount":"5000.00", "currency":"USD" },
  "agentId": "orb1agent001xyz",   // optional; defaults to intent.from
  "commitmentId": "cmt_…",        // optional; omit for an attested decision
  "nonce": "…",                   // optional (attested path)
  "policy": { "minTrustScore": 0 } // optional; see §7
}
// 200
{
  "id": "ver_…",
  "decision": "ALLOW",            // or "DENY"
  "reason": "PAYLOAD_MATCH",
  "binding": "agent-committed",
  "receipt": { …, "signature": "…" },
  "expiresAt": "2026-07-16T12:05:00.000Z"
}
```

With a `commitmentId`, Stvor recomputes `SHA-256(JCS(live payment payload))` and
compares it (constant-time) to the stored `payloadHash`:

| Situation | `decision` | `reason` |
|---|---|---|
| payload matches, commitment fresh & unused | `ALLOW` | `PAYLOAD_MATCH` |
| live payload differs from commitment | `DENY` | `PAYLOAD_MISMATCH` |
| commitment already used | `DENY` | `COMMITMENT_CONSUMED` |
| commitment past `expiresAt` | `DENY` | `COMMITMENT_EXPIRED` |
| `commitmentId` unknown | `DENY` | `COMMITMENT_NOT_FOUND` |
| `agentId` ≠ commitment’s agent | `DENY` | `AGENT_MISMATCH` |

A matching commitment is **consumed atomically** (single use) — a replay of the
same commitment DENYs with `COMMITMENT_CONSUMED`. Without a `commitmentId` the
decision is `attested` (`ALLOW` → `ATTESTED_OK`, subject to structural guards).

Every path — including every DENY — returns a signed receipt naming the payment
that was attempted. A block is as provable as an approval.

### `GET /verify/:id`

Re-read a decision (bound fields + the stored receipt). `404` if unknown.

### `POST /receipt` — optional settlement step

Attach an on-chain `txHash` after settling an **ALLOW**. Returns a *settlement
receipt* that references the verification receipt (`verificationReceiptId`) and
adds `txHash`.

```jsonc
{ "verificationId": "ver_…", "txHash": "0x…" }
```

| Response | Meaning |
|---|---|
| `201` | issued |
| `200` | idempotent replay (same `verificationId` + same `txHash`) → same receipt |
| `409` | already settled with a **different** `txHash` |
| `422` | verification was a DENY (cannot settle) |
| `410` | verification window expired |
| `404` | unknown verification |

### `GET /.well-known/public-key`

Current signing key as a JWK (`kty:EC, crv:P-256, kid, use:sig, alg:ES256`).

### `GET /.well-known/stvor-keys.json`

The **append-only keyset** — every key Stvor has ever signed with, with validity
windows. Resolve a receipt by its `kid`. This is what lets a receipt verify a
year later, after the signing key has rotated.

```jsonc
{ "keys": [ { "kid":"key_…", "jwk": {…}, "notBefore":"…", "notAfter":"…"? } ] }
```

## 5. Receipt format & offline verification

A receipt is the signed payload plus a `signature`. **Everything in the receipt
is signed** — there is no partially-covered field.

```jsonc
{
  "receiptId": "rec_…",
  "verificationId": "ver_…",
  "binding": "agent-committed",
  "agentId": "orb1agent001xyz",
  "to": "vendor", "amount": "5000.00", "currency": "USD",
  "chain": "…?", "asset": "…?",
  "nonce": "…",
  "decision": "ALLOW", "reason": "PAYLOAD_MATCH",
  "issuedAt": "…", "expiresAt": "…",
  "kid": "key_…",
  "commitmentId": "cmt_…?",
  "agentKeyThumbprint": "…?",   // RFC 7638, when agent-committed
  "agentSignature": "…?",       // the agent's own signature, carried through
  "txHash": "0x…?",             // settlement receipt only
  "verificationReceiptId": "rec_…?", // settlement receipt only
  "signature": "<base64url r‖s, 64 bytes>"
}
```

**Verification procedure (offline, zero network):**

1. Take the receipt, remove `signature`.
2. Resolve the key for `receipt.kid` from the keyset. Unknown kid → **FAIL
   (`UNKNOWN_KEY`)** — never fall back to another key.
3. Check the ES256 signature over `JCS(payload)` (P-256 / SHA-256 / raw
   IEEE-P1363 r‖s). Mismatch → **FAIL (`BAD_SIGNATURE`)**.

Signature scheme is **ES256 / P-256 / IEEE-P1363**, frozen. Any standard JOSE /
WebCrypto verifier accepts it from the published JWK.

Reference tooling (all run the same `@stvor/core` code):

- **Library:** `npm install @stvor/core` → `verifyReceiptOffline(receipt, jwkOrKeyset)`
- **CLI:** `npm i -g @stvor/verify` → `stvor-verify receipt.json --keyset stvor-keys.json` → `OK` / `FAIL <reason>`, exit `0`/`1`
- **Browser:** `verifier/index.html` in this repo — one self-contained file; paste receipt + key, verdict client-side, works offline from disk
- The payment client (`commit` / `verify` / `settle`) is in `stvor-sdk/`. Do **not** `npm install @stvor/sdk` — that name is an unrelated older library; use the REST endpoints above or vendor `stvor-sdk/` until it publishes under its final name.

## 6. Fail mode

`verify()` in the SDK takes `onError: "allow" | "deny" | "throw"` and
`timeoutMs`. **Pilot default: `timeoutMs: 500`, `onError: "allow"`.** On a Stvor
**transport failure** (timeout / network / exhausted 5xx) the SDK returns a
degraded decision:

```jsonc
{ "id": null, "decision": "ALLOW", "reason": "STVOR_UNREACHABLE",
  "binding": "attested", "receipt": null, "degraded": true }
```

`degraded: true` and `receipt: null` mean “Stvor did not decide this” — log and
count it; never treat it as a real ALLOW. A **DENY or a 4xx is not a transport
failure** and always passes through unchanged. This is decided here, in writing,
before the first outage — fail-closed-by-accident is how a partner removes you in
a week.

## 7. Trust scoring — not a gating check (yet)

Counterparty trust scoring is **not implemented** and is **not** part of this
contract. The engine is a stub; there is no reliable `trustScore` on the wire and
you must not build gating on one. `policy.minTrustScore` exists but defaults to
non-gating. When real trust scoring ships, it will be added additively and
documented here. Until then, Stvor’s guarantee is exactly the cryptographic
binding above — nothing is claimed that the code does not do.

## 8. Test vectors

[`fixtures/`](fixtures/) is published so you can self-check **before** going
live: `canonical-vectors.json` (your serializer must match byte-for-byte) and
`receipt-vectors.json` (valid + tampered, verify offline against `keyset.json`).
Regenerate with `bun run vectors`.
