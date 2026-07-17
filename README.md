# Stvor

Pre-execution verification for agent payments. Bind a payment's intent to its
execution, and mint a **Trust Receipt** anyone can verify **offline** — for an
ALLOW *and* for a DENY.

Swap the destination between intent and execution and you get a **signed DENY**,
not a silent pass. Verify any receipt with only the published key — no call to
Stvor, no trust in its server, just the math.

## Packages

| Package | What it is |
|---|---|
| `stvor-core` | RFC 8785 canonicalization, ES256 / P-256 signing, offline receipt verification. Zero network. |
| `stvor-api` | The verification service (Fastify + SQLite). `commit → verify → settle`. |
| `stvor-sdk` | `@stvor/client` — TypeScript client (commit/verify/settle + fail mode). |
| `stvor-verify` | `stvor-verify` CLI — offline receipt checker. |
| `verifier/` | Single-page browser verifier (paste receipt + key → verdict, fully client-side). |
| `examples/orbserv` | Reference partner integration (~20 lines). |

## Quickstart

```bash
bun install
bun run --cwd stvor-api dev     # local dev (STVOR_DEV=1 open mode)
bun run example:orbserv         # in another terminal, with the API running
bun test
```

## The flow

```
commit(payment, agentKey)      # freeze intent, signed by the agent, before funds move
  → verify(intent, commitmentId)   # a swapped destination → DENY + signed DENY receipt
    → wallet.send()                # execute on your own rails (only on ALLOW)
      → settle(id, txHash)         # attach the on-chain tx → settlement receipt
        → verifyReceipt(r, { keys })   # anyone verifies offline
```

## Docs

- **[CONTRACT.md](CONTRACT.md)** — the frozen wire contract. Build against this.
- **[DEPLOY.md](DEPLOY.md)** — Fly.io deployment, top to bottom.
- **[fixtures/](fixtures/)** — published test vectors (self-check your serializer before going live).

## Signing

ES256 / P-256 / IEEE-P1363, frozen. Any standard JOSE / WebCrypto verifier
accepts a Trust Receipt from the published JWK. Keys rotate via an append-only
keyset (`/.well-known/stvor-keys.json`), so old receipts keep verifying.
