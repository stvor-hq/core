# Site & published-surface fixes (blocking before sending the contract)

Every technical reader who lands on the site hits one of these and silently
loses trust. The code is the source of truth; make the site match it. Reference:
[`CONTRACT.md`](CONTRACT.md).

| # | Where | Says (wrong) | Should say (matches code) |
|---|---|---|---|
| 1 | Install snippet | `npm install @stvor/web3` → **404, package does not exist** | The real published names: `@stvor/core` (offline verify), `@stvor/verify` (CLI), `@stvor/client` (payment client). **Never `@stvor/sdk`** — that's an unrelated older E2EE library. Use these everywhere. |
| 2 | Curl / API docs | `nous.stvor.xyz/api/v1/agents/register` | One base URL + **flat paths, no `/api/v1`**: `POST /commitments`, `POST /verify`, `POST /receipt`. There is no `/agents/register` endpoint. |
| 3 | Crypto description | ed25519 (in places) | **ES256 / P-256** (IEEE-P1363). The code has only ever been P-256. Remove every ed25519 mention. |
| 4 | Value prop | Counterparty **trust scoring** as a live feature | Not implemented — the engine is a stub. Remove the trust-scoring claim until it is real (see [CONTRACT.md §7](CONTRACT.md)). Lead instead with the cryptographic binding, which is real and demonstrable. |
| 5 | Flow diagram | `verify → receipt` (attest-only) | The binding flow: **`commit → verify → settle`**, with an offline-verifiable receipt for ALLOW *and* DENY. |

## What to lead with instead (all true, all demonstrable today)

- Pre-execution verification that **binds intent to execution** — a swapped
  destination is a signed `DENY`, not a silent pass.
- A **Trust Receipt anyone can verify offline** — CLI, browser page, or 20 lines
  of WebCrypto, using only the published key. Ship the browser verifier
  (`verifier/index.html`) as an interactive demo; it is the strongest proof you
  have.
- **Published test vectors** (`fixtures/`) so an integrator self-checks before
  writing a line against you.

## One base URL, decided

Pick a single origin (`api.stvor.xyz` recommended) and use it in the site, the
SDK default (`baseUrl`), and the contract. Today the SDK default is
`https://api.stvor.xyz`; align the marketing/docs origin to it or change both
together.
