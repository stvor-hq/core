# Stvor test vectors

Published so an integrator can prove their serializer and their verifier agree
with Stvor **before** the first live call — instead of guessing at a
canonicalization bug for a week.

Regenerate with `bun run vectors` (from the repo root).

| File | What it is |
|---|---|
| `canonical-vectors.json` | payment intent → RFC 8785 `canonical` string → `canonicalHex` (UTF-8 bytes) → `sha256`. **Key-independent.** Run your own canonicalizer over each `input`; every field must match. |
| `receipt-vectors.json` | signed Trust Receipts (valid + tampered) with an `expected` OK/FAIL and, for failures, the `reason`. Verify each offline against `keyset.json`. |
| `issuer.jwk` | public issuer key (JWK). |
| `keyset.json` | the append-only keyset, as served at `/.well-known/stvor-keys.json`. |
| `issuer.private.jwk` | **TEST-ONLY** private key used to sign the vectors. Not a production key — it exists solely so these vectors are reproducible. Never use it for anything real. |

Verify a vector from the CLI:

```
bun run --cwd stvor-verify start -- fixtures/<receipt>.json --jwk fixtures/issuer.jwk
```
