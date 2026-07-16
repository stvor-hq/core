# Deploying Stvor (Fly.io)

One machine, one volume, one signing key. Copy-paste top to bottom.

> Why Fly: the API is SQLite + a persistent volume, so serverless (Vercel /
> Lambda / Workers) is out — you need a machine with a disk. Fly gives you a
> first-class volume for ~$5/mo.

## 0. Prerequisites

```bash
brew install flyctl        # or: curl -L https://fly.io/install.sh | sh
fly auth login
```

## 1. Create the app (no deploy yet)

Edit `fly.toml` → set `app` (globally unique) and `primary_region`. Then:

```bash
fly apps create stvor-api        # match the name in fly.toml
```

## 2. Create the volume — state lives here, not in the image

```bash
fly volumes create stvor_data --region iad --size 1
```

If the DB stayed in the container, every deploy would wipe the keyset and every
open commitment.

## 3. Signing key — generate ONCE, store as a secret, BACK IT UP

The prod container refuses to autogenerate (autogen requires `STVOR_DEV=1`, which
must never be set here). A new key on each deploy would mean a new `kid`, a
bloating keyset, and receipts referencing keys that no longer exist.

> **This is the one irreversible mistake in the whole system.** Everything else
> — the DB, commitments, client keys — is recreatable. Lose the signing key and
> every receipt you have ever issued stops verifying: the product's entire
> premise evaporates. Back it up before you do anything else.

```bash
# generate a P-256 signing key (PEM prints to stdout)
bun run --cwd stvor-api keygen > stvor-signing-key.pem

# store it as a secret
fly secrets set STVOR_SIGNING_KEY="$(cat stvor-signing-key.pem)"
```

**Back `stvor-signing-key.pem` up somewhere off Fly (password manager / KMS).**
Lose it and you lose the ability to verify every receipt you ever issued. Then
delete the local copy. Also snapshot the volume periodically — the keyset lives
there too:

```bash
fly volumes snapshots list stvor_data
```

## 4. Admin (root) key — required to boot, and the only key that reads /stats

```bash
fly secrets set STVOR_KEY="stvor_live_$(openssl rand -hex 24)"
```

Two things this does:

1. **Lets the server boot.** It fails closed without a `STVOR_KEY` (or a client
   key) — regardless of `NODE_ENV`. There is no accidental open mode; open
   requires an explicit `STVOR_DEV=1` you will never set in prod.
2. **Authenticates as `root`.** `/stats` and `/dashboard` are **root-only** — a
   partner's `stvor_test_`/`stvor_live_` key gets `403` there, so no client can
   read another client's traffic. Keep this key private; it is yours alone.

## 5. Deploy

```bash
fly deploy
```

## 6. Domain + TLS

```bash
fly certs add api.stvor.xyz
# add the DNS records fly prints (A/AAAA or CNAME) at your DNS host, then:
fly certs check api.stvor.xyz
```

## 7. Issue OrbServ a test key (per-client, attributed from day one)

```bash
fly ssh console -C "bun run /app/scripts/client-new.ts --name orbserv --env test"
```

It prints `stvor_test_...` **once** — copy it, it is not recoverable. Send that
to OrbServ with `CONTRACT.md`. (A `stvor_live_...` key later, same command with
`--env live`, when they go to production.)

> Shortcut if you just want a single shared key today: skip this and hand out
> the `STVOR_KEY` value from step 4. You lose per-partner attribution in
> `/stats`; the contract is identical either way (`Authorization: Bearer …`).

## 8. External acceptance — from outside, the way OrbServ will hit it

```bash
curl https://api.stvor.xyz/.well-known/stvor-keys.json

STVOR_API=https://api.stvor.xyz STVOR_KEY=stvor_test_... bun run scripts/e2e.ts
```

`e2e.ts` runs the real path — commit → verify → settle → offline-verify, plus a
destination-swap that must come back `DENY / PAYLOAD_MISMATCH` with a signed DENY
receipt that verifies offline. All checks must pass before you send the contract.

Spot-check a receipt with the standalone verifier too:

```bash
# save any receipt to r.json, then:
curl -s https://api.stvor.xyz/.well-known/stvor-keys.json > keyset.json
bun run --cwd stvor-verify start -- r.json --keyset keyset.json
```

## 9. Dashboard

`https://api.stvor.xyz/dashboard` → paste the **admin (root) `STVOR_KEY`**
(stored in your browser's localStorage) → live counts, polled every 5s. A
partner key gets `403` here by design. `PAYLOAD_MISMATCH` is the number to
watch: caught attacks.

---

## Operating rules

- **Never `fly scale count 2`.** SQLite is single-writer on one volume; a second
  machine gets a second empty volume and starts DENYing honest payments it has no
  commitment for. Scale vertically (`fly scale vm`) if you need more.
- **Keep `auto_stop_machines = false`.** A cold start blows the SDK's 500ms
  budget → partners fail-open → Stvor silently not verifying.
- **Migrations:** the schema is created on boot (`CREATE TABLE IF NOT EXISTS` +
  additive `ALTER`). Deploys are safe; the volume persists.
- **Rotating the signing key:** set a new `STVOR_SIGNING_KEY` and redeploy. The
  keyset endpoint keeps serving the old key (append-only), so old receipts keep
  verifying. Never delete a key from `/data/keys.json`.
