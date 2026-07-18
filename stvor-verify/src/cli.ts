#!/usr/bin/env node
/**
 * stvor-verify — offline Trust Receipt verifier.
 *
 *   stvor-verify <receipt.json> --jwk <issuer.jwk>
 *   stvor-verify <receipt.json> --keyset <stvor-keys.json>
 *   cat receipt.json | stvor-verify - --jwk issuer.jwk
 *
 * Prints "OK ..." and exits 0 on a valid receipt; "FAIL <reason>" and exits 1
 * otherwise. Makes ZERO network calls — it reads only the files you hand it, so
 * the guarantee holds even with no connectivity and no trust in Stvor's server.
 */
import { readFileSync } from 'node:fs'
import { verifyReceiptOffline, type EcJwk, type KeyRegistry } from '@stvor/core'

interface Args {
  receiptPath?: string
  jwkPath?: string
  keysetPath?: string
  json: boolean
}

function parseArgs(argv: string[]): Args {
  const args: Args = { json: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--jwk') args.jwkPath = argv[++i]
    else if (a === '--keyset' || a === '--keys') args.keysetPath = argv[++i]
    else if (a === '--json') args.json = true
    else if (a === '-h' || a === '--help') {
      usage()
      process.exit(0)
    } else if (!a.startsWith('-') || a === '-') args.receiptPath = a
  }
  return args
}

function usage() {
  process.stderr.write(
    'Usage: stvor-verify <receipt.json> (--jwk <issuer.jwk> | --keyset <stvor-keys.json>) [--json]\n' +
      '       cat receipt.json | stvor-verify - --jwk issuer.jwk\n' +
      'Offline verification only — no network calls.\n'
  )
}

function readStdin(): string {
  return readFileSync(0, 'utf8')
}

function fail(reason: string, detail?: string, json = false): never {
  if (json) process.stdout.write(JSON.stringify({ ok: false, reason, detail }) + '\n')
  else process.stdout.write(`FAIL ${reason}${detail ? ` (${detail})` : ''}\n`)
  process.exit(1)
}

async function main() {
  const args = parseArgs(process.argv.slice(2))

  if (!args.receiptPath) {
    usage()
    process.exit(2)
  }
  if (!args.jwkPath && !args.keysetPath) {
    usage()
    process.exit(2)
  }

  let receipt: unknown
  let keys: EcJwk | KeyRegistry
  try {
    const raw = args.receiptPath === '-' ? readStdin() : readFileSync(args.receiptPath, 'utf8')
    receipt = JSON.parse(raw)
  } catch (err) {
    fail('CANNOT_READ_RECEIPT', String(err), args.json)
  }
  try {
    keys = JSON.parse(readFileSync((args.jwkPath ?? args.keysetPath)!, 'utf8'))
  } catch (err) {
    fail('CANNOT_READ_KEYS', String(err), args.json)
  }

  const res = await verifyReceiptOffline(receipt, keys!)
  if (!res.ok) fail(res.reason ?? 'INVALID', res.detail ?? '', args.json)

  const r = res.receipt!
  if (args.json) {
    process.stdout.write(
      JSON.stringify({
        ok: true,
        binding: res.binding,
        issuerSignature: res.issuerSignature,
        agentSignature: res.agentSignature,
        receipt: r,
      }) + '\n'
    )
  } else {
    const amt = r.amount ? ` ${r.amount}${r.currency ? ' ' + r.currency : ''}` : ''
    const agent = res.agentSignature === 'not_applicable' ? '' : ` agentSig=${res.agentSignature}`
    process.stdout.write(
      `OK  binding=${r.binding} issuerSig=${res.issuerSignature}${agent}\n` +
        `    decision=${r.decision} to=${r.to}${amt} kid=${r.kid}\n`
    )
  }
  process.exit(0)
}

main().catch((err) => fail('INTERNAL', String(err)))
