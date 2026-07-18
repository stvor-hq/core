import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import type { TrustReceipt, AgentJwk } from '@stvor/core'
import type { Verification, Commitment, Settlement, Decision, Binding, Client } from './types.js'

const DB_PATH = process.env.STVOR_DB ?? '.stvor/stvor.db'
mkdirSync(dirname(DB_PATH), { recursive: true })

const db = new Database(DB_PATH)
db.exec('PRAGMA journal_mode = WAL')
db.exec('PRAGMA foreign_keys = ON')

db.exec(`
  CREATE TABLE IF NOT EXISTS verifications (
    id            TEXT PRIMARY KEY,
    decision      TEXT NOT NULL,
    reason        TEXT NOT NULL,
    binding       TEXT NOT NULL,
    client_id     TEXT NOT NULL DEFAULT 'root',
    agent_id      TEXT NOT NULL,
    to_addr       TEXT NOT NULL,
    amount        TEXT,
    currency      TEXT,
    chain         TEXT,
    asset         TEXT,
    nonce         TEXT NOT NULL,
    commitment_id TEXT,
    receipt       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    settled       INTEGER NOT NULL DEFAULT 0
  );
`)
db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    key_id     TEXT PRIMARY KEY,
    key_hash   TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    env        TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
  );
`)
// Additive migration for DBs created before client attribution existed.
try {
  db.exec("ALTER TABLE verifications ADD COLUMN client_id TEXT NOT NULL DEFAULT 'root'")
} catch {
  // column already exists — fine
}
db.exec(`
  CREATE TABLE IF NOT EXISTS commitments (
    commitment_id        TEXT PRIMARY KEY,
    agent_id             TEXT NOT NULL,
    payload_hash         TEXT NOT NULL,
    alg                  TEXT NOT NULL,
    nonce                TEXT NOT NULL,
    agent_signature      TEXT,
    agent_pubkey         TEXT,
    agent_key_thumbprint TEXT,
    created_at           TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    consumed             INTEGER NOT NULL DEFAULT 0,
    UNIQUE(agent_id, nonce)
  );
`)
db.exec(`
  CREATE TABLE IF NOT EXISTS settlements (
    verification_id TEXT PRIMARY KEY,
    tx_hash         TEXT NOT NULL,
    receipt         TEXT NOT NULL,
    issued_at       TEXT NOT NULL
  );
`)
// Durable, append-only decision log — the audit record, decoupled from the
// verifications working set. Counts only: decision/reason/binding/client, and
// deliberately NO to/amount/currency (retention-clean by construction). This is
// what /stats reads, so a caught swap at 3am is still counted next morning even
// though its short-lived verification row has been swept.
db.exec(`
  CREATE TABLE IF NOT EXISTS verification_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    decision   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    binding    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`)
db.exec('CREATE INDEX IF NOT EXISTS idx_ver_expires ON verifications(expires_at);')
db.exec('CREATE INDEX IF NOT EXISTS idx_cmt_expires ON commitments(expires_at);')
db.exec('CREATE INDEX IF NOT EXISTS idx_events_id ON verification_events(id DESC);')

interface VerificationRow {
  id: string
  decision: string
  reason: string
  binding: string
  client_id: string
  agent_id: string
  to_addr: string
  amount: string | null
  currency: string | null
  chain: string | null
  asset: string | null
  nonce: string
  commitment_id: string | null
  receipt: string
  created_at: string
  expires_at: string
  settled: number
}
interface CommitmentRow {
  commitment_id: string
  agent_id: string
  payload_hash: string
  alg: string
  nonce: string
  agent_signature: string | null
  agent_pubkey: string | null
  agent_key_thumbprint: string | null
  created_at: string
  expires_at: string
  consumed: number
}
interface SettlementRow {
  verification_id: string
  tx_hash: string
  receipt: string
  issued_at: string
}

const insertVerification = db.prepare(
  `INSERT INTO verifications
     (id, decision, reason, binding, client_id, agent_id, to_addr, amount, currency, chain, asset, nonce, commitment_id, receipt, created_at, expires_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
)
const selectVerification = db.query<VerificationRow>('SELECT * FROM verifications WHERE id = ?')
const markSettled = db.prepare('UPDATE verifications SET settled = 1 WHERE id = ?')

const insertCommitment = db.prepare(
  `INSERT INTO commitments
     (commitment_id, agent_id, payload_hash, alg, nonce, agent_signature, agent_pubkey, agent_key_thumbprint, created_at, expires_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
)
const selectCommitment = db.query<CommitmentRow>('SELECT * FROM commitments WHERE commitment_id = ?')
/** Atomic single-use consume: flips 0→1 only if currently 0. changes===1 means we won the race. */
const consumeCommitment = db.prepare('UPDATE commitments SET consumed = 1 WHERE commitment_id = ? AND consumed = 0')

const insertSettlement = db.prepare(
  `INSERT INTO settlements (verification_id, tx_hash, receipt, issued_at) VALUES (?, ?, ?, ?)`
)
const selectSettlement = db.query<SettlementRow>('SELECT * FROM settlements WHERE verification_id = ?')

// The verifications table is a working set, not the audit record (that's
// verification_events, durable). So we can prune BOTH sides now:
//   - unsettled + past its settlement window  → can never be settled, drop it
//   - settled + older than the retention grace → receipt is in `settlements`
//     and with the caller; the row is only kept briefly for GET /verify/:id
const SETTLED_RETENTION_MS = 24 * 60 * 60 * 1000 // 24h grace for re-reads
const deleteExpiredVerifications = db.prepare(
  'DELETE FROM verifications WHERE (settled = 0 AND expires_at < ?) OR (settled = 1 AND created_at < ?)'
)
// Once a commitment is past its freshness window it can never verify (expired),
// so it is safe to drop whether or not it was consumed.
const deleteExpiredCommitments = db.prepare('DELETE FROM commitments WHERE expires_at < ?')

interface ClientRow {
  key_id: string
  key_hash: string
  name: string
  env: string
  created_at: string
  revoked_at: string | null
}
const insertClient = db.prepare(
  'INSERT INTO clients (key_id, key_hash, name, env, created_at) VALUES (?, ?, ?, ?, ?)'
)
const selectClientByHash = db.query<ClientRow>('SELECT * FROM clients WHERE key_hash = ?')
const selectClients = db.query<ClientRow>('SELECT * FROM clients ORDER BY created_at DESC')
const countClients = db.query<{ n: number }>('SELECT COUNT(*) AS n FROM clients WHERE revoked_at IS NULL')
const revokeClientStmt = db.prepare('UPDATE clients SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL')

function rowToClient(r: ClientRow): Client {
  return {
    keyId: r.key_id,
    keyHash: r.key_hash,
    name: r.name,
    env: r.env as 'test' | 'live',
    createdAt: r.created_at,
    revokedAt: r.revoked_at ?? undefined,
  }
}

// Aggregates read the DURABLE event log, not the ephemeral verifications table.
interface CountRow {
  k: string
  n: number
}
const insertEvent = db.prepare(
  'INSERT INTO verification_events (decision, reason, binding, client_id, created_at) VALUES (?, ?, ?, ?, ?)'
)
// Env bucket for durable stats: root → production; dev → sandbox; client keys use clients.env.
const EVENT_ENV_CASE = `CASE
  WHEN e.client_id = 'root' THEN 'live'
  WHEN e.client_id = 'dev' THEN 'test'
  ELSE COALESCE(c.env, 'live')
END`

interface StatsSlice {
  total: number
  allow: number
  deny: number
  byReason: { key: string; count: number }[]
  byBinding: { key: string; count: number }[]
  byClient: { key: string; count: number }[]
  recent: {
    decision: string
    reason: string
    binding: string
    clientId: string
    createdAt: string
  }[]
}

function statsForEnv(env: 'live' | 'test'): StatsSlice {
  const toMap = (rows: CountRow[]) => rows.map((r) => ({ key: r.k, count: r.n }))
  const countTotalEnv = db.query<{ n: number }>(
    `SELECT COUNT(*) AS n FROM verification_events e
     LEFT JOIN clients c ON e.client_id = c.key_id
     WHERE (${EVENT_ENV_CASE}) = ?`
  )
  const countByDecisionEnv = db.query<CountRow>(
    `SELECT e.decision AS k, COUNT(*) AS n FROM verification_events e
     LEFT JOIN clients c ON e.client_id = c.key_id
     WHERE (${EVENT_ENV_CASE}) = ?
     GROUP BY e.decision`
  )
  const countByReasonEnv = db.query<CountRow>(
    `SELECT e.reason AS k, COUNT(*) AS n FROM verification_events e
     LEFT JOIN clients c ON e.client_id = c.key_id
     WHERE (${EVENT_ENV_CASE}) = ?
     GROUP BY e.reason ORDER BY n DESC`
  )
  const countByBindingEnv = db.query<CountRow>(
    `SELECT e.binding AS k, COUNT(*) AS n FROM verification_events e
     LEFT JOIN clients c ON e.client_id = c.key_id
     WHERE (${EVENT_ENV_CASE}) = ?
     GROUP BY e.binding`
  )
  const countByClientEnv = db.query<CountRow>(
    `SELECT e.client_id AS k, COUNT(*) AS n FROM verification_events e
     LEFT JOIN clients c ON e.client_id = c.key_id
     WHERE (${EVENT_ENV_CASE}) = ?
     GROUP BY e.client_id ORDER BY n DESC`
  )
  const selectRecentEnv = db.query<{
    decision: string; reason: string; binding: string; client_id: string; created_at: string
  }>(
    `SELECT e.decision, e.reason, e.binding, e.client_id, e.created_at
     FROM verification_events e
     LEFT JOIN clients c ON e.client_id = c.key_id
     WHERE (${EVENT_ENV_CASE}) = ?
     ORDER BY e.id DESC LIMIT 20`
  )

  const decisions = Object.fromEntries(countByDecisionEnv.all(env).map((r) => [r.k, r.n]))
  return {
    total: countTotalEnv.get(env)?.n ?? 0,
    allow: decisions.ALLOW ?? 0,
    deny: decisions.DENY ?? 0,
    byReason: toMap(countByReasonEnv.all(env)),
    byBinding: toMap(countByBindingEnv.all(env)),
    byClient: toMap(countByClientEnv.all(env)),
    recent: selectRecentEnv.all(env).map((r) => ({
      decision: r.decision,
      reason: r.reason,
      binding: r.binding,
      clientId: r.client_id,
      createdAt: r.created_at,
    })),
  }
}

function rowToVerification(r: VerificationRow): Verification {
  return {
    id: r.id,
    decision: r.decision as Decision,
    reason: r.reason,
    binding: r.binding as Binding,
    clientId: r.client_id,
    agentId: r.agent_id,
    to: r.to_addr,
    amount: r.amount ?? undefined,
    currency: r.currency ?? undefined,
    chain: r.chain ?? undefined,
    asset: r.asset ?? undefined,
    nonce: r.nonce,
    commitmentId: r.commitment_id ?? undefined,
    receipt: JSON.parse(r.receipt) as TrustReceipt,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    settled: r.settled === 1,
  }
}
function rowToCommitment(r: CommitmentRow): Commitment {
  return {
    commitmentId: r.commitment_id,
    agentId: r.agent_id,
    payloadHash: r.payload_hash,
    alg: r.alg as 'sha256',
    nonce: r.nonce,
    agentSignature: r.agent_signature ?? undefined,
    agentPubkey: r.agent_pubkey ? (JSON.parse(r.agent_pubkey) as AgentJwk) : undefined,
    agentKeyThumbprint: r.agent_key_thumbprint ?? undefined,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    consumed: r.consumed === 1,
  }
}
function rowToSettlement(r: SettlementRow): Settlement {
  return {
    verificationId: r.verification_id,
    txHash: r.tx_hash,
    receipt: JSON.parse(r.receipt) as TrustReceipt,
    issuedAt: r.issued_at,
  }
}

export type IssueSettlementResult =
  | { status: 'issued'; settlement: Settlement }
  | { status: 'duplicate'; settlement: Settlement }
  | { status: 'conflict'; existing: Settlement }

export const store = {
  saveVerification(v: Verification) {
    insertVerification.run(
      v.id,
      v.decision,
      v.reason,
      v.binding,
      v.clientId,
      v.agentId,
      v.to,
      v.amount ?? null,
      v.currency ?? null,
      v.chain ?? null,
      v.asset ?? null,
      v.nonce,
      v.commitmentId ?? null,
      JSON.stringify(v.receipt),
      v.createdAt,
      v.expiresAt
    )
  },

  getVerification(id: string): Verification | null {
    const row = selectVerification.get(id)
    return row ? rowToVerification(row) : null
  },

  saveCommitment(c: Commitment) {
    insertCommitment.run(
      c.commitmentId,
      c.agentId,
      c.payloadHash,
      c.alg,
      c.nonce,
      c.agentSignature ?? null,
      c.agentPubkey ? JSON.stringify(c.agentPubkey) : null,
      c.agentKeyThumbprint ?? null,
      c.createdAt,
      c.expiresAt
    )
  },

  getCommitment(id: string): Commitment | null {
    const row = selectCommitment.get(id)
    return row ? rowToCommitment(row) : null
  },

  /** Single-use consume. Returns true only for the caller that flipped it. */
  consumeCommitment(id: string): boolean {
    return consumeCommitment.run(id).changes === 1
  },

  getSettlement(verificationId: string): Settlement | null {
    const row = selectSettlement.get(verificationId)
    return row ? rowToSettlement(row) : null
  },

  /**
   * Idempotent, race-safe settlement issuance — exactly one per verification.
   * same tx  -> duplicate (idempotent replay); different tx -> conflict.
   * The PRIMARY KEY on verification_id is the source of truth under concurrency.
   */
  issueSettlement(settlement: Settlement): IssueSettlementResult {
    const existing = this.getSettlement(settlement.verificationId)
    if (existing) {
      return existing.txHash === settlement.txHash
        ? { status: 'duplicate', settlement: existing }
        : { status: 'conflict', existing }
    }
    try {
      insertSettlement.run(
        settlement.verificationId,
        settlement.txHash,
        JSON.stringify(settlement.receipt),
        settlement.issuedAt
      )
      markSettled.run(settlement.verificationId)
      return { status: 'issued', settlement }
    } catch (err) {
      if (String(err).includes('UNIQUE') || String(err).includes('PRIMARY')) {
        const now = this.getSettlement(settlement.verificationId)!
        return now.txHash === settlement.txHash
          ? { status: 'duplicate', settlement: now }
          : { status: 'conflict', existing: now }
      }
      throw err
    }
  },

  /**
   * Prunes the working set (verifications + commitments). Never touches
   * verification_events — the audit log is durable by design.
   */
  cleanupExpired(): number {
    const now = new Date()
    const nowIso = now.toISOString()
    const settledCutoff = new Date(now.getTime() - SETTLED_RETENTION_MS).toISOString()
    return (
      deleteExpiredVerifications.run(nowIso, settledCutoff).changes +
      deleteExpiredCommitments.run(nowIso).changes
    )
  },

  // --- API clients ---------------------------------------------------------
  createClient(c: Omit<Client, 'revokedAt'>) {
    insertClient.run(c.keyId, c.keyHash, c.name, c.env, c.createdAt)
  },

  getClientByHash(keyHash: string): Client | null {
    const row = selectClientByHash.get(keyHash)
    return row ? rowToClient(row) : null
  },

  /** Any non-revoked client exists — gates dev-open mode. */
  hasClients(): boolean {
    return (countClients.get()?.n ?? 0) > 0
  },

  listClients(): Client[] {
    return selectClients.all().map(rowToClient)
  },

  revokeClient(keyId: string): boolean {
    return revokeClientStmt.run(new Date().toISOString(), keyId).changes === 1
  },

  /** Append one decision to the durable log. Called once per /verify. */
  recordEvent(e: { decision: Decision; reason: string; binding: Binding; clientId: string; createdAt: string }) {
    insertEvent.run(e.decision, e.reason, e.binding, e.clientId, e.createdAt)
  },

  // --- dashboard aggregates (from the durable event log) -------------------
  stats() {
    return {
      production: statsForEnv('live'),
      sandbox: statsForEnv('test'),
    }
  },

  close() {
    db.close()
  },
}
