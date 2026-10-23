// The hash chain over one yup's history, recomputed. This is the same
// algorithm the Yuppers service uses to write the chain, byte for byte.

import { concat, equal, hash32, sha256, utf8, uuidBytes } from './bytes.ts'

const DOMAIN = utf8('yuppers history chain v1')

/** The value the first entry chains from. */
export async function genesis(): Promise<Uint8Array> {
  return sha256(utf8('yuppers history chain genesis v1'))
}

/**
 * One entry of a history as the chain covers it: every field the hash reads,
 * as the record's `chain` section lists them. `occurred_at` is RFC 3339 with
 * the microseconds the service stores.
 */
export interface ChainEntry {
  sequence: number
  type: string
  actor_kind: string
  actor_slot?: string | null
  contribution_id?: string | null
  revision_id?: string | null
  note?: string | null
  evidence_attachment_id?: string | null
  /** The entry's stored details. Numbers beyond 2^53 or with fractions are not supported. */
  data?: unknown
  occurred_at: string
  on_behalf_by?: string | null
  /** The hash the service stored for the entry, hex. Checked when present. */
  chain_hash?: string | null
}

/** Compares strings by their UTF-8 bytes, which is how the service sorts keys. */
function byBytes(left: string, right: string): number {
  const a = utf8(left)
  const b = utf8(right)
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index]
  }
  return a.length - b.length
}

/** Details as the service writes them: keys sorted, no spaces. */
export function canonical(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>
    const keys = Object.keys(object).sort(byBytes)
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(',')}}`
  }
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new Error('a number in the details cannot be written exactly')
  }
  return JSON.stringify(value)
}

function bigEndian(value: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigInt64(0, value)
  return out
}

/** `2026-10-22T10:00:00.123456Z` as microseconds since the Unix epoch. */
export function microseconds(text: string): bigint {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(text)
  if (!match) throw new Error(`"${text}" is not an RFC 3339 time`)
  const seconds = Date.parse(`${match[1]}${match[3]}`)
  if (Number.isNaN(seconds)) throw new Error(`"${text}" is not a time`)
  const fraction = BigInt((match[2] ?? '').padEnd(6, '0').slice(0, 6))
  return BigInt(seconds / 1000) * 1_000_000n + fraction
}

/** A field: a presence byte, and if present an 8-byte length and the bytes. */
function field(bytes: Uint8Array | null): Uint8Array {
  return bytes === null ? Uint8Array.of(0) : concat(Uint8Array.of(1), bigEndian(BigInt(bytes.length)), bytes)
}

const optional = (text: string | null | undefined) => (text == null ? null : utf8(text))
const optionalId = (text: string | null | undefined, what: string) =>
  text == null ? null : uuidBytes(text, what)

/** The hash of an entry that follows `previous`. */
export async function link(
  previous: Uint8Array,
  exchangeId: string,
  entry: ChainEntry,
): Promise<Uint8Array> {
  const parts = [
    DOMAIN,
    previous,
    field(uuidBytes(exchangeId, 'the exchange ID')),
    field(bigEndian(BigInt(entry.sequence))),
    field(utf8(entry.type)),
    field(utf8(entry.actor_kind)),
    field(optional(entry.actor_slot)),
    field(optionalId(entry.contribution_id, 'a contribution ID')),
    field(optionalId(entry.revision_id, 'a revision ID')),
    field(optional(entry.note)),
    field(optionalId(entry.evidence_attachment_id, 'an evidence ID')),
    field(utf8(canonical(entry.data))),
    field(bigEndian(microseconds(entry.occurred_at))),
  ]
  // Only an entry with a guardian adds this, so older chains hash as they did.
  if (entry.on_behalf_by != null) {
    parts.push(utf8('on_behalf_by'), field(uuidBytes(entry.on_behalf_by, 'a guardian ID')))
  }
  return sha256(concat(...parts))
}

export interface ChainResult {
  /** Hash after each entry, by sequence (index 0 is entry 1). */
  hashes: Uint8Array[]
}

/**
 * Recomputes the chain over `entries` (entry 1 first, no gaps). Throws,
 * naming the entry, when the sequence has a gap or a stored hash differs.
 */
export async function recompute(exchangeId: string, entries: readonly ChainEntry[]): Promise<ChainResult> {
  let previous = await genesis()
  const hashes: Uint8Array[] = []
  for (const [index, entry] of entries.entries()) {
    if (entry.sequence !== index + 1) {
      throw new Error(`entry ${index + 1} is missing: the list goes from ${index} to ${entry.sequence}`)
    }
    const hash = await link(previous, exchangeId, entry)
    if (entry.chain_hash != null && !equal(hash32(entry.chain_hash, `the hash of entry ${entry.sequence}`), hash)) {
      throw new Error(`entry ${entry.sequence} does not give the hash stored with it`)
    }
    hashes.push(hash)
    previous = hash
  }
  return { hashes }
}
