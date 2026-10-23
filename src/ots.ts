// A detached OpenTimestamps proof (.ots): read it, follow its operations from
// the stamped digest, and find the attestations at the ends. Only what a
// proof of a SHA-256 digest into Bitcoin needs: the file format of
// https://github.com/opentimestamps/python-opentimestamps, minus Keccak
// branches, which are skipped.

import { concat, digest, equal, reversed, toHex, utf8 } from './bytes.ts'
import { ripemd160 } from './ripemd160.ts'

export const MAGIC = Uint8Array.of(
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
)

const BITCOIN = Uint8Array.of(0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01)
const PENDING = Uint8Array.of(0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e)

export type Operation =
  | { op: 'append' | 'prepend'; argument: Uint8Array }
  | { op: 'sha256' | 'sha1' | 'ripemd160' | 'keccak256' | 'hexlify' | 'reverse' }

export type Attestation =
  | { kind: 'bitcoin'; height: number }
  | { kind: 'pending'; uri: string }
  | { kind: 'unknown'; tag: string }

/** A step of a proof: an attestation, or an operation and what follows it. */
export type Step =
  | { attestation: Attestation }
  | { operation: Operation; next: Timestamp }

/** What branches from one message: every step is a fork. */
export type Timestamp = Step[]

export interface Proof {
  /** The hash function of the stamped file ('sha256' for ours). */
  algorithm: string
  /** The digest that was stamped. */
  digest: Uint8Array
  timestamp: Timestamp
}

class Reader {
  offset = 0
  bytes: Uint8Array
  constructor(bytes: Uint8Array) {
    this.bytes = bytes
  }

  byte(): number {
    if (this.offset >= this.bytes.length) throw new Error('the proof ends too soon')
    return this.bytes[this.offset++]
  }

  take(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.bytes.length) throw new Error('the proof ends too soon')
    const out = this.bytes.slice(this.offset, this.offset + length)
    this.offset += length
    return out
  }

  varuint(): number {
    let value = 0
    let shift = 1
    for (let count = 0; count < 8; count++) {
      const byte = this.byte()
      value += (byte & 0x7f) * shift
      if ((byte & 0x80) === 0) return value
      shift *= 128
    }
    throw new Error('a number in the proof is too long')
  }

  varbytes(limit = 1 << 20): Uint8Array {
    const length = this.varuint()
    if (length > limit) throw new Error('a field in the proof is too long')
    return this.take(length)
  }

  get done(): boolean {
    return this.offset >= this.bytes.length
  }
}

const ALGORITHMS: Record<number, string> = { 0x02: 'sha1', 0x03: 'ripemd160', 0x08: 'sha256', 0x67: 'keccak256' }
const DIGEST_LENGTH: Record<string, number> = { sha1: 20, ripemd160: 20, sha256: 32, keccak256: 32 }

const MAX_DEPTH = 256

function step(reader: Reader, tag: number, depth: number): Step {
  if (tag === 0x00) {
    const kind = reader.take(8)
    const payload = new Reader(reader.varbytes())
    if (equal(kind, BITCOIN)) return { attestation: { kind: 'bitcoin', height: payload.varuint() } }
    if (equal(kind, PENDING)) {
      return { attestation: { kind: 'pending', uri: new TextDecoder().decode(payload.varbytes(1000)) } }
    }
    return { attestation: { kind: 'unknown', tag: toHex(kind) } }
  }
  let operation: Operation
  if (tag === 0xf0 || tag === 0xf1) {
    operation = { op: tag === 0xf0 ? 'append' : 'prepend', argument: reader.varbytes(4096) }
  } else if (tag === 0xf2) {
    operation = { op: 'reverse' }
  } else if (tag === 0xf3) {
    operation = { op: 'hexlify' }
  } else if (ALGORITHMS[tag]) {
    operation = { op: ALGORITHMS[tag] } as Operation
  } else {
    throw new Error(`the proof has an operation (0x${tag.toString(16)}) this reader does not know`)
  }
  return { operation, next: timestamp(reader, depth + 1) }
}

function timestamp(reader: Reader, depth: number): Timestamp {
  if (depth > MAX_DEPTH) throw new Error('the proof nests too deeply')
  const steps: Step[] = []
  let tag = reader.byte()
  while (tag === 0xff) {
    steps.push(step(reader, reader.byte(), depth))
    tag = reader.byte()
  }
  steps.push(step(reader, tag, depth))
  return steps
}

/** Reads a whole .ots file. Throws when it is not one. */
export function parseOts(bytes: Uint8Array): Proof {
  const reader = new Reader(bytes)
  if (!equal(reader.take(MAGIC.length), MAGIC)) throw new Error('this is not an OpenTimestamps proof')
  const version = reader.varuint()
  if (version !== 1) throw new Error(`proof version ${version} is not supported`)
  const algorithm = ALGORITHMS[reader.byte()]
  if (!algorithm) throw new Error('the proof stamps a digest this reader does not know')
  const stamped = reader.take(DIGEST_LENGTH[algorithm])
  const tree = timestamp(reader, 0)
  if (!reader.done) throw new Error('the proof has bytes after its end')
  return { algorithm, digest: stamped, timestamp: tree }
}

async function apply(operation: Operation, message: Uint8Array): Promise<Uint8Array | null> {
  switch (operation.op) {
    case 'append':
      return concat(message, operation.argument)
    case 'prepend':
      return concat(operation.argument, message)
    case 'sha256':
      return digest('SHA-256', message)
    case 'sha1':
      return digest('SHA-1', message)
    case 'ripemd160':
      return ripemd160(message)
    case 'reverse':
      return reversed(message)
    case 'hexlify':
      return utf8(toHex(message))
    default:
      // Keccak: nothing on the way to Bitcoin uses it.
      return null
  }
}

export interface Reached {
  attestation: Attestation
  /** The message at this attestation: for Bitcoin, the block's merkle root (internal byte order). */
  message: Uint8Array
}

/** Follows every fork from `start` and lists the attestations it reaches. */
export async function attestations(proof: Proof, start = proof.digest): Promise<Reached[]> {
  const reached: Reached[] = []
  async function walk(tree: Timestamp, message: Uint8Array) {
    for (const item of tree) {
      if ('attestation' in item) {
        reached.push({ attestation: item.attestation, message })
        continue
      }
      const next = await apply(item.operation, message)
      if (next) await walk(item.next, next)
    }
  }
  await walk(proof.timestamp, start)
  return reached
}

/** One block as a public source gives it. */
export interface Block {
  /** The merkle root as Bitcoin displays it (hex, reversed from the header's bytes). */
  merkleRoot: string
  /** Seconds since the epoch. */
  time: number
}

export type BlockSource = (height: number) => Promise<Block>

/**
 * Blockstream's public API (or any with the same two calls): the block at a
 * height, then its header's merkle root and time.
 */
export function blockstream(
  base = 'https://blockstream.info/api',
  fetcher: typeof fetch = (...args) => globalThis.fetch(...args),
): BlockSource {
  return async (height) => {
    const found = await fetcher(`${base}/block-height/${height}`)
    if (!found.ok) throw new Error(`the block source answered ${found.status} for height ${height}`)
    const hash = (await found.text()).trim()
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('the block source did not give a block hash')
    const block = await fetcher(`${base}/block/${hash}`)
    if (!block.ok) throw new Error(`the block source answered ${block.status} for block ${hash}`)
    const body = (await block.json()) as { merkle_root?: unknown; timestamp?: unknown }
    if (typeof body.merkle_root !== 'string' || typeof body.timestamp !== 'number') {
      throw new Error('the block source gave an answer this reader does not understand')
    }
    return { merkleRoot: body.merkle_root.toLowerCase(), time: body.timestamp }
  }
}

export type OtsOutcome =
  | { status: 'ok'; height: number; time: number }
  | { status: 'pending'; calendars: string[] }
  | { status: 'failed'; reason: string }
  | { status: 'unavailable'; reason: string }

/**
 * Checks a proof against the digest it should stamp (the day's root) and,
 * for a Bitcoin attestation, against the block's merkle root from a public
 * source. A proof with only pending attestations is `pending`, not a failure.
 */
export async function checkOts(
  bytes: Uint8Array,
  expected: Uint8Array,
  blocks: BlockSource,
): Promise<OtsOutcome> {
  let proof: Proof
  try {
    proof = parseOts(bytes)
  } catch (error) {
    return { status: 'failed', reason: (error as Error).message }
  }
  if (proof.algorithm !== 'sha256' || !equal(proof.digest, expected)) {
    return { status: 'failed', reason: "the proof stamps a different digest than the day's root" }
  }
  const reached = await attestations(proof)
  const bitcoin = reached.filter((item) => item.attestation.kind === 'bitcoin')
  if (bitcoin.length === 0) {
    const calendars = reached.flatMap((item) => (item.attestation.kind === 'pending' ? [item.attestation.uri] : []))
    if (calendars.length > 0) return { status: 'pending', calendars }
    return { status: 'failed', reason: 'the proof reaches no attestation' }
  }
  let trouble: OtsOutcome | null = null
  for (const item of bitcoin) {
    const height = (item.attestation as { height: number }).height
    let block: Block
    try {
      block = await blocks(height)
    } catch (error) {
      trouble ??= { status: 'unavailable', reason: `block ${height} could not be read: ${(error as Error).message}` }
      continue
    }
    if (toHex(reversed(item.message)) === block.merkleRoot) return { status: 'ok', height, time: block.time }
    trouble = { status: 'failed', reason: `the proof does not lead to the merkle root of Bitcoin block ${height}` }
  }
  return trouble as OtsOutcome
}
