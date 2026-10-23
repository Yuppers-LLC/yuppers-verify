// Every check on an exported record, in the order a reader would make them.

import { equal, fromBase64, hash32, toHex } from './bytes.ts'
import { recompute, type ChainEntry } from './chain.ts'
import { followPath, yupLeaf } from './merkle.ts'
import { blockstream, checkOts, type BlockSource } from './ots.ts'
import { checkTsr } from './tsr.ts'

/** The `anchor` section of an exported record. */
export interface AnchorSection {
  /** The UTC day the tree was made for, `YYYY-MM-DD`. */
  day: string
  /** The tree's root, hex. This is what the two stamps stamp. */
  root: string
  tree_size: number
  leaf_index: number
  /** The audit path, hex, bottom-up. */
  path: string[]
  /** The history entry the leaf covered. */
  sequence: number
  /** The history's hash at `sequence`, hex. */
  last_hash: string
  /** The OpenTimestamps proof, base64, when there is one. */
  ots?: string | null
  ots_status?: 'PENDING' | 'COMPLETE' | 'FAILED' | null
  /** The RFC 3161 response, base64, when there is one. */
  tsr?: string | null
  tsr_status?: 'PENDING' | 'COMPLETE' | 'FAILED' | null
}

/** The parts of an exported record the verifier reads. */
export interface ExportedRecord {
  exchange: { id: string; last_event?: number }
  /** The footer sentence with the last entry's hash in it. */
  history_chain?: string | null
  anchor?: AnchorSection | null
  /** Every entry of the history with the fields its hash covers. */
  chain_entries?: ChainEntry[] | null
}

export type CheckId = 'anchor' | 'history' | 'tree' | 'bitcoin' | 'authority'
export type CheckStatus = 'ok' | 'pending' | 'failed' | 'unavailable'

export interface Check {
  id: CheckId
  status: CheckStatus
  /** A plain account in English: what was found, or why it failed. */
  detail: string
  /** The facts behind it, for a caller that words them itself. */
  facts?: {
    entries?: number
    sequence?: number
    day?: string
    height?: number
    time?: string
    authority?: string
    chain?: string
  }
}

export interface Report {
  checks: Check[]
  /** No check failed or was impossible. Pending stamps do not count against it. */
  ok: boolean
}

export interface Options {
  /** Where to read Bitcoin blocks from. Defaults to Blockstream's public API. */
  blocks?: BlockSource
  /** DER certificates to trust for the authority's signature. */
  trustRoots?: readonly Uint8Array[]
}

const HASH_IN_TEXT = /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g

function asBytes(text: string, what: string): Uint8Array {
  try {
    return fromBase64(text)
  } catch {
    throw new Error(`${what} is not base64`)
  }
}

/** Runs one check, turning a thrown error into a failure of it. */
async function run(id: CheckId, work: () => Promise<Omit<Check, 'id'>>): Promise<Check> {
  try {
    return { id, ...(await work()) }
  } catch (error) {
    return { id, status: 'failed', detail: (error as Error).message }
  }
}

export async function verifyRecord(record: ExportedRecord, options: Options = {}): Promise<Report> {
  const anchor = record.anchor
  if (!anchor) {
    return {
      ok: false,
      checks: [
        {
          id: 'anchor',
          status: 'unavailable',
          detail: 'This record has no public timestamp yet. The next day’s tree covers it.',
        },
      ],
    }
  }

  const checks: Check[] = []
  let root: Uint8Array | null = null
  try {
    root = hash32(anchor.root, "the day's root")
  } catch (error) {
    checks.push({ id: 'anchor', status: 'failed', detail: (error as Error).message })
  }

  checks.push(
    await run('history', async () => {
      const lastHash = hash32(anchor.last_hash, 'the anchored hash')
      const entries = record.chain_entries
      if (!entries || entries.length === 0) {
        return {
          status: 'unavailable',
          detail:
            'This file does not hold the history’s entries, so its hash chain cannot be recomputed. The hash the day’s tree covers is still followed below.',
        }
      }
      const { hashes } = await recompute(record.exchange.id, entries)
      if (anchor.sequence < 1 || anchor.sequence > hashes.length) {
        throw new Error(`the record has no entry ${anchor.sequence}`)
      }
      if (!equal(hashes[anchor.sequence - 1], lastHash)) {
        throw new Error(`the history up to entry ${anchor.sequence} does not give the hash the tree covers`)
      }
      if (record.exchange.last_event !== undefined && record.exchange.last_event !== hashes.length) {
        throw new Error(`the record says the history has ${record.exchange.last_event} entries, but the file holds ${hashes.length}`)
      }
      const latest = record.history_chain?.match(HASH_IN_TEXT)?.at(-1)
      if (latest && toHex(hashes.at(-1) as Uint8Array) !== latest.toLowerCase()) {
        throw new Error('the history does not end at the hash the record prints')
      }
      return {
        status: 'ok',
        detail: `The ${hashes.length} entries chain correctly, and entry ${anchor.sequence} gives the hash the day's tree covers.`,
        facts: { entries: hashes.length, sequence: anchor.sequence },
      }
    }),
  )

  checks.push(
    await run('tree', async () => {
      if (!root) throw new Error("the day's root is not usable")
      const leaf = await yupLeaf(record.exchange.id, hash32(anchor.last_hash, 'the anchored hash'))
      const path = anchor.path.map((item, index) => hash32(item, `path step ${index + 1}`))
      if (!(await followPath(leaf, anchor.leaf_index, anchor.tree_size, path, root))) {
        throw new Error(`this yup's leaf does not lead to the root of ${anchor.day}`)
      }
      return {
        status: 'ok',
        detail: `This yup's leaf leads to the root of ${anchor.day} in ${path.length} steps, in a tree of ${anchor.tree_size}.`,
        facts: { day: anchor.day },
      }
    }),
  )

  checks.push(
    await run('bitcoin', async () => {
      if (!anchor.ots) {
        return { status: 'pending', detail: 'There is no OpenTimestamps proof yet.' }
      }
      if (!root) throw new Error("the day's root is not usable")
      const outcome = await checkOts(asBytes(anchor.ots, 'the OpenTimestamps proof'), root, options.blocks ?? blockstream())
      switch (outcome.status) {
        case 'ok':
          return {
            status: 'ok',
            detail: `The root is in Bitcoin block ${outcome.height}, mined ${new Date(outcome.time * 1000).toISOString()}.`,
            facts: { height: outcome.height, time: new Date(outcome.time * 1000).toISOString() },
          }
        case 'pending':
          return {
            status: 'pending',
            detail: 'The proof has not reached Bitcoin yet. It does within hours; fetch the record again then.',
          }
        default:
          return { status: outcome.status, detail: outcome.reason }
      }
    }),
  )

  checks.push(
    await run('authority', async () => {
      if (!anchor.tsr) {
        return { status: 'pending', detail: 'There is no time-stamp token from an authority yet.' }
      }
      if (!root) throw new Error("the day's root is not usable")
      const outcome = await checkTsr(asBytes(anchor.tsr, 'the time-stamp token'), root, options.trustRoots)
      if (outcome.status === 'failed') return { status: 'failed', detail: outcome.reason }
      return {
        status: 'ok',
        detail: `Stamped by ${outcome.authority} at ${outcome.time}. The certificate chain ${outcome.chain}.`,
        facts: { authority: outcome.authority, time: outcome.time, chain: outcome.chain },
      }
    }),
  )

  return { checks, ok: checks.every((check) => check.status === 'ok' || check.status === 'pending') }
}
