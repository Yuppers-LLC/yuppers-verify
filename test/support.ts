// A small record built by hand: a history, a day's tree around its last hash,
// and an OpenTimestamps proof the tests make themselves.

import { concat, toHex, sha256, utf8 } from '../src/bytes.ts'
import { genesis, link, type ChainEntry } from '../src/chain.ts'
import { auditPath, merkleRoot, staffLeaf, yupLeaf } from '../src/merkle.ts'
import { MAGIC, type Block } from '../src/ots.ts'
import type { ExportedRecord } from '../src/verify.ts'

export const EXCHANGE = '3f2b6c1e-8a4d-4f7e-9b1a-0c5d7e2a9b44'
export const OTHER = '9d1c0a77-12ab-4c3d-8e5f-6a7b8c9d0e1f'

export function entries(): ChainEntry[] {
  return [
    {
      sequence: 1,
      type: 'CREATED',
      actor_kind: 'PARTICIPANT',
      actor_slot: 'A',
      data: { currency: 'USD', timezone: 'America/New_York' },
      occurred_at: '2026-10-01T10:00:00.000001Z',
    },
    {
      sequence: 2,
      type: 'REVISION_SENT',
      actor_kind: 'PARTICIPANT',
      actor_slot: 'A',
      revision_id: '11111111-2222-4333-8444-555555555555',
      note: 'Here is my offer é',
      data: {},
      occurred_at: '2026-10-01T10:05:00.5Z',
    },
    {
      sequence: 3,
      type: 'STAFF_NOTE',
      actor_kind: 'STAFF',
      data: { b: [1, 2, { z: null, a: 'x' }], a: true },
      occurred_at: '2026-10-02T09:00:00.123456Z',
      on_behalf_by: OTHER,
    },
  ]
}

export async function hashesOf(list: ChainEntry[]): Promise<Uint8Array[]> {
  const out: Uint8Array[] = []
  let previous = await genesis()
  for (const entry of list) {
    previous = await link(previous, EXCHANGE, entry)
    out.push(previous)
  }
  return out
}

/** `n` other leaves, with ours placed in a spot that is not the first or last. */
export async function dayLeaves(lastHash: Uint8Array, others = 6) {
  const leaves: Uint8Array[] = []
  for (let index = 0; index < others; index++) {
    leaves.push(await yupLeaf(`00000000-0000-4000-8000-00000000000${index}`, await sha256(utf8(`h${index}`))))
  }
  leaves.push(await staffLeaf(await sha256(utf8('staff'))))
  const ours = await yupLeaf(EXCHANGE, lastHash)
  leaves.push(ours)
  // Sorted by hash bytes, as the service does.
  leaves.sort((left, right) => toHex(left).localeCompare(toHex(right)))
  return { leaves, ours, index: leaves.findIndex((leaf) => toHex(leaf) === toHex(ours)) }
}

function varuint(value: number): number[] {
  const out: number[] = []
  let rest = value
  while (rest >= 0x80) {
    out.push((rest & 0x7f) | 0x80)
    rest = Math.floor(rest / 128)
  }
  out.push(rest)
  return out
}

/**
 * A proof of `root` that appends `suffix`, hashes, and ends at a Bitcoin
 * attestation at `height`. Returns the proof and the merkle root (internal
 * byte order) the attestation commits to.
 */
export async function makeOts(
  root: Uint8Array,
  height: number,
  options: { pending?: string; bitcoin?: boolean } = {},
): Promise<{ bytes: Uint8Array; commitment: Uint8Array }> {
  const suffix = utf8('salt')
  const commitment = await sha256(concat(root, suffix))
  const bitcoin = Uint8Array.of(0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01, ...varuint(varuint(height).length), ...varuint(height))
  const pendingUri = utf8(options.pending ?? '')
  const pending = Uint8Array.of(
    0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
    ...varuint(pendingUri.length + varuint(pendingUri.length).length),
    ...varuint(pendingUri.length),
    ...pendingUri,
  )
  const tail = options.bitcoin === false ? pending : bitcoin
  const bytes = concat(
    MAGIC,
    Uint8Array.of(0x01, 0x08),
    root,
    // append "salt", then sha256, then the attestation
    Uint8Array.of(0xf0, suffix.length, ...suffix, 0x08),
    tail,
  )
  return { bytes, commitment }
}

export function blockFor(commitment: Uint8Array, time = 1_700_000_000): Block {
  return { merkleRoot: toHex(Uint8Array.from(commitment).reverse()), time }
}

export async function makeRecord(): Promise<{
  record: ExportedRecord
  root: Uint8Array
  leaves: Uint8Array[]
}> {
  const list = entries()
  const hashes = await hashesOf(list)
  // The day's tree covered entry 2; entry 3 came after.
  const covered = hashes[1]
  const { leaves, index } = await dayLeaves(covered)
  const root = await merkleRoot(leaves)
  const path = await auditPath(leaves, index)
  return {
    root,
    leaves,
    record: {
      exchange: { id: EXCHANGE, last_event: 3 },
      history_chain: `History of 3 entries, last hash ${toHex(hashes[2])}.`,
      chain_entries: list,
      anchor: {
        day: '2026-10-02',
        root: toHex(root),
        tree_size: leaves.length,
        leaf_index: index,
        path: path.map(toHex),
        sequence: 2,
        last_hash: toHex(covered),
        ots: null,
        ots_status: 'PENDING',
        tsr: null,
        tsr_status: 'PENDING',
      },
    },
  }
}
