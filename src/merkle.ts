// The day's tree (RFC 6962 section 2.1) and the leaves it holds.

import { concat, equal, sha256, utf8, uuidBytes } from './bytes.ts'

/** A yup's leaf: SHA-256(0x00 || "yuppers-yup" || exchange ID (16 bytes) || last history hash (32 bytes)). */
export async function yupLeaf(exchangeId: string, lastHash: Uint8Array): Promise<Uint8Array> {
  return sha256(
    concat(Uint8Array.of(0), utf8('yuppers-yup'), uuidBytes(exchangeId, 'the exchange ID'), lastHash),
  )
}

/** The staff log's leaf: SHA-256(0x00 || "yuppers-staff" || the staff log's last hash). */
export async function staffLeaf(lastHash: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(Uint8Array.of(0), utf8('yuppers-staff'), lastHash))
}

async function node(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(Uint8Array.of(1), left, right))
}

/** The largest power of two below n (n at least 2). */
function split(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/** The root of a tree over leaves that are already leaf hashes. An empty tree is the hash of nothing. */
export async function merkleRoot(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array())
  if (leaves.length === 1) return leaves[0]
  const k = split(leaves.length)
  return node(await merkleRoot(leaves.slice(0, k)), await merkleRoot(leaves.slice(k)))
}

/** The audit path of one leaf, bottom-up (RFC 6962 section 2.1.1). */
export async function auditPath(leaves: readonly Uint8Array[], index: number): Promise<Uint8Array[]> {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new Error('no such leaf')
  if (leaves.length === 1) return []
  const k = split(leaves.length)
  return index < k
    ? [...(await auditPath(leaves.slice(0, k), index)), await merkleRoot(leaves.slice(k))]
    : [...(await auditPath(leaves.slice(k), index - k)), await merkleRoot(leaves.slice(0, k))]
}

/**
 * Whether `path` leads from the leaf at `index` to `root` in a tree of
 * `size` leaves (RFC 9162 section 2.1.3.2, the same walk as RFC 6962's).
 */
export async function followPath(
  leaf: Uint8Array,
  index: number,
  size: number,
  path: readonly Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) {
    return false
  }
  let fn = index
  let sn = size - 1
  let running = leaf
  for (const sibling of path) {
    if (sn === 0) return false
    if (fn % 2 === 1 || fn === sn) {
      running = await node(sibling, running)
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2)
          sn = Math.floor(sn / 2)
        }
      }
    } else {
      running = await node(running, sibling)
    }
    fn = Math.floor(fn / 2)
    sn = Math.floor(sn / 2)
  }
  return sn === 0 && equal(running, root)
}
