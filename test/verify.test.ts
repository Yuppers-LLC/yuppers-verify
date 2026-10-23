import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import { fromBase64, fromHex, sha256, toHex, utf8 } from '../src/bytes.ts'
import { canonical, genesis, link, microseconds, recompute } from '../src/chain.ts'
import { auditPath, followPath, merkleRoot } from '../src/merkle.ts'
import { checkOts, parseOts, attestations } from '../src/ots.ts'
import { ripemd160 } from '../src/ripemd160.ts'
import { checkTsr } from '../src/tsr.ts'
import { verifyRecord, type ExportedRecord } from '../src/verify.ts'
import { EXCHANGE, blockFor, entries, makeOts, makeRecord } from './support.ts'

const fixture = (name: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)))
const hex = (text: string) => fromHex(text)

describe('the hash chain', () => {
  // The same row and answer as chain.rs's own test of a row written before guardians.
  it('gives the hash the service gives for a known row', async () => {
    const hash = await link(await genesis(), '00000000-0000-0000-0000-000000000001', {
      sequence: 1,
      type: 'CREATED',
      actor_kind: 'SYSTEM',
      actor_slot: null,
      data: { b: 1, a: [true, null] },
      occurred_at: '1970-01-01T00:00:00Z',
    })
    expect(toHex(hash)).toBe('5775e59609768afaaecb89ef6be1ce2296d9beb33852ddb1da0bbbe83271a595')
  })

  it('writes details with sorted keys and no spaces, ordering keys by their UTF-8 bytes', () => {
    expect(canonical({ b: 1, a: [true, null, 'x"y'], '\u{10000}': 1, '￿': 2 })).toBe(
      '{"a":[true,null,"x\\"y"],"b":1,"￿":2,"\u{10000}":1}',
    )
    expect(() => canonical({ n: 1.5 })).toThrow()
  })

  it('reads times to the microsecond', () => {
    expect(microseconds('1970-01-01T00:00:01.000002Z')).toBe(1_000_002n)
    expect(microseconds('2026-10-01T10:00:00.5Z')).toBe(1_790_848_800_500_000n)
    expect(() => microseconds('yesterday')).toThrow()
  })

  it('adds a guardian only when there is one', async () => {
    const [, , third] = entries()
    const base = await genesis()
    const without = await link(base, EXCHANGE, { ...third, on_behalf_by: null })
    const withGuardian = await link(base, EXCHANGE, third)
    expect(toHex(without)).not.toBe(toHex(withGuardian))
  })

  it('stops at a gap or a stored hash that is not what the entry gives', async () => {
    const list = entries()
    await expect(recompute(EXCHANGE, [list[0], list[2]])).rejects.toThrow(/entry 2 is missing/)
    await expect(recompute(EXCHANGE, [{ ...list[0], chain_hash: '00'.repeat(32) }])).rejects.toThrow(/entry 1/)
  })
})

describe('RIPEMD-160', () => {
  it('matches the published test vectors', () => {
    expect(toHex(ripemd160(new Uint8Array()))).toBe('9c1185a5c5e9fc54612808977ee8f548b2258d31')
    expect(toHex(ripemd160(utf8('abc')))).toBe('8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')
    expect(toHex(ripemd160(utf8('a'.repeat(1000))))).toBe(toHex(ripemd160(utf8('a'.repeat(1000)))))
    expect(toHex(ripemd160(utf8('12345678901234567890123456789012345678901234567890123456789012345678901234567890')))).toBe(
      '9b752e45573d4b39f4dbd3323cab82bf63326bfb',
    )
  })
})

describe('the tree', () => {
  // RFC 6962 test vectors (certificate-transparency's merkle tree tests).
  const inputs = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f']
  const leaves = async () =>
    Promise.all(inputs.map(async (input) => sha256(new Uint8Array([0, ...hex(input)]))))

  it('gives the roots of the published vectors', async () => {
    const all = await leaves()
    expect(toHex(await merkleRoot([]))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(toHex(await merkleRoot(all.slice(0, 1)))).toBe('6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d')
    expect(toHex(await merkleRoot(all.slice(0, 2)))).toBe('fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125')
    expect(toHex(await merkleRoot(all))).toBe('5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328')
  })

  it('follows every leaf of every size from 1 to 19 to the root, and no other way', async () => {
    for (let size = 1; size <= 19; size++) {
      const all = await Promise.all(Array.from({ length: size }, (_, index) => sha256(utf8(`leaf ${index}`))))
      const root = await merkleRoot(all)
      for (let index = 0; index < size; index++) {
        const path = await auditPath(all, index)
        expect(await followPath(all[index], index, size, path, root)).toBe(true)
        // Wrong position, a short path, a long one and a changed step all fail.
        expect(await followPath(all[index], (index + 1) % size === index ? size : (index + 1) % size, size, path, root)).toBe(false)
        if (path.length > 0) {
          expect(await followPath(all[index], index, size, path.slice(1), root)).toBe(false)
          const changed = [...path]
          changed[0] = await sha256(changed[0])
          expect(await followPath(all[index], index, size, changed, root)).toBe(false)
        }
        expect(await followPath(all[index], index, size, [...path, root], root)).toBe(false)
      }
    }
  })
})

describe('the OpenTimestamps proof', () => {
  it('reads a real proof, made by the project, down to its Bitcoin attestation', async () => {
    const proof = parseOts(fixture('hello.ots'))
    expect(proof.algorithm).toBe('sha256')
    expect(toHex(proof.digest)).toBe(toHex(await sha256(fixture('hello.txt'))))
    const reached = await attestations(proof)
    expect(reached.map((item) => item.attestation)).toEqual([{ kind: 'bitcoin', height: 358391 }])
  })

  it('checks it against the real block', async () => {
    const block = JSON.parse(new TextDecoder().decode(fixture('block-358391.json'))) as {
      merkle_root: string
      timestamp: number
    }
    const stamped = await sha256(fixture('hello.txt'))
    const source = async (height: number) => {
      expect(height).toBe(358391)
      return { merkleRoot: block.merkle_root, time: block.timestamp }
    }
    expect(await checkOts(fixture('hello.ots'), stamped, source)).toEqual({
      status: 'ok',
      height: 358391,
      time: block.timestamp,
    })
    // Another block's merkle root, another digest, a block source that is down.
    expect((await checkOts(fixture('hello.ots'), stamped, async () => ({ merkleRoot: '00'.repeat(32), time: 0 }))).status).toBe('failed')
    expect((await checkOts(fixture('hello.ots'), await sha256(utf8('other')), source)).status).toBe('failed')
    const down = await checkOts(fixture('hello.ots'), stamped, async () => {
      throw new Error('offline')
    })
    expect(down).toMatchObject({ status: 'unavailable' })
  })

  it('refuses what is not a proof', async () => {
    const stamped = await sha256(fixture('hello.txt'))
    const source = async () => ({ merkleRoot: '', time: 0 })
    expect((await checkOts(utf8('not a proof'), stamped, source)).status).toBe('failed')
    expect((await checkOts(fixture('hello.ots').slice(0, 100), stamped, source)).status).toBe('failed')
  })

  it('reports a proof that has only reached the calendars as pending', async () => {
    const { root } = await makeRecord()
    const { bytes } = await makeOts(root, 0, { bitcoin: false, pending: 'https://alice.btc.calendar.opentimestamps.org' })
    expect(await checkOts(bytes, root, async () => ({ merkleRoot: '', time: 0 }))).toEqual({
      status: 'pending',
      calendars: ['https://alice.btc.calendar.opentimestamps.org'],
    })
  })
})

describe('the time-stamp token', () => {
  const stamped = () => hex(new TextDecoder().decode(fixture('digicert.digest.hex')).trim())

  it('checks a real response from DigiCert', async () => {
    const outcome = await checkTsr(fixture('digicert.tsr'), stamped())
    expect(outcome).toMatchObject({ status: 'ok', trusted: false })
    if (outcome.status !== 'ok') return
    expect(outcome.authority).toContain('DigiCert')
    expect(outcome.time).toMatch(/^2026-10-22T/)
  })

  it('reaches a trusted root when it is given one', async () => {
    const outcome = await checkTsr(fixture('digicert.tsr'), stamped(), [fixture('digicert-trusted-root-g4.der')])
    expect(outcome).toMatchObject({ status: 'ok', trusted: true })
  })

  it('does not trust a root that did not sign the chain', async () => {
    // The timestamp responder's own certificate is not the chain's root.
    const wrong = fixture('digicert-trusted-root-g4.der').slice()
    wrong[200] ^= 1
    expect((await checkTsr(fixture('digicert.tsr'), stamped(), [wrong])).status).toBe('failed')
  })

  it('fails for another digest, a changed response and a response that is not one', async () => {
    expect((await checkTsr(fixture('digicert.tsr'), await sha256(utf8('other')))).status).toBe('failed')
    const changed = fixture('digicert.tsr').slice()
    // A digit of the time inside the signed time-stamp information.
    const time = Buffer.from(changed).indexOf('20261022')
    expect(time).toBeGreaterThan(0)
    changed[time + 7] ^= 1
    expect((await checkTsr(changed, stamped())).status).toBe('failed')
    expect((await checkTsr(utf8('nope'), stamped())).status).toBe('failed')
  })
})

describe('a whole record', () => {
  const statuses = (report: Awaited<ReturnType<typeof verifyRecord>>) =>
    Object.fromEntries(report.checks.map((check) => [check.id, check.status]))

  it('passes its chain and tree, with the stamps not made yet', async () => {
    const { record } = await makeRecord()
    const report = await verifyRecord(record)
    expect(statuses(report)).toEqual({ history: 'ok', tree: 'ok', bitcoin: 'pending', authority: 'pending' })
    expect(report.ok).toBe(true)
  })

  it('passes with a proof that reaches Bitcoin and fails if the block says otherwise', async () => {
    const { record, root } = await makeRecord()
    const { bytes, commitment } = await makeOts(root, 900_000)
    const stamped: ExportedRecord = {
      ...record,
      anchor: { ...record.anchor!, ots: btoa(String.fromCharCode(...bytes)), ots_status: 'COMPLETE' },
    }
    const good = await verifyRecord(stamped, { blocks: async () => blockFor(commitment) })
    expect(good.checks.find((check) => check.id === 'bitcoin')).toMatchObject({
      status: 'ok',
      facts: { height: 900_000 },
    })
    expect(good.ok).toBe(true)
    const bad = await verifyRecord(stamped, { blocks: async () => blockFor(await sha256(commitment)) })
    expect(statuses(bad).bitcoin).toBe('failed')
    expect(bad.ok).toBe(false)
  })

  it('fails when the proof stamps a different root', async () => {
    const { record } = await makeRecord()
    const { bytes, commitment } = await makeOts(await sha256(utf8('another day')), 1)
    const report = await verifyRecord(
      { ...record, anchor: { ...record.anchor!, ots: btoa(String.fromCharCode(...bytes)) } },
      { blocks: async () => blockFor(commitment) },
    )
    expect(statuses(report).bitcoin).toBe('failed')
  })

  it('fails when the token stamps a different root', async () => {
    const { record } = await makeRecord()
    const tsr = btoa(String.fromCharCode(...fixture('digicert.tsr')))
    const report = await verifyRecord({ ...record, anchor: { ...record.anchor!, tsr } })
    expect(statuses(report).authority).toBe('failed')
  })

  it('fails when an entry of the history was changed', async () => {
    const { record } = await makeRecord()
    const changed = structuredClone(record)
    changed.chain_entries![0].note = 'edited'
    // Its stored hash no longer matches, or, with none stored, the covered hash moves.
    const report = await verifyRecord(changed)
    expect(statuses(report).history).toBe('failed')
    const stripped = structuredClone(changed)
    for (const entry of stripped.chain_entries!) delete entry.chain_hash
    expect(statuses(await verifyRecord(stripped)).history).toBe('failed')
  })

  it('fails when the covered hash, the path or the root is not the tree’s', async () => {
    const { record } = await makeRecord()
    const path = structuredClone(record)
    path.anchor!.path[0] = '00'.repeat(32)
    expect(statuses(await verifyRecord(path)).tree).toBe('failed')

    const root = structuredClone(record)
    root.anchor!.root = '11'.repeat(32)
    expect(statuses(await verifyRecord(root)).tree).toBe('failed')

    const index = structuredClone(record)
    index.anchor!.leaf_index = (index.anchor!.leaf_index + 1) % index.anchor!.tree_size
    expect(statuses(await verifyRecord(index)).tree).toBe('failed')

    const hash = structuredClone(record)
    hash.anchor!.last_hash = '22'.repeat(32)
    const report = await verifyRecord(hash)
    expect(statuses(report)).toMatchObject({ history: 'failed', tree: 'failed' })

    const other = structuredClone(record)
    other.exchange.id = '00000000-0000-4000-8000-0000000000aa'
    expect(statuses(await verifyRecord(other)).tree).toBe('failed')
  })

  it('fails when the history ends elsewhere than the printed hash', async () => {
    const { record } = await makeRecord()
    const printed = { ...record, history_chain: `Last hash ${'33'.repeat(32)}` }
    expect(statuses(await verifyRecord(printed)).history).toBe('failed')
  })

  it('says plainly what it could not check', async () => {
    const { record } = await makeRecord()
    const thin = { ...record, chain_entries: undefined }
    const report = await verifyRecord(thin)
    expect(statuses(report).history).toBe('unavailable')
    expect(report.ok).toBe(false)
    const none = await verifyRecord({ ...record, anchor: null })
    expect(none.checks).toHaveLength(1)
    expect(none.ok).toBe(false)
  })

  it('reads the base64 the service sends', () => {
    expect(toHex(fromBase64('AAEC/w=='))).toBe('000102ff')
  })
})
