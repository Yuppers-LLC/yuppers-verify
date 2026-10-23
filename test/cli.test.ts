import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

import { main } from '../src/cli.ts'
import { makeRecord } from './support.ts'

async function run(args: string[]) {
  const lines: string[] = []
  const code = await main(args, (line) => lines.push(line))
  return { code, text: lines.join('\n') }
}

async function file(content: unknown) {
  const path = join(await mkdtemp(join(tmpdir(), 'verify-')), 'record.json')
  await writeFile(path, typeof content === 'string' ? content : JSON.stringify(content))
  return path
}

describe('yuppers-verify', () => {
  it('prints each check and exits 0 when none failed', async () => {
    const { record } = await makeRecord()
    const { code, text } = await run([await file(record)])
    expect(code).toBe(0)
    expect(text).toMatch(/ok\s+History/)
    expect(text).toMatch(/pending\s+Bitcoin/)
  })

  it('exits 1 on a failed check and says which', async () => {
    const { record } = await makeRecord()
    record.anchor!.path[0] = '00'.repeat(32)
    const { code, text } = await run([await file(record)])
    expect(code).toBe(1)
    expect(text).toMatch(/FAILED\s+Day.s tree/)
  })

  it('exits 2 for a file that is not a record and for a bad command line', async () => {
    expect((await run([await file('not json')])).code).toBe(2)
    expect((await run([])).code).toBe(2)
    expect((await run(['--nope'])).code).toBe(2)
  })
})
