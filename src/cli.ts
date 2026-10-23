// `yuppers-verify record.json`: the command line over the same checks the
// website's /verify page runs.

import { readFile } from 'node:fs/promises'

import { blockstream } from './ots.ts'
import { verifyRecord, type CheckStatus, type ExportedRecord } from './verify.ts'

const USAGE = `Usage: yuppers-verify <record.json> [--block-source <url>] [--trust <ca.der>]...

Checks an exported Yuppers record: the history's hash chain, its place in the
day's tree, the OpenTimestamps proof against Bitcoin, and the time-stamp
authority's signed token. Nothing is sent anywhere except the block lookup.

  --block-source <url>  A Blockstream-style API to read Bitcoin blocks from
                        (default https://blockstream.info/api)
  --trust <file>        A DER certificate to trust for the authority's token;
                        repeat for more. Without one the chain is checked only
                        as far as the certificates in the token go.

Exit status: 0 when every check is ok or pending, 1 when one failed or could
not be made, 2 for a bad command line.
`

const LABELS: Record<CheckStatus, string> = {
  ok: 'ok         ',
  pending: 'pending    ',
  failed: 'FAILED     ',
  unavailable: 'not checked',
}

const TITLES = {
  anchor: 'Timestamp ',
  history: 'History   ',
  tree: 'Day’s tree',
  bitcoin: 'Bitcoin   ',
  authority: 'Authority ',
}

export async function main(argv: string[], out: (line: string) => void = console.log): Promise<number> {
  let file: string | undefined
  let blockSource: string | undefined
  const trust: string[] = []
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    if (argument === '--help' || argument === '-h') {
      out(USAGE)
      return 0
    }
    if (argument === '--block-source' || argument === '--trust') {
      const value = argv[++index]
      if (!value) {
        out(USAGE)
        return 2
      }
      if (argument === '--trust') trust.push(value)
      else blockSource = value
    } else if (argument.startsWith('-') || file) {
      out(USAGE)
      return 2
    } else {
      file = argument
    }
  }
  if (!file) {
    out(USAGE)
    return 2
  }

  let record: ExportedRecord
  try {
    record = JSON.parse(await readFile(file, 'utf8')) as ExportedRecord
    if (!record?.exchange?.id) throw new Error('no exchange in it')
  } catch (error) {
    out(`${file} is not an exported Yuppers record (${(error as Error).message}).`)
    return 2
  }

  const report = await verifyRecord(record, {
    blocks: blockSource ? blockstream(blockSource.replace(/\/+$/, '')) : undefined,
    trustRoots: await Promise.all(trust.map(async (path) => new Uint8Array(await readFile(path)))),
  })
  for (const check of report.checks) {
    out(`${LABELS[check.status]}  ${TITLES[check.id]}  ${check.detail}`)
  }
  out(report.ok ? '\nEvery check that could be made passed.' : '\nThis record did not pass every check.')
  return report.ok ? 0 : 1
}
