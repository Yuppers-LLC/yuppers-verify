# @yuppers/verify

Checks that a Yuppers record's history was publicly timestamped on a date.

## Why this is public

Yuppers fingerprints every yup's history once a day and has the fingerprint
stamped by two services it does not control: the Bitcoin chain, through
OpenTimestamps, and a public RFC 3161 timestamp authority. This code lets
anyone check a record against those stamps without trusting Yuppers, and it
keeps working if Yuppers is gone. [FORMAT.md](FORMAT.md) describes every
check exactly, so you can also write your own verifier.

It reads an exported record (the JSON file from "Download" on the record
page) and runs five checks:

| Check       | What it shows |
| ----------- | ------------- |
| `history`   | The history's hash chain, recomputed from the entries in the file, ends at the hash the day's tree covered (entry `anchor.sequence`), and at the hash the record prints for its latest entry. |
| `tree`      | The yup's leaf follows `anchor.path` to `anchor.root`. |
| `bitcoin`   | `anchor.ots`, a standard OpenTimestamps proof, stamps that root, and the Bitcoin block it names has the proof's merkle root. Reports the block's time. A proof not yet in Bitcoin is `pending`, not a failure. |
| `authority` | `anchor.tsr`, an RFC 3161 response, stamps that root, is signed by its certificate, and the certificate's chain holds. Reports the authority and its time. |
| `anchor`    | Only when the record has no `anchor` yet. |

A check is `ok`, `pending` (not made yet: try again later), `failed` (it
does not hold, with why) or `unavailable` (it could not be made, for example
the block source is offline or the file lacks the entries). The command exits
0 when every check is ok or pending, 1 otherwise, 2 for a bad command line.

What the checks prove: the history up to entry N, as it stood when the day's
tree was made, existed by the time of the Bitcoin block and the authority's
time.

## What it does not prove

- That the entries are true, or what they mean, or that anyone agreed to
  anything. Only that they were not changed after that date.
- Anything about entries after `anchor.sequence`. A later day covers them.
- That the Bitcoin block source is honest. Use `--block-source` for another.
- The authority's certificate chain, unless you pass `--trust`.
- A record whose text is hidden has no entries in the file. Its `history`
  check is `unavailable`.
- That a court would accept it.

## Install and use

From git. Pin a commit or a tag:

```
npm install github:vchance/yuppers-verify#v0.1.0
npx yuppers-verify record.json
```

Or clone it:

```
git clone https://github.com/vchance/yuppers-verify
cd yuppers-verify && npm ci
node bin/yuppers-verify.mjs record.json
```

Installing from git runs `npm run build`, which compiles `src/` to `dist/`
for the command line. Other options:

```
yuppers-verify record.json --block-source https://mempool.space/api --trust root.der
```

Needs Node 22.18 or later. The only network call is the Bitcoin block lookup
(`/block-height/{h}`, then `/block/{hash}` on a Blockstream-compatible API);
`--block-source` changes where. Without `--trust`, the authority's
certificate chain is checked as far as the certificates in the response go;
with one or more DER certificates it must reach one of them.

## Library

```ts
import { verifyRecord } from '@yuppers/verify'
// The package exports its TypeScript source, so your bundler compiles it.

const report = await verifyRecord(JSON.parse(text), {
  // blocks: async (height) => ({ merkleRoot: '…display-order hex…', time: 1700000000 }),
  // trustRoots: [derBytes],
})
for (const check of report.checks) console.log(check.id, check.status, check.detail)
```

The core uses only Web Crypto, `fetch` and two libraries (`pkijs`, `asn1js`),
so it runs in a browser as it does in Node. Nothing is sent anywhere but the
block lookup.

## The format

See [FORMAT.md](FORMAT.md).

## License

MIT.
