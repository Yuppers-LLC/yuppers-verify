# What the verifier checks

This file describes exactly what `@yuppers/verify` reads and computes. It is
written so that you can redo every check with `openssl`, the OpenTimestamps
client and a few lines of any language. The source in `src/` is the
reference: `chain.ts`, `merkle.ts`, `ots.ts`, `tsr.ts` and `verify.ts`.

Notation: `‖` is concatenation. `SHA-256(x)` is the 32-byte digest. "Hex" is
lowercase hexadecimal; the verifier also accepts uppercase. A UUID is the 16
bytes you get by reading its `8-4-4-4-12` text as hex.

## 1. What a record gives you

A Yuppers record can be downloaded as JSON. The verifier reads these fields
and ignores the rest.

```
exchange.id            UUID of the yup
exchange.last_event    optional number: how many history entries there are
history_chain          optional text; the last 64-hex string in it is the
                       hash the record prints for its latest entry
chain_entries[]        the history entries, in sequence order (section 2)
anchor                 the public-timestamp section, or null (section 5)
```

`anchor` is `null` until the first daily tree covers the yup. Then it is:

```
day          "YYYY-MM-DD", the UTC day the tree was made for
root         64 hex: the day's root (section 4)
tree_size    number of leaves in the tree
leaf_index   position of this yup's leaf in the sorted leaves
path         array of 64-hex hashes, bottom-up (section 4)
sequence     the history entry the tree covered (1-based)
last_hash    64 hex: the history's hash at that entry
ots          base64 of the .ots file, or null
ots_status   "PENDING" | "COMPLETE" | "FAILED" | null
tsr          base64 of the .tsr file, or null
tsr_status   "PENDING" | "COMPLETE" | "FAILED" | null
```

`ots_status` and `tsr_status` come from the service. The verifier does not
rely on them; it checks the files.

## 2. The history chain

`chain_entries` has one object per history entry, entry 1 first, with no
gaps (`sequence` must be 1, 2, 3, ...):

```
sequence                 integer
type                     string
actor_kind               string
actor_slot               string or null
contribution_id          UUID or null
revision_id              UUID or null
note                     string or null
evidence_attachment_id   UUID or null
data                     any JSON value (null counts as "null")
occurred_at              RFC 3339 time with an offset, up to 9 fractional digits
on_behalf_by             UUID or null (a guardian's ID)
chain_hash               64 hex, the hash the service stored (optional)
```

**Field encoding.** `F(null)` is the single byte `00`. `F(bytes)` is `01 ‖
len ‖ bytes`, where `len` is the byte length as an 8-byte big-endian
unsigned integer.

**Genesis.** `H0 = SHA-256("yuppers history chain genesis v1")` (the ASCII
text, no terminator).

**Entry hash.** With `H(n-1)` the previous hash:

```
H(n) = SHA-256(
    "yuppers history chain v1"                 ASCII, no terminator, no F()
  ‖ H(n-1)                                     32 bytes, no F()
  ‖ F( exchange.id as 16 bytes )
  ‖ F( sequence as 8-byte big-endian )
  ‖ F( type, UTF-8 )
  ‖ F( actor_kind, UTF-8 )
  ‖ F( actor_slot, UTF-8 )                     F(null) when absent
  ‖ F( contribution_id as 16 bytes )           F(null) when absent
  ‖ F( revision_id as 16 bytes )               F(null) when absent
  ‖ F( note, UTF-8 )                           F(null) when absent
  ‖ F( evidence_attachment_id as 16 bytes )    F(null) when absent
  ‖ F( canonical(data), UTF-8 )
  ‖ F( occurred_at as microseconds, 8-byte big-endian signed )
  [ ‖ "on_behalf_by" ‖ F( on_behalf_by as 16 bytes ) ]   only when present
)
```

Notes:

- `canonical(data)` is JSON with object keys sorted by their UTF-8 bytes,
  no spaces, strings written as `JSON.stringify` writes them, and `null`
  for a missing value. Numbers must be integers that fit in 53 bits; the
  verifier refuses others.
- `occurred_at` becomes whole microseconds since the Unix epoch. Digits
  beyond the sixth fractional digit are dropped, not rounded.
- The `on_behalf_by` part is appended only for an entry done in a guardian's
  name. The ASCII label `on_behalf_by` is written raw, without `F()`.
- If `chain_hash` is present, it must equal the computed hash.

The verifier then requires:

- the hash at entry `anchor.sequence` equals `anchor.last_hash`;
- if `exchange.last_event` is present, it equals the number of entries;
- if `history_chain` holds a 64-hex string, the last one equals the hash of
  the final entry.

## 3. The yup's leaf

```
leaf = SHA-256( 00 ‖ "yuppers-yup" ‖ exchange.id (16 bytes) ‖ last_hash (32 bytes) )
```

`"yuppers-yup"` is ASCII with no terminator. `last_hash` is `anchor.last_hash`.
(The service also puts one leaf for its own staff log in each tree,
`SHA-256(00 ‖ "yuppers-staff" ‖ staff log hash)`. A record does not need it.)

## 4. The day's tree, the path and the root

Each day the service takes all leaves, **sorts them ascending by their 32
bytes** (unsigned, first byte first) and builds the Merkle tree of RFC 6962
section 2.1 over them:

- no leaves: `SHA-256("")`
- one leaf: the leaf itself
- n >= 2 leaves: let `k` be the largest power of two less than n;
  `node = SHA-256( 01 ‖ MTH(first k) ‖ MTH(the other n-k) )`

The leaves here are already hashes, so no further leaf prefix is applied.
The **root** is `MTH` of the sorted leaves. `anchor.root` is that root.

`anchor.path` is the RFC 6962 audit path for the leaf at `leaf_index`,
bottom-up. The verifier follows it with the RFC 9162 section 2.1.3.2
algorithm:

```
fn = leaf_index; sn = tree_size - 1; r = leaf
fail if leaf_index >= tree_size
for p in path:
    fail if sn == 0
    if fn is odd or fn == sn:
        r = SHA-256(01 ‖ p ‖ r)
        if fn is even:
            while fn is even and fn != 0: fn >>= 1; sn >>= 1
    else:
        r = SHA-256(01 ‖ r ‖ p)
    fn >>= 1; sn >>= 1
pass iff sn == 0 and r == root
```

## 5. The two stamps

What is stamped is the root itself, 32 bytes.

**Bitcoin (OpenTimestamps).** `ots` is a detached `.ots` file whose file
digest is the root: magic header, version 1, hash type `08` (SHA-256), the
32-byte root, then the proof tree. You can check it with the standard
client: write the file out and run `ots info day.ots`, then `ots verify
day.ots` (the client wants a file to hash; to give it the root directly, use
`ots verify -d <root hex> day.ots`).

The verifier parses the file, requires SHA-256 and a digest equal to the
root, then follows every branch of operations (append, prepend, SHA-256,
SHA-1, RIPEMD-160, reverse, hexlify; Keccak branches are skipped). It looks
for a Bitcoin attestation (tag `05 88 96 0d 73 d7 19 01`, payload: block
height). At such an attestation the message it has computed is the block's
merkle root in internal byte order. It fetches the block at that height from
a Blockstream-style API (`GET {base}/block-height/{height}` gives the block
hash, `GET {base}/block/{hash}` gives JSON with `merkle_root` and
`timestamp`) and requires the reversed message, in hex, to equal
`merkle_root`. The block's `timestamp` is the Bitcoin time reported.

A file with only pending attestations (tag `83 df e3 0d 2e f9 0c 8e`, payload
a calendar URL) has not reached Bitcoin yet.

**Authority (RFC 3161).** `tsr` is a DER `TimeStampResp`. You can inspect it
with `openssl ts -reply -in day.tsr -text` and verify it with `openssl ts
-verify -in day.tsr -digest <root hex> -CAfile roots.pem -untrusted
certs.pem`, where `certs.pem` holds the certificates inside the response.

The verifier requires: the status is granted (0 or 1); the token is CMS
signed data; the `TSTInfo` message imprint uses SHA-256 and equals the root;
the signature verifies with the signer certificate that is in the response;
the stamp time lies within that certificate's validity; the certificate has
the time-stamping extended key usage (1.3.6.1.5.5.7.3.8). It then walks the
chain upward through the certificates in the response, checking each
signature and that each was valid at the stamp time. If you give it trusted
DER certificates (`--trust`), the chain must reach one of them. Without
them it only reports how far the included certificates go, and you should
compare the top certificate with the authority's published one.

## 6. Where to get the files

All are public, with no sign-in. Base URL `https://yuppers.app`.

```
GET /v1/anchors                  JSON list of days, newest first
GET /v1/anchors/{day}            JSON: day, root, tree_size, staff_head,
                                 created_at, ots_status, tsr_status
GET /v1/anchors/{day}.ots        the .ots file (404 until a calendar took it)
GET /v1/anchors/{day}.tsr        the .tsr file (404 until granted)
```

A record already carries the two files for its own day, in `anchor`. The
published copies should have the same `root`. A copy from Yuppers proves
nothing by itself: the checks above do.

## 7. What each status means

Each check reports one of four statuses.

- `ok`: the check was made and holds.
- `pending`: the stamp does not exist yet (no file, or the `.ots` has no
  Bitcoin attestation yet). Try again later. Pending does not count against
  the result.
- `failed`: the check was made and does not hold. The detail says why.
- `unavailable`: the check could not be made, for example the record has no
  `chain_entries`, or the block source could not be reached.

The checks, by `id`:

| id          | Holds when |
| ----------- | ---------- |
| `anchor`    | Reported alone, as `unavailable`, when the record has no `anchor`. It also reports `failed` when `anchor.root` is not 64 hex. |
| `history`   | Section 2 passes. `unavailable` when `chain_entries` is null or empty. |
| `tree`      | Section 3 and 4: the leaf follows the path to `anchor.root`. |
| `bitcoin`   | The `.ots` stamps the root and reaches a Bitcoin block whose merkle root matches (section 5). |
| `authority` | The `.tsr` stamps the root and its signature and chain hold (section 5). |

The overall result is ok when no check is `failed` or `unavailable`.
Pending checks are allowed.

## 8. Known limits

- **`tree_size` is not bound by the root.** The root commits to the leaves
  and their order, but not to how many there are. The size only gives the
  shape of the path. A path that reaches the stamped root is what counts.
- **Hidden yups have null `chain_entries`.** When a reviewer has hidden a
  yup's text, the export carries `chain_entries: null`. The `history` check
  is then `unavailable`. The tree, Bitcoin and authority checks still run on
  the hash the record gives.
- The verifier does not check that a Bitcoin block is on the best chain
  beyond what the block source says. Use your own node or a second source
  with `--block-source` if that matters.
- Without trusted roots, the authority's certificate chain is checked only
  as far as the response goes.
- A stamp shows that data existed by a time. It does not show that the data
  is true. See the README.
