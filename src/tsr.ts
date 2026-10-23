// An RFC 3161 TimeStampResp (DER): the token's message imprint, its signature
// and its certificate chain.

import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

import { equal, toHex } from './bytes.ts'

const SHA256 = '2.16.840.1.101.3.4.2.1'
const ID_KP_TIME_STAMPING = '1.3.6.1.5.5.7.3.8'

const NAMES: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
}

export type TsrOutcome =
  | {
      status: 'ok'
      /** Who signed: the certificate's subject. */
      authority: string
      /** When the authority says it stamped the digest, ISO 8601 UTC. */
      time: string
      /** What the certificate chain was checked up to. */
      chain: string
      /** True when the chain reached a certificate the caller trusts; false when it only holds together. */
      trusted: boolean
    }
  | { status: 'failed'; reason: string }

function nameOf(name: pkijs.RelativeDistinguishedNames): string {
  return name.typesAndValues
    .map((item) => `${NAMES[item.type] ?? item.type}=${String(item.value.valueBlock.value)}`)
    .join(', ')
}

function view(buffer: ArrayBuffer | Uint8Array): ArrayBuffer {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function sameName(left: pkijs.RelativeDistinguishedNames, right: pkijs.RelativeDistinguishedNames): boolean {
  return toHex(new Uint8Array(left.toSchema().toBER())) === toHex(new Uint8Array(right.toSchema().toBER()))
}

/**
 * Checks a time-stamp response against the digest it should stamp.
 * `trustRoots` are DER certificates the caller trusts; without them the
 * chain is checked only as far as the certificates in the response go.
 */
export async function checkTsr(
  bytes: Uint8Array,
  expected: Uint8Array,
  trustRoots: readonly Uint8Array[] = [],
): Promise<TsrOutcome> {
  try {
    return await check(bytes, expected, trustRoots)
  } catch (error) {
    return { status: 'failed', reason: (error as Error).message }
  }
}

async function check(
  bytes: Uint8Array,
  expected: Uint8Array,
  trustRoots: readonly Uint8Array[],
): Promise<TsrOutcome> {
  const parsed = asn1js.fromBER(view(bytes))
  if (parsed.offset === -1) throw new Error('this is not a time-stamp response')
  const response = new pkijs.TimeStampResp({ schema: parsed.result })
  if (response.status.status > 1 || !response.timeStampToken) {
    throw new Error('the authority did not grant the time stamp')
  }
  const token = response.timeStampToken
  if (token.contentType !== pkijs.ContentInfo.SIGNED_DATA) throw new Error('the token is not signed data')
  const signed = new pkijs.SignedData({ schema: token.content })
  const content = signed.encapContentInfo.eContent
  if (!content) throw new Error('the token holds no time-stamp information')
  const inner = asn1js.fromBER(view(content.getValue()))
  if (inner.offset === -1) throw new Error('the time-stamp information cannot be read')
  const info = new pkijs.TSTInfo({ schema: inner.result })

  const imprint = info.messageImprint
  if (imprint.hashAlgorithm.algorithmId !== SHA256) throw new Error('the token stamps a digest that is not SHA-256')
  if (!equal(new Uint8Array(imprint.hashedMessage.valueBlock.valueHexView), expected)) {
    throw new Error("the token stamps a different digest than the day's root")
  }

  const certificates = (signed.certificates ?? []).filter(
    (item): item is pkijs.Certificate => item instanceof pkijs.Certificate,
  )
  const roots = trustRoots.map((root) => {
    const found = asn1js.fromBER(view(root))
    if (found.offset === -1) throw new Error('a trusted certificate cannot be read')
    return new pkijs.Certificate({ schema: found.result })
  })

  const signer = signed.signerInfos[0]
  if (!signer) throw new Error('the token has no signature')
  // The library's own time-stamp path wants the stamped data itself and hashes
  // it to compare with the imprint. All we have is the digest, and the imprint
  // is compared above, so it is told the content is plain data: the signature
  // is checked over the same bytes either way.
  signed.encapContentInfo.eContentType = '1.2.840.113549.1.7.1'
  const outcome = await signed.verify({
    signer: 0,
    checkChain: false,
    checkDate: info.genTime,
    extendedMode: true,
  })
  if (!outcome.signatureVerified) {
    throw new Error(`the signature does not verify (${outcome.message})`)
  }
  const certificate = outcome.signerCertificate
  if (!certificate) throw new Error("the signer's certificate is not in the response")

  const at = info.genTime
  if (at < certificate.notBefore.value || at > certificate.notAfter.value) {
    throw new Error("the stamp's time is outside the signer certificate's validity")
  }
  const usages = certificate.extensions?.find((item) => item.extnID === '2.5.29.37')
  const purposes = (usages?.parsedValue as pkijs.ExtKeyUsage | undefined)?.keyPurposes ?? []
  if (!purposes.includes(ID_KP_TIME_STAMPING)) {
    throw new Error('the signer certificate is not one for time stamps')
  }

  // The chain, walked here rather than by the library, which stumbles on
  // the cross-signed roots authorities include: up through the included
  // certificates, each signed by the next and valid when the stamp was made,
  // until a certificate the caller trusts signed it (or is it).
  const sameCertificate = (left: pkijs.Certificate, right: pkijs.Certificate) =>
    toHex(new Uint8Array(left.toSchema().toBER())) === toHex(new Uint8Array(right.toSchema().toBER()))
  let top = certificate
  let reachedRoot = false
  for (let depth = 0; depth < 10; depth++) {
    if (top.notBefore.value > at || top.notAfter.value < at) {
      throw new Error(`a certificate in the chain (${nameOf(top.subject)}) was not valid when the stamp was made`)
    }
    if (roots.some((root) => sameCertificate(root, top))) {
      reachedRoot = true
      break
    }
    const root = roots.find((item) => sameName(item.subject, top.issuer))
    if (root && (await top.verify(root))) {
      top = root
      reachedRoot = true
      break
    }
    if (sameName(top.issuer, top.subject)) break
    const parent = certificates.find((item) => item !== top && sameName(item.subject, top.issuer))
    if (!parent || !(await top.verify(parent))) break
    top = parent
  }
  if (roots.length > 0 && !reachedRoot) {
    throw new Error("the signer's certificate chain does not reach a certificate you trust")
  }
  const trusted = roots.length > 0
  return {
    status: 'ok',
    authority: nameOf(certificate.subject),
    time: info.genTime.toISOString(),
    chain: trusted
      ? `reaches a certificate you trust (${nameOf(top.subject)})`
      : `holds together up to ${nameOf(top.subject)}; compare it with the authority's published certificate`,
    trusted,
  }
}
