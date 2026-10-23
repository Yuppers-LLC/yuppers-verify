// Byte helpers and SHA-256. Web Crypto only, so the same code runs in Node
// and in a browser.

const encoder = new TextEncoder()

export function utf8(text: string): Uint8Array {
  return encoder.encode(text)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function toHex(bytes: Uint8Array): string {
  let text = ''
  for (const byte of bytes) text += byte.toString(16).padStart(2, '0')
  return text
}

export function fromHex(text: string): Uint8Array {
  const clean = text.trim().toLowerCase()
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) throw new Error('not hexadecimal')
  const out = new Uint8Array(clean.length / 2)
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16)
  }
  return out
}

/** A 32-byte hash in hex; throws with `what` named when it is anything else. */
export function hash32(text: unknown, what: string): Uint8Array {
  if (typeof text !== 'string' || !/^[0-9a-fA-F]{64}$/.test(text)) {
    throw new Error(`${what} is not a 64-character hexadecimal hash`)
  }
  return fromHex(text)
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text.replace(/\s+/g, ''))
  const out = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) out[index] = binary.charCodeAt(index)
  return out
}

export function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index++) if (left[index] !== right[index]) return false
  return true
}

export function reversed(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes).reverse()
}

export async function digest(algorithm: 'SHA-1' | 'SHA-256', data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest(algorithm, data as BufferSource))
}

export function sha256(data: Uint8Array): Promise<Uint8Array> {
  return digest('SHA-256', data)
}

/** A UUID as its 16 bytes. */
export function uuidBytes(text: unknown, what: string): Uint8Array {
  const hex = typeof text === 'string' ? text.replace(/-/g, '') : ''
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error(`${what} is not a UUID`)
  return fromHex(hex)
}
