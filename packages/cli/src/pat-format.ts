/**
 * PAT mint helper (CLI-local).
 *
 * Mirrors the canonical format from `packages/core/src/pats/format.ts`
 * (spec §8.1):
 *
 *   <prefix><base64url(random32)>_<base32(crc32(random))[-6:]>
 *
 * Inlined here to keep the CLI's dependency graph small — the CLI does not
 * need the rest of the core runtime (handlers, adapters, audit pipeline)
 * just to mint a single token against a configured `TokenStore`. The
 * structural format MUST stay byte-compatible with the core implementation;
 * a unit test in `pat-format.test.ts` cross-checks against `verifyPat`.
 */
import { createHash, randomBytes } from "node:crypto"

const RANDOM_BYTES = 32
const CHECKSUM_LENGTH = 6
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

export interface MintedPat {
  readonly token: string
  readonly tokenHash: Buffer
}

export function mintPat(prefix: string): MintedPat {
  const random = randomBytes(RANDOM_BYTES).toString("base64url")
  const checksum = computeChecksum(random)
  const token = `${prefix}${random}_${checksum}`
  const tokenHash = createHash("sha256").update(token).digest()
  return { token, tokenHash }
}

export function buildDisplay(prefix: string, token: string): string {
  const body = token.slice(prefix.length)
  const sep = body.lastIndexOf("_")
  const random = body.slice(0, sep)
  const checksum = body.slice(sep + 1)
  return `${prefix}${random.slice(0, 4)}…${checksum.slice(-4)}`
}

function computeChecksum(random: string): string {
  const crc = crc32(random)
  return base32(crc).slice(-CHECKSUM_LENGTH)
}

const CRC32_TABLE: ReadonlyArray<number> = (() => {
  const table = new Array<number>(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[i] = c >>> 0
  }
  return table
})()

function crc32(input: string): number {
  const bytes = Buffer.from(input, "utf8")
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i] as number
    const idx = (crc ^ byte) & 0xff
    crc = (crc >>> 8) ^ (CRC32_TABLE[idx] as number)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function base32(value: number): string {
  const buf = Buffer.alloc(5)
  buf.writeUInt8((value >>> 24) & 0xff, 0)
  buf.writeUInt8((value >>> 16) & 0xff, 1)
  buf.writeUInt8((value >>> 8) & 0xff, 2)
  buf.writeUInt8(value & 0xff, 3)
  buf.writeUInt8(0, 4)
  let bits = 0
  let acc = 0
  let out = ""
  for (let i = 0; i < buf.length; i++) {
    acc = (acc << 8) | (buf[i] as number)
    bits += 8
    while (bits >= 5) {
      bits -= 5
      const idx = (acc >>> bits) & 0x1f
      out += BASE32_ALPHABET[idx]
    }
  }
  return out.slice(0, 7)
}
