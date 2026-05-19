import * as nodeCrypto from "node:crypto"
import { createHash, randomBytes } from "node:crypto"

/**
 * PAT token format (spec §8.1):
 *   <prefix><base64url(random32)>_<base32(crc32(random))[-6:]>
 *
 * The random portion is 32 bytes from `crypto.randomBytes`, base64url-encoded
 * without padding. The checksum is the CRC-32 of the (encoded) random portion,
 * base32-encoded (RFC 4648, uppercase A-Z and 2-7), keeping the last 6
 * characters.
 *
 * This module is pure: it has no I/O and never persists the token. Callers
 * receive the plaintext token once and a SHA-256 hash for storage
 * (spec §8.2, §14).
 */

/** Length of the base64url-encoded 32-byte random portion (no padding). */
const RANDOM_LENGTH = 43
/** Number of base32 chars retained from the CRC-32 checksum. */
const CHECKSUM_LENGTH = 6
/** Number of random bytes. */
const RANDOM_BYTES = 32

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
const BASE32_CHAR = /^[A-Z2-7]+$/
const BASE64URL_CHAR = /^[A-Za-z0-9_-]+$/

export type PatFormatErrorCode =
  | "missing_prefix"
  | "missing_checksum"
  | "malformed_random"
  | "malformed_checksum"

export class PatFormatError extends Error {
  readonly code: PatFormatErrorCode
  constructor(code: PatFormatErrorCode, message: string) {
    super(message)
    this.name = "PatFormatError"
    this.code = code
  }
}

export interface ParsedPat {
  readonly prefix: string
  /** base64url, no padding. */
  readonly random: string
  /** 6 chars, RFC 4648 base32 alphabet. */
  readonly checksum: string
}

export interface MintedPat {
  /** Plaintext token. Show to the user exactly once; never persist. */
  readonly token: string
  /** SHA-256 of the plaintext token, for `TokenStore.createPat`. */
  readonly tokenHash: Buffer
  readonly parsed: ParsedPat
}

/** Mint a fresh PAT. */
export function mintPat(prefix: string): MintedPat {
  const random = randomBytes(RANDOM_BYTES).toString("base64url")
  const checksum = computeChecksum(random)
  const token = `${prefix}${random}_${checksum}`
  const tokenHash = createHash("sha256").update(token).digest()
  return {
    token,
    tokenHash,
    parsed: { prefix, random, checksum },
  }
}

/**
 * Parse a presented token. Validates structural shape only; does NOT verify
 * the checksum (use {@link verifyPat} for that).
 */
export function parsePat(token: string, prefix: string): ParsedPat {
  if (!token.startsWith(prefix)) {
    throw new PatFormatError("missing_prefix", "token does not start with configured prefix")
  }
  const body = token.slice(prefix.length)
  const sep = body.lastIndexOf("_")
  if (sep === -1) {
    throw new PatFormatError("missing_checksum", "token is missing checksum separator")
  }
  const random = body.slice(0, sep)
  const checksum = body.slice(sep + 1)

  if (random.length !== RANDOM_LENGTH || !BASE64URL_CHAR.test(random)) {
    throw new PatFormatError("malformed_random", "random portion is not 43 base64url chars")
  }
  if (checksum.length !== CHECKSUM_LENGTH || !BASE32_CHAR.test(checksum)) {
    throw new PatFormatError("malformed_checksum", "checksum is not 6 base32 chars")
  }

  return { prefix, random, checksum }
}

/**
 * Verify a presented token's checksum against the recomputed checksum using
 * `crypto.timingSafeEqual` (CLAUDE.md §2). Returns false (never throws) on
 * any structural problem so the caller cannot distinguish "malformed" from
 * "bad checksum" by exception class on the hot path.
 */
export function verifyPat(token: string, prefix: string): boolean {
  let parsed: ParsedPat
  try {
    parsed = parsePat(token, prefix)
  } catch {
    return false
  }
  const expected = Buffer.from(computeChecksum(parsed.random), "utf8")
  const actual = Buffer.from(parsed.checksum, "utf8")
  if (expected.length !== actual.length) {
    return false
  }
  return nodeCrypto.timingSafeEqual(expected, actual)
}

function computeChecksum(random: string): string {
  const crc = crc32(random)
  return base32(crc).slice(-CHECKSUM_LENGTH)
}

// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320). Standard table-driven impl.
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

/**
 * Base32 (RFC 4648, A-Z2-7, no padding) encoding of a 32-bit unsigned
 * integer. Always yields 7 chars (40 bits / 5).
 */
function base32(value: number): string {
  // 32 bits zero-padded to 40 (multiple of 5).
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
  // 40 bits / 5 = 8 chars. The last char encodes the trailing zero byte; drop it.
  return out.slice(0, 7)
}
