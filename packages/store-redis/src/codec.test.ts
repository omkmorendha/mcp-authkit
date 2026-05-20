import { createHmac, randomBytes } from "node:crypto"
import { describe, expect, it } from "vitest"
import { decode, encode, HMAC_TAG_BYTES } from "./codec.js"

describe("codec", () => {
  const key = randomBytes(32)

  it("round-trips primitive values", () => {
    const blob = encode(key, { a: 1, b: "two", c: null })
    expect(decode(key, blob)).toEqual({ a: 1, b: "two", c: null })
  })

  it("round-trips Buffer fields via MessagePack bin", () => {
    const tokenHash = Buffer.from("abcdef".repeat(11) + "ab", "utf8") // 64 bytes
    const blob = encode(key, { tokenHash })
    const out = decode(key, blob) as { tokenHash: Uint8Array }
    expect(Buffer.from(out.tokenHash)).toEqual(tokenHash)
  })

  it("round-trips Date fields via MessagePack timestamp extension", () => {
    const expiresAt = new Date("2030-01-02T03:04:05.678Z")
    const blob = encode(key, { expiresAt })
    const out = decode(key, blob) as { expiresAt: Date }
    expect(out.expiresAt).toBeInstanceOf(Date)
    expect(out.expiresAt.toISOString()).toBe(expiresAt.toISOString())
  })

  it("rejects a blob with a mutated body (wrong HMAC)", () => {
    const blob = encode(key, { a: 1 })
    // Mutate one byte of the body — the HMAC must no longer match.
    blob[HMAC_TAG_BYTES + 1] = (blob[HMAC_TAG_BYTES + 1] ?? 0) ^ 0xff
    expect(decode(key, blob)).toBeNull()
  })

  it("rejects a blob with a mutated tag (wrong HMAC)", () => {
    const blob = encode(key, { a: 1 })
    blob[0] = (blob[0] ?? 0) ^ 0xff
    expect(decode(key, blob)).toBeNull()
  })

  it("rejects a blob shorter than the HMAC tag width", () => {
    expect(decode(key, Buffer.alloc(0))).toBeNull()
    expect(decode(key, Buffer.alloc(HMAC_TAG_BYTES - 1))).toBeNull()
  })

  it("rejects a blob signed with a different key", () => {
    const other = randomBytes(32)
    const blob = encode(other, { a: 1 })
    expect(decode(key, blob)).toBeNull()
  })

  it("rejects a tag-valid blob with garbage MessagePack body", () => {
    // Construct this only by signing a deliberately invalid body. 0xc1 is
    // reserved as "never used" by MessagePack; the decoder must throw.
    const body = Buffer.from([0xc1])
    const tag = createHmac("sha256", key).update(body).digest()
    const blob = Buffer.concat([tag, body])
    expect(decode(key, blob)).toBeNull()
  })

  it("produces deterministic output for identical input under the same key", () => {
    const a = encode(key, { a: 1, b: "two" })
    const b = encode(key, { a: 1, b: "two" })
    expect(a.equals(b)).toBe(true)
  })
})
