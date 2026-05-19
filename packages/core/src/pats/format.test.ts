import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"
import { mintPat, PatFormatError, parsePat, verifyPat } from "./format.js"

const timingSafeEqualSpy = vi.hoisted(() => vi.fn<(a: Uint8Array, b: Uint8Array) => boolean>())

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>()
  return {
    ...actual,
    timingSafeEqual: (a: Uint8Array, b: Uint8Array) => {
      timingSafeEqualSpy(a, b)
      return actual.timingSafeEqual(a, b)
    },
  }
})

const PREFIX = "mcp_pat_"

describe("mintPat", () => {
  it("produces a token matching <prefix><base64url(32)>_<base32 checksum [-6:]>", () => {
    const minted = mintPat(PREFIX)
    expect(minted.token.startsWith(PREFIX)).toBe(true)
    const body = minted.token.slice(PREFIX.length)
    const sep = body.lastIndexOf("_")
    const random = body.slice(0, sep)
    const checksum = body.slice(sep + 1)
    expect(random).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(checksum).toMatch(/^[A-Z2-7]{6}$/)
    expect(minted.parsed).toEqual({ prefix: PREFIX, random, checksum })
  })

  it("returns SHA-256 of the plaintext token as a Buffer", () => {
    const minted = mintPat(PREFIX)
    const expected = createHash("sha256").update(minted.token).digest()
    expect(Buffer.isBuffer(minted.tokenHash)).toBe(true)
    expect(minted.tokenHash.equals(expected)).toBe(true)
  })

  it("produces distinct randoms and hashes on successive mints", () => {
    const a = mintPat(PREFIX)
    const b = mintPat(PREFIX)
    expect(a.parsed.random).not.toBe(b.parsed.random)
    expect(a.tokenHash.equals(b.tokenHash)).toBe(false)
  })

  it("respects a custom prefix", () => {
    const minted = mintPat("custom_")
    expect(minted.token.startsWith("custom_")).toBe(true)
    expect(verifyPat(minted.token, "custom_")).toBe(true)
  })
})

describe("parsePat", () => {
  it("returns prefix, random, and checksum on a well-formed token", () => {
    const minted = mintPat(PREFIX)
    const parsed = parsePat(minted.token, PREFIX)
    expect(parsed).toEqual(minted.parsed)
  })

  it("rejects wrong prefix with code=missing_prefix", () => {
    const minted = mintPat(PREFIX)
    expect(() => parsePat(minted.token, "wrong_")).toThrow(PatFormatError)
    try {
      parsePat(minted.token, "wrong_")
    } catch (e) {
      expect((e as PatFormatError).code).toBe("missing_prefix")
    }
  })

  it("rejects missing checksum separator with code=missing_checksum", () => {
    expect(() => parsePat(`${PREFIX}abcdef`, PREFIX)).toThrow(
      expect.objectContaining({ code: "missing_checksum" }),
    )
  })

  it("rejects random portion of wrong length with code=malformed_random", () => {
    const minted = mintPat(PREFIX)
    const truncated = `${PREFIX}${minted.parsed.random.slice(0, 20)}_${minted.parsed.checksum}`
    expect(() => parsePat(truncated, PREFIX)).toThrow(
      expect.objectContaining({ code: "malformed_random" }),
    )
  })

  it("rejects random portion with invalid base64url chars", () => {
    // Force a non-base64url char ('!') at the start of the random body.
    const random = `!${"A".repeat(42)}`
    expect(() => parsePat(`${PREFIX}${random}_ABCDEF`, PREFIX)).toThrow(
      expect.objectContaining({ code: "malformed_random" }),
    )
  })

  it("rejects checksum of wrong length with code=malformed_checksum", () => {
    const minted = mintPat(PREFIX)
    const bad = `${PREFIX}${minted.parsed.random}_ABCDE` // 5 chars
    expect(() => parsePat(bad, PREFIX)).toThrow(
      expect.objectContaining({ code: "malformed_checksum" }),
    )
  })

  it("rejects checksum with non-base32 chars", () => {
    const minted = mintPat(PREFIX)
    const bad = `${PREFIX}${minted.parsed.random}_abc123` // lowercase + '1'
    expect(() => parsePat(bad, PREFIX)).toThrow(
      expect.objectContaining({ code: "malformed_checksum" }),
    )
  })
})

describe("verifyPat", () => {
  it("returns true on a freshly minted token (round-trip)", () => {
    const minted = mintPat(PREFIX)
    expect(verifyPat(minted.token, PREFIX)).toBe(true)
  })

  it("returns false for a tampered checksum", () => {
    const minted = mintPat(PREFIX)
    // Flip first checksum char to a different base32 char.
    const first = minted.parsed.checksum[0] as string
    const flipped = (first === "A" ? "B" : "A") + minted.parsed.checksum.slice(1)
    const tampered = `${PREFIX}${minted.parsed.random}_${flipped}`
    expect(verifyPat(tampered, PREFIX)).toBe(false)
  })

  it("returns false for a tampered random portion (recomputed checksum differs)", () => {
    const minted = mintPat(PREFIX)
    // Replace first random char with a different base64url char.
    const first = minted.parsed.random[0] as string
    const flipped = (first === "A" ? "B" : "A") + minted.parsed.random.slice(1)
    const tampered = `${PREFIX}${flipped}_${minted.parsed.checksum}`
    expect(verifyPat(tampered, PREFIX)).toBe(false)
  })

  it("returns false (does not throw) on malformed input", () => {
    expect(verifyPat("garbage", PREFIX)).toBe(false)
    expect(verifyPat(`${PREFIX}short_AAAAAA`, PREFIX)).toBe(false)
    expect(verifyPat(`${PREFIX}no-separator-here`, PREFIX)).toBe(false)
  })

  it("returns false for wrong prefix", () => {
    const minted = mintPat(PREFIX)
    expect(verifyPat(minted.token, "wrong_")).toBe(false)
  })
})

describe("security: constant-time comparison (CLAUDE.md §2 / spec §14)", () => {
  it("uses crypto.timingSafeEqual for checksum equality with equal-length buffers", () => {
    timingSafeEqualSpy.mockClear()
    const minted = mintPat(PREFIX)
    expect(verifyPat(minted.token, PREFIX)).toBe(true)
    expect(timingSafeEqualSpy).toHaveBeenCalledTimes(1)
    const call = timingSafeEqualSpy.mock.calls[0] as readonly [Uint8Array, Uint8Array]
    expect(call[0].byteLength).toBe(call[1].byteLength)
  })
})
