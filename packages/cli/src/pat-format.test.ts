import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"
import { buildDisplay, mintPat } from "./pat-format.js"

const PREFIX = "mcp_pat_"

describe("mintPat (CLI-local)", () => {
  it("produces a token starting with the configured prefix", () => {
    const minted = mintPat(PREFIX)
    expect(minted.token.startsWith(PREFIX)).toBe(true)
  })

  it("uses base64url for the random portion and a 6-char base32 checksum", () => {
    const minted = mintPat(PREFIX)
    const body = minted.token.slice(PREFIX.length)
    const sep = body.lastIndexOf("_")
    const random = body.slice(0, sep)
    const checksum = body.slice(sep + 1)
    expect(random).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(checksum).toMatch(/^[A-Z2-7]{6}$/)
  })

  it("returns SHA-256 of the plaintext as tokenHash", () => {
    const minted = mintPat(PREFIX)
    const expected = createHash("sha256").update(minted.token).digest()
    expect(minted.tokenHash.equals(expected)).toBe(true)
  })

  it("produces unique tokens across mints", () => {
    const a = mintPat(PREFIX)
    const b = mintPat(PREFIX)
    expect(a.token).not.toBe(b.token)
  })
})

describe("buildDisplay", () => {
  it("renders prefix + first 4 random + ellipsis + last 4 checksum", () => {
    const minted = mintPat(PREFIX)
    const display = buildDisplay(PREFIX, minted.token)
    const body = minted.token.slice(PREFIX.length)
    const sep = body.lastIndexOf("_")
    const random = body.slice(0, sep)
    const checksum = body.slice(sep + 1)
    expect(display).toBe(`${PREFIX}${random.slice(0, 4)}…${checksum.slice(-4)}`)
  })
})
