import { PassThrough } from "node:stream"
import { describe, expect, it } from "vitest"
import { CliError, ExitCode } from "../exit-codes.js"
import { genSecret } from "./gen-secret.js"

function collect(stream: PassThrough): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    stream.on("data", (c: Buffer) => chunks.push(c))
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")))
    stream.on("error", reject)
  })
}

describe("genSecret", () => {
  it("prints a base64url string of the expected length for the default 32 bytes", async () => {
    const out = new PassThrough()
    genSecret({ stdout: out })
    out.end()
    const text = (await collect(out)).trimEnd()
    // 32 bytes -> base64url length 43 (no padding).
    expect(text).toHaveLength(43)
    expect(text).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it("honours --json", async () => {
    const out = new PassThrough()
    genSecret({ length: 16, json: true, stdout: out })
    out.end()
    const text = (await collect(out)).trimEnd()
    const parsed = JSON.parse(text) as { secret: string; length: number }
    expect(parsed.length).toBe(16)
    expect(parsed.secret).toMatch(/^[A-Za-z0-9_-]+$/)
    // 16 bytes -> base64url length 22.
    expect(parsed.secret).toHaveLength(22)
  })

  it("rejects non-positive length with a user error", () => {
    try {
      genSecret({ length: 0 })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(CliError)
      expect((err as CliError).exitCode).toBe(ExitCode.userError)
    }
  })

  it("rejects an absurd length", () => {
    expect(() => genSecret({ length: 10_000 })).toThrowError(/length must be/)
  })
})
