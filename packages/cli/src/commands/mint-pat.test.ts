import { dirname, resolve } from "node:path"
import { PassThrough } from "node:stream"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { CliError, ExitCode } from "../exit-codes.js"
import { createLogger } from "../logger.js"
import { mintPatCommand } from "./mint-pat.js"

const here = dirname(fileURLToPath(import.meta.url))
const fixtures = resolve(here, "..", "test", "fixtures")

function collect(stream: PassThrough): Promise<string> {
  return new Promise((res, rej) => {
    const chunks: Buffer[] = []
    stream.on("data", (c: Buffer) => chunks.push(c))
    stream.on("end", () => res(Buffer.concat(chunks).toString("utf8")))
    stream.on("error", rej)
  })
}

const silent = createLogger("silent")

describe("mintPatCommand", () => {
  it("mints a PAT and prints the token in plain mode", async () => {
    const out = new PassThrough()
    await mintPatCommand({
      configPath: resolve(fixtures, "with-memory-store.config.ts"),
      user: "alice",
      name: "demo",
      scopes: ["echo:say"],
      logger: silent,
      stdout: out,
    })
    out.end()
    const text = (await collect(out)).trimEnd()
    expect(text.startsWith("mcp_pat_")).toBe(true)
    // Format: prefix + 43 base64url + '_' + 6 base32.
    expect(text).toMatch(/^mcp_pat_[A-Za-z0-9_-]{43}_[A-Z2-7]{6}$/)
  })

  it("prints token/id/expiresAt as JSON when --json is set", async () => {
    const out = new PassThrough()
    await mintPatCommand({
      configPath: resolve(fixtures, "with-memory-store.config.ts"),
      user: "alice",
      name: "demo",
      scopes: ["echo:say"],
      expiresInDays: 7,
      json: true,
      logger: silent,
      stdout: out,
    })
    out.end()
    const text = (await collect(out)).trimEnd()
    const parsed = JSON.parse(text) as { token: string; id: string; expiresAt: string }
    expect(parsed.token).toMatch(/^mcp_pat_/)
    expect(parsed.id).toBeTypeOf("string")
    expect(parsed.id.length).toBeGreaterThan(0)
    expect(() => new Date(parsed.expiresAt).toISOString()).not.toThrow()
    const expiresAt = new Date(parsed.expiresAt).getTime()
    const expected = Date.now() + 7 * 24 * 60 * 60 * 1000
    // Within a minute of the expected expiry.
    expect(Math.abs(expiresAt - expected)).toBeLessThan(60_000)
  })

  it("rejects empty --user", async () => {
    try {
      await mintPatCommand({
        configPath: resolve(fixtures, "with-memory-store.config.ts"),
        user: "  ",
        name: "demo",
        scopes: ["echo:say"],
        logger: silent,
      })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(CliError)
      expect((err as CliError).exitCode).toBe(ExitCode.userError)
    }
  })

  it("rejects empty scopes", async () => {
    try {
      await mintPatCommand({
        configPath: resolve(fixtures, "with-memory-store.config.ts"),
        user: "alice",
        name: "demo",
        scopes: [],
        logger: silent,
      })
      throw new Error("expected throw")
    } catch (err) {
      expect((err as CliError).exitCode).toBe(ExitCode.userError)
    }
  })

  it("rejects when auth.pat.enabled is false", async () => {
    try {
      await mintPatCommand({
        configPath: resolve(fixtures, "pat-disabled.config.ts"),
        user: "alice",
        name: "demo",
        scopes: ["echo:say"],
        logger: silent,
      })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(CliError)
      expect((err as CliError).exitCode).toBe(ExitCode.configError)
      expect((err as CliError).message).toContain("pat.enabled")
    }
  })

  it("rejects expires-in-days out of range", async () => {
    try {
      await mintPatCommand({
        configPath: resolve(fixtures, "with-memory-store.config.ts"),
        user: "alice",
        name: "demo",
        scopes: ["echo:say"],
        expiresInDays: 0,
        logger: silent,
      })
      throw new Error("expected throw")
    } catch (err) {
      expect((err as CliError).exitCode).toBe(ExitCode.userError)
    }
  })

  it("surfaces a config error when the config file is missing", async () => {
    try {
      await mintPatCommand({
        configPath: resolve(fixtures, "missing.config.ts"),
        user: "alice",
        name: "demo",
        scopes: ["echo:say"],
        logger: silent,
      })
      throw new Error("expected throw")
    } catch (err) {
      expect((err as CliError).exitCode).toBe(ExitCode.configError)
    }
  })
})
