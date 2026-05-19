import { dirname, resolve } from "node:path"
import { PassThrough } from "node:stream"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { CliError, ExitCode } from "../exit-codes.js"
import { createLogger } from "../logger.js"
import { verifyConfig } from "./verify-config.js"

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

describe("verifyConfig", () => {
  it("prints an OK summary for a valid config", async () => {
    const out = new PassThrough()
    await verifyConfig({
      configPath: resolve(fixtures, "valid.config.ts"),
      logger: createLogger("silent"),
      stdout: out,
    })
    out.end()
    const text = await collect(out)
    expect(text).toContain("Config OK")
    expect(text).toContain("https://mcp.example.test/")
    expect(text).toContain("https://as.example.test/")
    // PAT prefix is secret-shaped per redactConfigForLog.
    expect(text).not.toContain("mcp_pat_")
  })

  it("emits structured JSON with --json", async () => {
    const out = new PassThrough()
    await verifyConfig({
      configPath: resolve(fixtures, "valid.config.ts"),
      json: true,
      logger: createLogger("silent"),
      stdout: out,
    })
    out.end()
    const text = (await collect(out)).trimEnd()
    const parsed = JSON.parse(text) as { ok: boolean; configPath: string; summary: unknown }
    expect(parsed.ok).toBe(true)
    expect(parsed.summary).toBeDefined()
  })

  it("returns a config-error CliError when the file is missing", async () => {
    try {
      await verifyConfig({
        configPath: resolve(fixtures, "does-not-exist.config.ts"),
        logger: createLogger("silent"),
      })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(CliError)
      expect((err as CliError).exitCode).toBe(ExitCode.configError)
    }
  })
})
