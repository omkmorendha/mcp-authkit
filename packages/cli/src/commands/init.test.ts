import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { PassThrough } from "node:stream"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { CliError, ExitCode } from "../exit-codes.js"
import { createLogger } from "../logger.js"
import { init } from "./init.js"

let workdir: string

beforeEach(() => {
  workdir = mkdtempSync(join(tmpdir(), "mcp-authkit-cli-init-"))
})

afterEach(() => {
  // mkdtempSync creates a unique dir; leaving it for the OS to reap is fine.
})

const silentLogger = createLogger("silent")

describe("init", () => {
  it("creates the four scaffolded files in an empty directory", () => {
    const out = new PassThrough()
    init({ path: workdir, logger: silentLogger, stdout: out, cwd: workdir })
    expect(existsSync(join(workdir, "mcp-authkit.config.ts"))).toBe(true)
    expect(existsSync(join(workdir, ".env.example"))).toBe(true)
    expect(existsSync(join(workdir, "server.ts"))).toBe(true)
    expect(existsSync(join(workdir, "README.md"))).toBe(true)
    const config = readFileSync(join(workdir, "mcp-authkit.config.ts"), "utf8")
    expect(config).toContain("defineConfig")
    expect(config).toContain("memoryTokenStore")
  })

  it("refuses to write into a non-empty directory", () => {
    writeFileSync(join(workdir, "existing-file"), "hello", "utf8")
    try {
      init({ path: workdir, logger: silentLogger, cwd: workdir })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(CliError)
      expect((err as CliError).exitCode).toBe(ExitCode.userError)
      expect((err as CliError).message).toContain("non-empty")
    }
    // No scaffold files written.
    expect(existsSync(join(workdir, "mcp-authkit.config.ts"))).toBe(false)
  })

  it("overwrites with --force", () => {
    writeFileSync(join(workdir, "existing-file"), "hello", "utf8")
    init({
      path: workdir,
      force: true,
      logger: silentLogger,
      stdout: new PassThrough(),
      cwd: workdir,
    })
    expect(existsSync(join(workdir, "mcp-authkit.config.ts"))).toBe(true)
  })

  it("treats dotfile-only contents as non-empty unless --force is passed", () => {
    writeFileSync(join(workdir, ".hiddenfile"), "x", "utf8")
    expect(() =>
      init({ path: workdir, logger: silentLogger, stdout: new PassThrough(), cwd: workdir }),
    ).toThrow(/non-empty directory/)
    expect(() =>
      init({
        path: workdir,
        force: true,
        logger: silentLogger,
        stdout: new PassThrough(),
        cwd: workdir,
      }),
    ).not.toThrow()
  })
})
