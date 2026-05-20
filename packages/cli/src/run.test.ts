import { spawnSync } from "node:child_process"
import { existsSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { PassThrough } from "node:stream"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { ExitCode } from "./exit-codes.js"
import { run } from "./run.js"

const here = dirname(fileURLToPath(import.meta.url))
const fixtures = resolve(here, "test", "fixtures")
const repoRoot = resolve(here, "..", "..", "..")
const binDist = resolve(here, "..", "dist", "bin", "mcp-authkit.js")

function collect(stream: PassThrough): Promise<string> {
  return new Promise((res, rej) => {
    const chunks: Buffer[] = []
    stream.on("data", (c: Buffer) => chunks.push(c))
    stream.on("end", () => res(Buffer.concat(chunks).toString("utf8")))
    stream.on("error", rej)
  })
}

describe("run() — in-process dispatch", () => {
  it("returns 0 and prints a base64url secret for `gen-secret`", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: ["gen-secret", "16"],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.success)
    const text = (await collect(stdout)).trimEnd()
    expect(text).toMatch(/^[A-Za-z0-9_-]{22}$/)
  })

  it("returns 1 (user error) when a secret-shaped flag is present in argv", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: ["--secret", "shh", "gen-secret"],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.userError)
    const err = await collect(stderr)
    expect(err).toMatch(/refuses to read secrets/i)
    // No secret was generated even though gen-secret was named.
    const out = await collect(stdout)
    expect(out).toBe("")
  })

  it("returns 2 (config error) when verify-config points at a missing file", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: ["--config", resolve(fixtures, "does-not-exist.config.ts"), "verify-config"],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.configError)
  })

  it("returns 0 for verify-config against a valid fixture", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: ["--config", resolve(fixtures, "valid.config.ts"), "verify-config"],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.success)
    const out = await collect(stdout)
    expect(out).toContain("Config OK")
  })

  it("mints a PAT end-to-end against the in-memory store fixture", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: [
        "--config",
        resolve(fixtures, "with-memory-store.config.ts"),
        "--json",
        "mint-pat",
        "--user",
        "alice",
        "--name",
        "ci",
        "--scopes",
        "echo:say",
      ],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.success)
    const text = (await collect(stdout)).trimEnd()
    const parsed = JSON.parse(text) as { token: string; id: string; expiresAt: string }
    expect(parsed.token).toMatch(/^mcp_pat_/)
    expect(parsed.id.length).toBeGreaterThan(0)
  })

  it("init scaffolds into a tmpdir and refuses without --force on re-run", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mcp-authkit-cli-run-init-"))
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({ argv: ["init", tmp], stdout, stderr, cwd: tmp })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.success)
    expect(existsSync(join(tmp, "mcp-authkit.config.ts"))).toBe(true)

    // Second run without --force fails (the dir now contains scaffold files).
    const stdout2 = new PassThrough()
    const stderr2 = new PassThrough()
    const code2 = await run({ argv: ["init", tmp], stdout: stdout2, stderr: stderr2, cwd: tmp })
    stdout2.end()
    stderr2.end()
    expect(code2).toBe(ExitCode.userError)
    expect(await collect(stderr2)).toMatch(/non-empty|overwrite/)
  })

  it("returns 1 (user error) on a bad --log-level value", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: ["--log-level", "bogus", "gen-secret"],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.userError)
  })

  it("returns 1 (user error) when --expires-in-days is non-positive", async () => {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    const code = await run({
      argv: [
        "--config",
        resolve(fixtures, "with-memory-store.config.ts"),
        "mint-pat",
        "--user",
        "alice",
        "--name",
        "x",
        "--scopes",
        "echo:say",
        "--expires-in-days",
        "0",
      ],
      stdout,
      stderr,
    })
    stdout.end()
    stderr.end()
    expect(code).toBe(ExitCode.userError)
  })
})

// Subprocess smoke tests against the built bin. Skipped if dist is missing
// (e.g. when the test runner is invoked before `pnpm build`). CI builds
// first; locally the developer can run `pnpm --filter mcp-authkit-cli build`.
describe.runIf(existsSync(binDist))("bin subprocess", () => {
  it("`gen-secret 8` prints 11 base64url chars and exits 0", () => {
    const result = spawnSync(process.execPath, [binDist, "gen-secret", "8"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
    expect(result.status).toBe(0)
    expect(result.stdout.trimEnd()).toMatch(/^[A-Za-z0-9_-]{11}$/)
  })

  it("rejects --secret with exit 1 from the bin", () => {
    const result = spawnSync(process.execPath, [binDist, "--secret", "x", "gen-secret"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
    expect(result.status).toBe(1)
    expect(result.stderr).toMatch(/refuses to read secrets/i)
  })

  it("returns exit code 2 from the bin when verify-config can't find the file", () => {
    const result = spawnSync(
      process.execPath,
      [binDist, "--config", resolve(fixtures, "does-not-exist.config.ts"), "verify-config"],
      { cwd: repoRoot, encoding: "utf8" },
    )
    expect(result.status).toBe(2)
  })
})
