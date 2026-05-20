import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, "..", "..", "..", "..")
const binDist = resolve(here, "..", "..", "dist", "bin", "mcp-authkit.js")

// Subprocess smoke tests against the built bin in the *primary* package.
// Skipped if dist is missing (e.g. when the test runner is invoked before
// `pnpm build`). CI builds first; locally the developer can run
// `pnpm -r build` to populate dist.
//
// These tests are the load-bearing guarantee for #108: installing the
// primary `mcp-authkit` package must expose a working `mcp-authkit` bin
// at `<pkg>/dist/bin/mcp-authkit.js` whose behavior matches the spec.
describe.runIf(existsSync(binDist))("mcp-authkit (primary package) bin", () => {
  it("`gen-secret 8` prints 11 base64url chars and exits 0", () => {
    const result = spawnSync(process.execPath, [binDist, "gen-secret", "8"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
    expect(result.status).toBe(0)
    expect(result.stdout.trimEnd()).toMatch(/^[A-Za-z0-9_-]{11}$/)
  })

  it("rejects --secret with exit 1 (argv guard still active)", () => {
    const result = spawnSync(process.execPath, [binDist, "--secret", "x", "gen-secret"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
    expect(result.status).toBe(1)
    expect(result.stderr).toMatch(/refuses to read secrets/i)
  })

  it("returns exit code 2 when verify-config cannot find the file", () => {
    const result = spawnSync(
      process.execPath,
      [binDist, "--config", resolve(repoRoot, "does-not-exist.config.ts"), "verify-config"],
      { cwd: repoRoot, encoding: "utf8" },
    )
    expect(result.status).toBe(2)
  })

  it("`--help` exits 0 and lists the documented subcommands", () => {
    const result = spawnSync(process.execPath, [binDist, "--help"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
    expect(result.status).toBe(0)
    // Spec docs/spec/v0.2.md#57-cli lists these commands.
    expect(result.stdout).toMatch(/init/)
    expect(result.stdout).toMatch(/mint-pat/)
    expect(result.stdout).toMatch(/verify-config/)
    expect(result.stdout).toMatch(/jwks-fetch/)
    expect(result.stdout).toMatch(/gen-secret/)
  })
})
