import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { describe, expect, it } from "vitest"
import { defineConfig } from "./define.js"
import { _setTsImportForTests, ConfigLoadError, loadConfig } from "./load.js"
import type { AuthKitConfig } from "./types.js"

const here = dirname(fileURLToPath(import.meta.url))
const fixtures = resolve(here, "test/fixtures")

describe("loadConfig", () => {
  it("loads a valid TS config file", async () => {
    const config = await loadConfig(resolve(fixtures, "valid.config.ts"), { cwd: here })

    expect(config.resourceIndicator).toBe("https://mcp.example.test/")
    expect(config.auth.authorizationServer?.issuer).toBe("https://as.example.test/")
    expect(typeof config.auth.tokenStore.createPat).toBe("function")
    expect(config.auth.pat.enabled).toBe(true)
    expect(typeof config.resolveUserScopes).toBe("function")
  })

  it("maps schema-validation errors to the file path with field details", async () => {
    const filePath = resolve(fixtures, "invalid.config.ts")
    await expect(loadConfig(filePath, { cwd: here })).rejects.toMatchObject({
      name: "ConfigLoadError",
      filePath,
    })

    try {
      await loadConfig(filePath, { cwd: here })
      throw new Error("loadConfig did not reject")
    } catch (err) {
      const message = (err as Error).message
      expect(message).toContain(filePath)
      expect(message).toContain("schema validation failed")
      // Some specific field paths should appear so operators can locate the
      // offending entry without rerunning under a debugger.
      expect(message).toMatch(/auth\.pat/)
      expect(message).toMatch(/scopes/)
      expect(message).toMatch(/resolveUserScopes/)
    }
  })

  it("rejects a path outside the working directory by default", async () => {
    // /tmp is unrelated to the package CWD; the resolved absolute path
    // therefore lives outside it.
    const outside = "/tmp/mcp-authkit-outside-cwd.config.ts"
    await expect(loadConfig(outside, { cwd: here })).rejects.toMatchObject({
      name: "ConfigLoadError",
    })

    try {
      await loadConfig(outside, { cwd: here })
      throw new Error("loadConfig did not reject outside-cwd path")
    } catch (err) {
      expect((err as Error).message).toContain("outside the working directory")
    }
  })

  it("allows an outside-CWD path when allowOutsideCwd is true", async () => {
    // Use the valid fixture but pretend the CWD is a sibling dir so the
    // path resolves outside it. Without the override we'd reject; with it
    // we'd attempt the import — verify by passing a guaranteed-missing
    // path and asserting the *not-found* error fires after the CWD check.
    const valid = resolve(fixtures, "valid.config.ts")
    const fakeCwd = "/tmp"
    const config = await loadConfig(valid, { cwd: fakeCwd, allowOutsideCwd: true })
    expect(config.resourceIndicator).toBe("https://mcp.example.test/")
  })

  it("enforces the timeout budget (default 10s; simulated via an 11s import)", async () => {
    // Swap in a stub that mimics a `setTimeout(...11_000)` at the top of a
    // config file — the spec's quoted scenario. The 50 ms test budget
    // tells us the timeout *mechanism* fires; the default 10 s value is
    // covered by the unit assertion below.
    const valid = resolve(fixtures, "valid.config.ts")
    const restore = _setTsImportForTests(
      () => new Promise(() => {}), // a promise that never resolves
    )
    try {
      await expect(loadConfig(valid, { cwd: here, timeoutMs: 50 })).rejects.toMatchObject({
        name: "ConfigLoadError",
      })
      try {
        await loadConfig(valid, { cwd: here, timeoutMs: 50 })
        throw new Error("loadConfig did not time out")
      } catch (err) {
        expect((err as Error).message).toContain("timed out")
        expect((err as Error).message).toContain("50ms")
      }
    } finally {
      restore()
    }
  })

  it("uses a 10 second default timeout (spec §12 bounded load)", async () => {
    // Spy on setTimeout to verify the loader arms a 10_000 ms timer when no
    // explicit timeoutMs is supplied. Resolves the import immediately so
    // the test completes in <1s.
    const valid = resolve(fixtures, "valid.config.ts")
    const restore = _setTsImportForTests(async () => {
      return await import(valid)
    })
    const armedDelays: number[] = []
    const originalSetTimeout = globalThis.setTimeout
    globalThis.setTimeout = ((handler: () => void, ms?: number, ...args: unknown[]) => {
      if (typeof ms === "number") armedDelays.push(ms)
      // biome-ignore lint/suspicious/noExplicitAny: passthrough wrapper
      return (originalSetTimeout as any)(handler, ms, ...args)
      // biome-ignore lint/suspicious/noExplicitAny: passthrough wrapper
    }) as any
    try {
      await loadConfig(valid, { cwd: here })
    } finally {
      globalThis.setTimeout = originalSetTimeout
      restore()
    }
    expect(armedDelays).toContain(10_000)
  })

  it("rejects when the file does not exist", async () => {
    const missing = resolve(fixtures, "does-not-exist.config.ts")
    await expect(loadConfig(missing, { cwd: here })).rejects.toThrow(ConfigLoadError)
    try {
      await loadConfig(missing, { cwd: here })
      throw new Error("did not throw")
    } catch (err) {
      expect((err as Error).message).toContain("not found")
    }
  })

  it("rejects when the file has no default export", async () => {
    const noDefault = resolve(fixtures, "no-default.config.ts")
    const fs = await import("node:fs/promises")
    await fs.writeFile(noDefault, "export const x = 1\n", "utf8")
    try {
      await expect(loadConfig(noDefault, { cwd: here })).rejects.toMatchObject({
        name: "ConfigLoadError",
      })
      try {
        await loadConfig(noDefault, { cwd: here })
      } catch (err) {
        expect((err as Error).message).toContain("no default export")
      }
    } finally {
      await fs.unlink(noDefault).catch(() => {})
    }
  })
})

describe("defineConfig", () => {
  it("is the identity function (no runtime work)", () => {
    const config: AuthKitConfig = {
      resourceIndicator: "https://mcp.example.test/",
      auth: {
        tokenStore: memoryTokenStore(),
        pat: { enabled: false },
      },
      scopes: { vocabulary: {} },
      resolveUserScopes: async () => [],
    }
    expect(defineConfig(config)).toBe(config)
  })
})
