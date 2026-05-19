import { describe, expect, it } from "vitest"
import { ArgvSecretLeakError, assertNoSecretFlags } from "./argv-guard.js"

describe("assertNoSecretFlags", () => {
  it("accepts the documented public flags", () => {
    const argv = [
      "mint-pat",
      "--user",
      "alice",
      "--name",
      "demo",
      "--scopes",
      "echo:say,files:read",
      "--expires-in-days",
      "30",
      "--config",
      "./mcp-authkit.config.ts",
      "--log-level",
      "info",
      "--json",
      "--force",
      "--issuer",
      "https://auth.example.com",
    ]
    expect(() => assertNoSecretFlags(argv)).not.toThrow()
  })

  it("rejects --secret", () => {
    expect(() => assertNoSecretFlags(["--secret", "shhh"])).toThrowError(ArgvSecretLeakError)
  })

  it("rejects --token", () => {
    expect(() => assertNoSecretFlags(["--token=abc"])).toThrowError(/secret/i)
  })

  it("rejects --password", () => {
    expect(() => assertNoSecretFlags(["--password", "x"])).toThrowError(ArgvSecretLeakError)
  })

  it("rejects --pat and --pat-id", () => {
    expect(() => assertNoSecretFlags(["--pat", "x"])).toThrowError(ArgvSecretLeakError)
    expect(() => assertNoSecretFlags(["--pat-id", "x"])).toThrowError(ArgvSecretLeakError)
  })

  it("rejects --api-key, --client-secret, --apikey, --passphrase, --credential", () => {
    expect(() => assertNoSecretFlags(["--api-key", "x"])).toThrowError(ArgvSecretLeakError)
    expect(() => assertNoSecretFlags(["--client-secret=x"])).toThrowError(ArgvSecretLeakError)
    expect(() => assertNoSecretFlags(["--apikey", "x"])).toThrowError(ArgvSecretLeakError)
    expect(() => assertNoSecretFlags(["--passphrase", "x"])).toThrowError(ArgvSecretLeakError)
    expect(() => assertNoSecretFlags(["--credential", "x"])).toThrowError(ArgvSecretLeakError)
  })

  it("ignores positional args that look secret-named (subcommands are not flags)", () => {
    // mint-pat is a subcommand, not a flag. Token positional is not a flag.
    expect(() => assertNoSecretFlags(["mint-pat", "tokenvalue"])).not.toThrow()
  })

  it("carries the offending flag name on the error", () => {
    try {
      assertNoSecretFlags(["--secret-value", "x"])
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(ArgvSecretLeakError)
      expect((err as ArgvSecretLeakError).flag).toBe("--secret-value")
    }
  })
})
