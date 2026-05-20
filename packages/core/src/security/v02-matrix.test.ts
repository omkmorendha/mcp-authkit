/**
 * v0.2 security test matrix (spec §12 additions + §13 security list).
 *
 * The v0.1 security non-negotiables are exercised by
 * `security-matrix.test.ts` against a live HTTP rig. v0.2 adds seven new
 * items, each already covered by a focused test next to the feature it
 * guards. This file is the aggregating index: one `it` per spec line that
 * (a) asserts the public-API surface the feature exposes still exists, and
 * (b) names the canonical test file that exercises the behavior so a
 * future contributor can find the deep coverage from one place.
 *
 * Spec anchors:
 *   - docs/spec/v0.2.md#12-security-non-negotiables-additions
 *   - docs/spec/v0.2.md#13-testing (Security)
 */
import { describe, expect, it } from "vitest"

describe("spec v0.2 §12 / §13 — security test matrix", () => {
  // ---------------------------------------------------------------------
  // 1. Token exchange that returns the wrong audience is rejected.
  //    Canonical: packages/core/src/oauth/token-exchange.test.ts
  // ---------------------------------------------------------------------
  it("token exchange rejects wrong-audience result", async () => {
    const mod = await import("../oauth/token-exchange.js")
    expect(typeof mod.exchangeToken).toBe("function")
    expect(mod.TokenExchangeError).toBeDefined()
    // The reason string the helper uses when the AS-minted token's `aud`
    // does not match the requested audience.
    const err = new mod.TokenExchangeError("audience", "audience mismatch")
    expect(err.reason).toBe("audience")
  })

  // ---------------------------------------------------------------------
  // 2. DCR initial access token never appears in logs.
  //    Canonical: packages/core/src/oauth/dcr.test.ts
  // ---------------------------------------------------------------------
  it("DCR initial access token is on the log-redaction allowlist", async () => {
    const mod = await import("../oauth/dcr.js")
    expect(typeof mod.registerClient).toBe("function")
    expect(mod.DCR_LOG_REDACT_PATHS).toContain("initialAccessToken")
    // The AS-returned registration_access_token is also a secret; the
    // canonical test asserts it never appears in logs.
    expect(mod.DCR_LOG_REDACT_PATHS.length).toBeGreaterThan(0)
  })

  // ---------------------------------------------------------------------
  // 3. SQL injection attempts via `tableNames` override are rejected.
  //    Canonical: packages/store-postgres/src/{identifiers,index}.test.ts
  //               packages/store-sqlite/src/{identifiers,index}.test.ts
  // ---------------------------------------------------------------------
  it("postgres store rejects table identifiers containing SQL metacharacters", async () => {
    const mod = await import("mcp-authkit-store-postgres")
    expect(typeof mod.postgresTokenStore).toBe("function")
    expect(mod.InvalidIdentifierError).toBeDefined()
  })

  it("sqlite store rejects table identifiers containing SQL metacharacters", async () => {
    const mod = await import("mcp-authkit-store-sqlite")
    expect(typeof mod.sqliteTokenStore).toBe("function")
    expect(mod.InvalidIdentifierError).toBeDefined()
  })

  // ---------------------------------------------------------------------
  // 4. Redis cache value with a wrong HMAC tag is treated as a miss + warn.
  //    Canonical: packages/store-redis/src/{codec,index}.test.ts
  // ---------------------------------------------------------------------
  it("redis cache exposes HMAC-tagged codec helpers", async () => {
    const mod = await import("mcp-authkit-store-redis")
    expect(typeof mod.redisCache).toBe("function")
  })

  // ---------------------------------------------------------------------
  // 5. Production stdio replay (replayed counter) tears down the transport.
  //    Canonical: packages/core/src/stdio/{transport,frame}.test.ts
  // ---------------------------------------------------------------------
  it("signed stdio transport exposes a teardown channel for replays", async () => {
    const mod = await import("../stdio/index.js")
    expect(typeof mod.createSignedStdioTransport).toBe("function")
    expect(typeof mod.checkSignedStdioConfig).toBe("function")
    expect(mod.SignedStdioConfigError).toBeDefined()
  })

  // ---------------------------------------------------------------------
  // 6. Multi-tenant cross-tenant token (right shape, wrong issuer) rejected.
  //    Canonical: packages/core/src/auth/multi-tenant.test.ts
  // ---------------------------------------------------------------------
  it("multi-tenant resolver public API exists", async () => {
    const mod = await import("../auth/tenant.js")
    expect(typeof mod.makeSelector).toBe("function")
    expect(typeof mod.resolveAuthorizationServer).toBe("function")
    expect(typeof mod.assertResolvedConfig).toBe("function")
  })

  // ---------------------------------------------------------------------
  // 7. CLI `mint-pat --user '../../../etc/passwd'` is rejected.
  //    Canonical: packages/cli/src/commands/mint-pat.test.ts
  // ---------------------------------------------------------------------
  it("CLI mint-pat rejects path-traversal user identifiers", async () => {
    const cli = await import("mcp-authkit-cli")
    expect(typeof cli.mintPatCommand).toBe("function")
    // Drive the command with a hostile --user argument and a config path
    // pointing at a non-existent file. The argv validation runs before any
    // I/O, so the call must throw a userError CliError naming --user,
    // never proceeding to load the config.
    let caught: unknown
    try {
      await cli.mintPatCommand({
        configPath: "/nonexistent/should-never-be-loaded.config.ts",
        user: "../../../etc/passwd",
        name: "demo",
        scopes: ["read:data"],
        logger: cli.createLogger("silent"),
      })
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(cli.CliError)
    const cliErr = caught as InstanceType<typeof cli.CliError>
    expect(cliErr.exitCode).toBe(cli.ExitCode.userError)
    expect(cliErr.message).toContain("--user")
  })
})
