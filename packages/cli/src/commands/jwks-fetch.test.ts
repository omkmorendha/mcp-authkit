import { dirname, resolve } from "node:path"
import { PassThrough } from "node:stream"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { CliError, ExitCode } from "../exit-codes.js"
import { createLogger } from "../logger.js"
import { jwksFetch } from "./jwks-fetch.js"

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

interface FakeRoute {
  status?: number
  body?: unknown
  textBody?: string
  bodyIsInvalidJson?: boolean
}

function fakeFetcher(routes: Record<string, FakeRoute>): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : String(input)
    const route = routes[url]
    if (route === undefined) {
      throw new Error(`unexpected fetch URL: ${url}`)
    }
    const status = route.status ?? 200
    const headers = new Headers({ "Content-Type": "application/json" })
    if (route.bodyIsInvalidJson === true) {
      return new Response("not json", { status, headers })
    }
    const text = route.textBody ?? JSON.stringify(route.body ?? {})
    return new Response(text, { status, headers })
  }) as typeof fetch
}

describe("jwksFetch", () => {
  it("prints key ids and algorithms from a configured jwksUri", async () => {
    const out = new PassThrough()
    const jwks = {
      keys: [
        { kid: "k1", kty: "RSA", alg: "RS256", use: "sig" },
        { kid: "k2", kty: "EC", alg: "ES256", use: "sig" },
      ],
    }
    await jwksFetch({
      configPath: resolve(fixtures, "valid.config.ts"),
      logger: silent,
      stdout: out,
      fetchImpl: fakeFetcher({
        "https://as.example.test/.well-known/jwks.json": { body: jwks },
      }),
    })
    out.end()
    const text = await collect(out)
    expect(text).toContain("https://as.example.test/.well-known/jwks.json")
    expect(text).toContain("keys: 2")
    expect(text).toContain("kid=k1")
    expect(text).toContain("alg=RS256")
    expect(text).toContain("kid=k2")
    expect(text).toContain("alg=ES256")
  })

  it("emits the raw JWKS with --json", async () => {
    const out = new PassThrough()
    const jwks = { keys: [{ kid: "k1", kty: "RSA", alg: "RS256" }] }
    await jwksFetch({
      configPath: resolve(fixtures, "valid.config.ts"),
      json: true,
      logger: silent,
      stdout: out,
      fetchImpl: fakeFetcher({
        "https://as.example.test/.well-known/jwks.json": { body: jwks },
      }),
    })
    out.end()
    const text = (await collect(out)).trimEnd()
    expect(JSON.parse(text)).toEqual(jwks)
  })

  it("discovers via --issuer using AS metadata", async () => {
    const out = new PassThrough()
    const issuer = "https://issuer.example.test"
    const meta = { jwks_uri: `${issuer}/jwks` }
    const jwks = { keys: [{ kid: "k1", kty: "RSA", alg: "RS256" }] }
    await jwksFetch({
      configPath: resolve(fixtures, "no-as.config.ts"),
      issuer,
      logger: silent,
      stdout: out,
      fetchImpl: fakeFetcher({
        [`${issuer}/.well-known/oauth-authorization-server`]: { body: meta },
        [`${issuer}/jwks`]: { body: jwks },
      }),
    })
    out.end()
    const text = await collect(out)
    expect(text).toContain(`${issuer}/jwks`)
    expect(text).toContain("keys: 1")
  })

  it("falls back to OIDC discovery when AS metadata 404s", async () => {
    const out = new PassThrough()
    const issuer = "https://issuer.example.test"
    const meta = { jwks_uri: `${issuer}/jwks-oidc` }
    const jwks = { keys: [] }
    await jwksFetch({
      configPath: resolve(fixtures, "no-as.config.ts"),
      issuer,
      logger: silent,
      stdout: out,
      fetchImpl: fakeFetcher({
        [`${issuer}/.well-known/oauth-authorization-server`]: { status: 404 },
        [`${issuer}/.well-known/openid-configuration`]: { body: meta },
        [`${issuer}/jwks-oidc`]: { body: jwks },
      }),
    })
    out.end()
    const text = await collect(out)
    expect(text).toContain(`${issuer}/jwks-oidc`)
    expect(text).toContain("keys: 0")
  })

  it("fails with a config error when config has no jwksUri and no --issuer is given", async () => {
    try {
      await jwksFetch({
        configPath: resolve(fixtures, "no-as.config.ts"),
        logger: silent,
        fetchImpl: fakeFetcher({}),
      })
      throw new Error("expected throw")
    } catch (err) {
      expect(err).toBeInstanceOf(CliError)
      expect((err as CliError).exitCode).toBe(ExitCode.configError)
    }
  })

  it("returns a runtime error when discovery exhausts both candidates", async () => {
    const issuer = "https://issuer.example.test"
    try {
      await jwksFetch({
        configPath: resolve(fixtures, "no-as.config.ts"),
        issuer,
        logger: silent,
        fetchImpl: fakeFetcher({
          [`${issuer}/.well-known/oauth-authorization-server`]: { status: 404 },
          [`${issuer}/.well-known/openid-configuration`]: { status: 404 },
        }),
      })
      throw new Error("expected throw")
    } catch (err) {
      expect((err as CliError).exitCode).toBe(ExitCode.runtimeError)
    }
  })

  it("returns a runtime error when the JWKS response is malformed", async () => {
    try {
      await jwksFetch({
        configPath: resolve(fixtures, "valid.config.ts"),
        logger: silent,
        fetchImpl: fakeFetcher({
          "https://as.example.test/.well-known/jwks.json": { body: { not: "a jwks" } },
        }),
      })
      throw new Error("expected throw")
    } catch (err) {
      expect((err as CliError).exitCode).toBe(ExitCode.runtimeError)
    }
  })
})
