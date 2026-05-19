/**
 * `jwks-fetch [--issuer URL]` — fetch a JWKS and print key IDs + algorithms.
 *
 * Discovery order:
 *   1. If `--issuer <url>` is supplied, perform RFC 8414 discovery against
 *      `<issuer>/.well-known/oauth-authorization-server` to find `jwks_uri`.
 *      Falls back to OIDC `.well-known/openid-configuration` if AS metadata
 *      is missing.
 *   2. Otherwise, load the config; require `auth.authorizationServer.jwksUri`.
 *
 * With `--json`, the raw JWKS object is printed. Without, a short
 * human-readable table of `{ kid, kty, alg }` rows is printed.
 *
 * Spec: docs/spec/v0.2.md#94-jwks-fetch
 */
import { isAbsolute } from "node:path"
import { ConfigLoadError, loadConfig } from "mcp-authkit-config"
import { CliError, ExitCode } from "../exit-codes.js"
import type { CliLogger } from "../logger.js"

export interface JwksFetchOptions {
  configPath: string
  issuer?: string
  json?: boolean
  logger: CliLogger
  stdout?: NodeJS.WritableStream
  /** Override for tests. Defaults to global `fetch`. */
  fetchImpl?: typeof fetch
  /** Per-request timeout. Default 10s. */
  timeoutMs?: number
}

const DEFAULT_TIMEOUT_MS = 10_000

interface Jwk {
  kid?: string
  kty?: string
  alg?: string
  use?: string
}

interface Jwks {
  keys: Jwk[]
}

export async function jwksFetch(options: JwksFetchOptions): Promise<void> {
  const out = options.stdout ?? process.stdout
  const doFetch = options.fetchImpl ?? globalThis.fetch
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  let jwksUri: string
  if (options.issuer !== undefined && options.issuer.length > 0) {
    jwksUri = await discoverJwksUri(options.issuer, doFetch, timeoutMs, options.logger)
  } else {
    let config: Awaited<ReturnType<typeof loadConfig>>
    try {
      config = await loadConfig(options.configPath, {
        allowOutsideCwd: isAbsolute(options.configPath),
      })
    } catch (err) {
      if (err instanceof ConfigLoadError) {
        throw new CliError(ExitCode.configError, err.message, { cause: err })
      }
      throw err
    }
    const fromConfig = config.auth.authorizationServer?.jwksUri
    if (fromConfig === undefined || fromConfig.length === 0) {
      throw new CliError(
        ExitCode.configError,
        "auth.authorizationServer.jwksUri is not set; pass --issuer <url> to discover it",
      )
    }
    jwksUri = fromConfig
  }

  options.logger.debug("fetching JWKS", { jwksUri })
  const jwks = await fetchJson<Jwks>(jwksUri, doFetch, timeoutMs)
  if (!Array.isArray(jwks.keys)) {
    throw new CliError(
      ExitCode.runtimeError,
      `JWKS response is missing a "keys" array (jwksUri: ${jwksUri})`,
    )
  }

  if (options.json === true) {
    out.write(`${JSON.stringify(jwks)}\n`)
    return
  }

  out.write(`jwksUri: ${jwksUri}\n`)
  out.write(`keys: ${jwks.keys.length}\n`)
  for (const key of jwks.keys) {
    const kid = key.kid ?? "(no kid)"
    const kty = key.kty ?? "?"
    const alg = key.alg ?? "(unspecified)"
    const use = key.use ?? "-"
    out.write(`  - kid=${kid} kty=${kty} alg=${alg} use=${use}\n`)
  }
}

async function discoverJwksUri(
  issuer: string,
  doFetch: typeof fetch,
  timeoutMs: number,
  logger: CliLogger,
): Promise<string> {
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer
  const candidates = [
    `${base}/.well-known/oauth-authorization-server`,
    `${base}/.well-known/openid-configuration`,
  ]
  let lastErr: unknown
  for (const url of candidates) {
    try {
      logger.debug("trying discovery URL", { url })
      const meta = await fetchJson<{ jwks_uri?: unknown }>(url, doFetch, timeoutMs)
      if (typeof meta.jwks_uri === "string" && meta.jwks_uri.length > 0) {
        return meta.jwks_uri
      }
    } catch (err) {
      lastErr = err
    }
  }
  const message = lastErr instanceof Error ? lastErr.message : "no jwks_uri found"
  throw new CliError(
    ExitCode.runtimeError,
    `Could not discover jwks_uri for issuer "${issuer}": ${message}`,
    { cause: lastErr },
  )
}

async function fetchJson<T>(url: string, doFetch: typeof fetch, timeoutMs: number): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  let response: Response
  try {
    response = await doFetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    throw new CliError(ExitCode.runtimeError, `request failed: ${url} (${message})`, { cause: err })
  } finally {
    clearTimeout(timer)
  }
  if (!response.ok) {
    throw new CliError(
      ExitCode.runtimeError,
      `request failed: ${url} returned HTTP ${response.status}`,
    )
  }
  try {
    return (await response.json()) as T
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    throw new CliError(ExitCode.runtimeError, `response is not valid JSON: ${url} (${message})`, {
      cause: err,
    })
  }
}
