/**
 * `mint-pat --user <id> --name <name> --scopes <csv> [--expires-in-days N]`
 *
 * Loads the config, opens the store, mints a PAT, prints the token once to
 * stdout. The CLI does not grant itself OAuth and does not mint "admin" or
 * "system" PATs — the caller must specify a real user identifier the
 * operator's domain recognizes (spec §9.2).
 *
 * `--user`, `--name`, `--scopes`, `--expires-in-days` are all non-secret
 * (spec §12: secrets stay in env vars or the config file).
 *
 * Spec: docs/spec/v0.2.md#92-mint-pat
 */
import { isAbsolute } from "node:path"
import { ConfigLoadError, loadConfig } from "mcp-authkit-config"
import type { CreatePatInput } from "mcp-authkit-store-memory"
import { CliError, ExitCode } from "../exit-codes.js"
import type { CliLogger } from "../logger.js"
import { buildDisplay, mintPat } from "../pat-format.js"

export interface MintPatOptions {
  configPath: string
  user: string
  name: string
  scopes: readonly string[]
  expiresInDays?: number
  json?: boolean
  logger: CliLogger
  stdout?: NodeJS.WritableStream
}

const DEFAULT_EXPIRY_DAYS = 90
const MAX_EXPIRY_DAYS = 365 * 5

export async function mintPatCommand(options: MintPatOptions): Promise<void> {
  if (options.user.trim().length === 0) {
    throw new CliError(ExitCode.userError, "--user must be a non-empty string")
  }
  if (options.name.trim().length === 0) {
    throw new CliError(ExitCode.userError, "--name must be a non-empty string")
  }
  if (options.scopes.length === 0) {
    throw new CliError(ExitCode.userError, "--scopes must list at least one scope")
  }

  const days = options.expiresInDays ?? DEFAULT_EXPIRY_DAYS
  if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
    throw new CliError(
      ExitCode.userError,
      `--expires-in-days must be an integer in [1, ${MAX_EXPIRY_DAYS}]`,
    )
  }

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

  if (!config.auth.pat.enabled) {
    throw new CliError(
      ExitCode.configError,
      "auth.pat.enabled is false; cannot mint PATs against this configuration",
    )
  }
  const prefix = config.auth.pat.prefix ?? "mcp_pat_"

  const store = config.auth.tokenStore
  if (store.init !== undefined) {
    try {
      await store.init()
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      throw new CliError(ExitCode.runtimeError, `TokenStore init failed: ${message}`, {
        cause: err,
      })
    }
  }

  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000)
  const minted = mintPat(prefix)
  const input: CreatePatInput = {
    userIdentifier: options.user,
    name: options.name,
    scopes: [...options.scopes],
    expiresAt,
    tokenHash: minted.tokenHash,
    display: buildDisplay(prefix, minted.token),
  }

  let stored: Awaited<ReturnType<typeof store.createPat>>
  try {
    stored = await store.createPat(input)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    throw new CliError(ExitCode.runtimeError, `TokenStore.createPat failed: ${message}`, {
      cause: err,
    })
  } finally {
    if (store.close !== undefined) {
      try {
        await store.close()
      } catch (err) {
        options.logger.warn("TokenStore close failed", {
          error: err instanceof Error ? err.message : String(err),
        })
      }
    }
  }

  const out = options.stdout ?? process.stdout
  if (options.json === true) {
    out.write(
      `${JSON.stringify({
        token: minted.token,
        id: stored.id,
        expiresAt: stored.expiresAt.toISOString(),
      })}\n`,
    )
  } else {
    out.write(`${minted.token}\n`)
    options.logger.info("PAT minted", {
      id: stored.id,
      expiresAt: stored.expiresAt.toISOString(),
      display: stored.display,
    })
  }
}
