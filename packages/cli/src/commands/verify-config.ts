/**
 * `verify-config` — load and validate the config file.
 *
 * Runs the same schema validation that `createAuthKit` will run at startup
 * (delegated to `loadConfig` from `mcp-authkit-config`), then prints a
 * redacted summary via `redactConfigForLog`. Exits 0 on success, 2 on a
 * config error.
 *
 * Spec: docs/spec/v0.2.md#93-verify-config
 */
import { isAbsolute } from "node:path"
import { ConfigLoadError, loadConfig, redactConfigForLog } from "mcp-authkit-config"
import { CliError, ExitCode } from "../exit-codes.js"
import type { CliLogger } from "../logger.js"

export interface VerifyConfigOptions {
  configPath: string
  json?: boolean
  logger: CliLogger
  stdout?: NodeJS.WritableStream
}

export async function verifyConfig(options: VerifyConfigOptions): Promise<void> {
  const out = options.stdout ?? process.stdout
  try {
    // An absolute --config path is the operator's explicit opt-in to load
    // from outside the CWD (spec §12 bounded load).
    const config = await loadConfig(options.configPath, {
      allowOutsideCwd: isAbsolute(options.configPath),
    })
    const summary = redactConfigForLog(config)
    if (options.json === true) {
      out.write(`${JSON.stringify({ ok: true, configPath: options.configPath, summary })}\n`)
    } else {
      out.write(`Config OK: ${options.configPath}\n`)
      out.write(`${JSON.stringify(summary, null, 2)}\n`)
    }
    options.logger.debug("verify-config completed", { configPath: options.configPath })
  } catch (err) {
    if (err instanceof ConfigLoadError) {
      throw new CliError(ExitCode.configError, err.message, { cause: err })
    }
    throw err
  }
}
