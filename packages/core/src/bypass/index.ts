/**
 * Bypass mode, static-token path, and stdio auto-enable.
 *
 * Spec: docs/spec/v0.1.md#11-bypass-mode-and-stdio
 * Security: docs/spec/v0.1.md#14-security-non-negotiables (bypass refuses production)
 *
 * @module
 */
import type { Logger } from "pino"
import type { AuthContext, AuthKitConfig } from "../types.js"

/**
 * Thrown at startup when bypass mode is enabled in a production environment
 * without explicitly setting `bypass.allowInProduction: true`.
 *
 * Spec §11.1: "Refuses to start if NODE_ENV === 'production' unless
 * bypass.allowInProduction: true."
 */
export class BypassProductionError extends Error {
  override readonly name = "BypassProductionError"
}

export interface CheckBypassOptions {
  config: AuthKitConfig
  /**
   * The value of NODE_ENV. Defaults to `process.env["NODE_ENV"]`.
   * Injected explicitly in tests to avoid mutating process.env.
   */
  env?: string
  logger: Logger
}

/**
 * Call once at startup. Performs two actions:
 * 1. Throws `BypassProductionError` if bypass is active in production
 *    without `allowInProduction: true` (spec §14 security non-negotiable).
 * 2. Emits `logger.warn` naming the bypass user and scopes if bypass is active.
 *
 * "Active" means either `bypass.enabled` is true, or stdio auto-enable applies
 * (detected separately via `shouldAutoEnableBypass`).
 */
export function checkBypassConfig(opts: CheckBypassOptions): void {
  const { config, logger } = opts
  const env = opts.env ?? process.env.NODE_ENV

  const bypass = config.auth.bypass

  if (bypass === undefined || !bypass.enabled) {
    return
  }

  if (env === "production" && bypass.allowInProduction !== true) {
    throw new BypassProductionError(
      "Bypass mode is enabled but NODE_ENV is 'production'. " +
        "Set bypass.allowInProduction: true to allow this explicitly, " +
        "or disable bypass mode before deploying to production.",
    )
  }

  logger.warn(
    {
      bypass: {
        user: bypass.user,
        scopes: bypass.scopes,
        allowInProduction: bypass.allowInProduction ?? false,
      },
    },
    "Bypass mode is active — all requests will be authenticated as configured user without token validation",
  )
}

/**
 * Detects the stdio auto-enable path (spec §11.2).
 *
 * Returns `true` when:
 * - The transport is stdio, AND
 * - No `authorizationServer` is configured (no other auth is set up).
 *
 * When this returns `true`, the caller should activate bypass mode and emit
 * a startup warning.
 */
export function shouldAutoEnableBypass(
  config: AuthKitConfig,
  transport: "http" | "stdio",
): boolean {
  if (transport !== "stdio") return false
  return config.auth.authorizationServer === undefined
}

/**
 * Synthesizes an `AuthContext` for a request handled in bypass mode.
 *
 * Spec §11.1: `tokenType` is `"bypass"`, `expiresAt` is `null`.
 * The caller is responsible for emitting `logger.debug` on every bypassed request.
 */
export function synthesizeBypassContext(
  config: NonNullable<AuthKitConfig["auth"]["bypass"]>,
): AuthContext {
  return {
    subject: config.user,
    tokenType: "bypass",
    tokenId: `bypass:${config.user}`,
    scopes: config.scopes,
    expiresAt: null,
    raw: {},
  }
}

/**
 * Synthesizes an `AuthContext` for a request authenticated via static token.
 *
 * Spec §11.3: `tokenType` is `"static"`, `expiresAt` is `null`.
 * Treated as a synthetic PAT with fixed scopes; cannot manage PATs (spec §8.6).
 */
export function synthesizeStaticContext(
  config: NonNullable<AuthKitConfig["auth"]["staticToken"]>,
): AuthContext {
  return {
    subject: config.user,
    tokenType: "static",
    tokenId: `static:${config.user}`,
    scopes: config.scopes,
    expiresAt: null,
    raw: {},
  }
}
