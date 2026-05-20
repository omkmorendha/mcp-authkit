/**
 * Production stdio config validation (v0.2 §11).
 *
 * Mirrors `bypass/checkBypassConfig`: called once at startup. Throws if the
 * config violates the §11 invariants; emits the loud startup warn.
 *
 * @module
 */
import type { Logger } from "pino"
import type { AuthKitConfig } from "../types.js"
import { keyFingerprint, normaliseHmacKey } from "./frame.js"

export class SignedStdioConfigError extends Error {
  override readonly name = "SignedStdioConfigError"
}

export interface CheckSignedStdioOptions {
  config: AuthKitConfig
  logger: Logger
}

/**
 * Validate the `auth.stdio` block.
 *
 * Hard rules:
 * - `mode === "signed"` is the only supported value (v0.2 §11).
 * - Bypass mode is REFUSED when signed stdio is active. Throws at startup
 *   if `bypass.enabled === true`.
 * - `hmacKey` must be a non-empty string or `Buffer`.
 *
 * Emits a single `logger.warn` naming the mode and the 8-hex-char key
 * fingerprint. NEVER logs the key itself.
 */
export function checkSignedStdioConfig(opts: CheckSignedStdioOptions): void {
  const { config, logger } = opts
  const stdio = config.auth.stdio
  if (stdio === undefined) return

  if (stdio.mode !== "signed") {
    throw new SignedStdioConfigError(
      `auth.stdio.mode must be "signed" (got ${JSON.stringify((stdio as { mode: unknown }).mode)}).`,
    )
  }

  // normaliseHmacKey throws on empty key.
  const key = normaliseHmacKey(stdio.hmacKey)
  const fingerprint = keyFingerprint(key)

  if (config.auth.bypass?.enabled === true) {
    throw new SignedStdioConfigError(
      "auth.stdio.mode is 'signed' but auth.bypass.enabled is true. " +
        "Bypass mode is refused alongside signed stdio (spec v0.2 §11). " +
        "Disable bypass or remove the signed-stdio config.",
    )
  }

  logger.warn(
    {
      stdio: {
        mode: stdio.mode,
        keyFingerprint: fingerprint,
      },
    },
    "Production stdio (signed-handshake) is active — every frame is HMAC-verified; only static token or PATs authenticate",
  )
}
