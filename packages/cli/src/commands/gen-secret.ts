/**
 * `gen-secret [length]` — print `crypto.randomBytes(length).toString('base64url')`.
 *
 * Default length is 32 bytes (256 bits). No config is loaded. Used as a
 * one-shot helper for operators bootstrapping HMAC keys, static tokens, etc.
 *
 * Spec: docs/spec/v0.2.md#95-gen-secret-length
 */
import { randomBytes } from "node:crypto"
import { CliError, ExitCode } from "../exit-codes.js"

export interface GenSecretOptions {
  length?: number
  json?: boolean
  stdout?: NodeJS.WritableStream
}

const DEFAULT_LENGTH = 32
const MAX_LENGTH = 4096

export function genSecret(options: GenSecretOptions = {}): void {
  const length = options.length ?? DEFAULT_LENGTH
  if (!Number.isInteger(length) || length < 1 || length > MAX_LENGTH) {
    throw new CliError(
      ExitCode.userError,
      `length must be an integer in [1, ${MAX_LENGTH}], got ${String(length)}`,
    )
  }
  const out = options.stdout ?? process.stdout
  const secret = randomBytes(length).toString("base64url")
  if (options.json === true) {
    out.write(`${JSON.stringify({ secret, length })}\n`)
  } else {
    out.write(`${secret}\n`)
  }
}
