/**
 * Argv leak guard (spec §12).
 *
 * The CLI never reads secrets from argv. Anything secret comes from env vars
 * or the loaded config file. This helper rejects flags whose value looks
 * secret-shaped before any I/O happens, so an operator who fat-fingers
 *
 *   mcp-authkit mint-pat --secret sk_live_...
 *
 * fails closed before the config is loaded or any authorization-server call
 * is made.
 *
 * The check is deliberately broad. Any flag whose name contains
 * `secret|token|password|pat|key` (case-insensitive) is rejected with a
 * pointer to the env var or config file as the correct source. The handful
 * of legitimate `--*-key`-style flags this framework exposes (e.g.
 * `--scopes`, `--name`, `--user`, `--config`, `--log-level`, `--issuer`,
 * `--expires-in-days`, `--json`, `--force`) are not in that pattern.
 *
 * Note: `--config` is allowed because it is a path, not a secret.
 */

// Match flag *names* (no value portion) that contain any of these substrings.
// Token boundaries are word-ish: a hyphen, the leading `--`, or the end of
// the flag name. The lookahead at the end keeps `--scopes`, `--name`,
// `--user`, `--config`, `--log-level`, `--issuer`, `--expires-in-days`,
// `--json`, `--force` from matching while catching `--secret`, `--token`,
// `--password`, `--api-key`, `--client-secret`, `--pat`, `--apikey`.
const SECRET_TOKENS = /(^|-)(secret|token|password|pat|apikey|key|credential|passphrase)(-|$)/i

export class ArgvSecretLeakError extends Error {
  readonly flag: string
  constructor(flag: string) {
    super(
      `CLI refuses to read secrets from argv. The flag "${flag}" looks secret-shaped. ` +
        `Provide secrets via environment variables or your mcp-authkit.config.ts.`,
    )
    this.name = "ArgvSecretLeakError"
    this.flag = flag
  }
}

/**
 * Scan a raw argv array (typically `process.argv.slice(2)`) for any flag
 * whose name matches the secret pattern. Throws on the first match.
 *
 * The check is on the *flag name*, not the value, so a real PAT accidentally
 * stuffed into `--name` is not flagged here — `mint-pat` does not require a
 * secret value for any of its public flags, so callers cannot smuggle one
 * in. The intent of the guard is to make leakage from misuse visible.
 */
export function assertNoSecretFlags(argv: readonly string[]): void {
  for (const arg of argv) {
    if (typeof arg !== "string") continue
    if (!arg.startsWith("--")) continue
    // `--flag=value` — strip value for matching.
    const eq = arg.indexOf("=")
    const flagName = eq === -1 ? arg : arg.slice(0, eq)
    // Strip the leading `--` before pattern testing.
    const bare = flagName.slice(2)
    if (SECRET_TOKENS.test(bare)) {
      throw new ArgvSecretLeakError(flagName)
    }
  }
}
