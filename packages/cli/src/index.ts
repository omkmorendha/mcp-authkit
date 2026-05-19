/**
 * Programmatic entry for the mcp-authkit CLI.
 *
 * The bin (`./bin/mcp-authkit.ts`) is a thin wrapper around `run()`. Library
 * consumers who want to invoke a subcommand from their own tooling can
 * import the per-command functions directly.
 *
 * Spec: docs/spec/v0.2.md#510-import-paths-added-in-v02 (`mcp-authkit/cli`)
 */
export { ArgvSecretLeakError, assertNoSecretFlags } from "./argv-guard.js"
export { genSecret } from "./commands/gen-secret.js"
export { init } from "./commands/init.js"
export { jwksFetch } from "./commands/jwks-fetch.js"
export { mintPatCommand } from "./commands/mint-pat.js"
export { verifyConfig } from "./commands/verify-config.js"
export { CliError, ExitCode, type ExitCodeValue } from "./exit-codes.js"
export { type CliLogger, createLogger, type LogLevel } from "./logger.js"
export { buildProgram, type RunOptions, run } from "./run.js"
