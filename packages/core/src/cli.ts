/**
 * Public `mcp-authkit/cli` entry point.
 *
 * Re-exports the programmatic CLI surface from `mcp-authkit-cli` so library
 * consumers can invoke a subcommand from their own tooling without taking a
 * direct dependency on the CLI package name:
 *
 * ```ts
 * import { run } from "mcp-authkit/cli"
 * await run({ argv: ["verify-config"] })
 * ```
 *
 * Spec: docs/spec/v0.2.md#510-import-paths-added-in-v02
 */
export {
  ArgvSecretLeakError,
  assertNoSecretFlags,
  buildProgram,
  CliError,
  type CliLogger,
  createLogger,
  ExitCode,
  type ExitCodeValue,
  genSecret,
  init,
  jwksFetch,
  type LogLevel,
  mintPatCommand,
  type RunOptions,
  run,
  verifyConfig,
} from "mcp-authkit-cli"
