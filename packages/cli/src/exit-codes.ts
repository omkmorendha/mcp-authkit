/**
 * CLI exit codes, per spec §5.7.
 *
 *   0 success
 *   1 user error      (bad flag, missing arg, refusal due to non-empty dir)
 *   2 config error    (missing file, schema violation, bounded-load failure)
 *   3 runtime error   (network failure, store failure, unexpected throw)
 *
 * `CliError` carries the intended exit code with the message; the top-level
 * runner maps any other throw to exit code 3.
 */

export const ExitCode = {
  success: 0,
  userError: 1,
  configError: 2,
  runtimeError: 3,
} as const

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode]

export class CliError extends Error {
  readonly exitCode: ExitCodeValue
  constructor(exitCode: ExitCodeValue, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = "CliError"
    this.exitCode = exitCode
  }
}
