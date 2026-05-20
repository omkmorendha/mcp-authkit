/**
 * CLI dispatcher.
 *
 * Builds the `commander` program, wires each subcommand to its
 * implementation in `./commands/`, applies global options, and translates
 * thrown errors into the exit-code matrix from spec §5.7.
 *
 * The argv leak guard (`assertNoSecretFlags`) runs *before* commander
 * starts parsing — a secret-shaped flag fails closed without ever touching
 * an authorization server, store, or config loader (spec §12).
 *
 * Spec: docs/spec/v0.2.md#57-cli
 */
import { Command, Option } from "commander"
import { ArgvSecretLeakError, assertNoSecretFlags } from "./argv-guard.js"
import { genSecret } from "./commands/gen-secret.js"
import { init } from "./commands/init.js"
import { jwksFetch } from "./commands/jwks-fetch.js"
import { mintPatCommand } from "./commands/mint-pat.js"
import { verifyConfig } from "./commands/verify-config.js"
import { CliError, ExitCode, type ExitCodeValue } from "./exit-codes.js"
import { type CliLogger, createLogger, isLogLevel, type LogLevel } from "./logger.js"

export interface RunOptions {
  /** argv excluding the node executable and script. Defaults to `process.argv.slice(2)`. */
  argv?: readonly string[]
  /** Override stdout for tests. */
  stdout?: NodeJS.WritableStream
  /** Override stderr for tests (used only for logger output). */
  stderr?: NodeJS.WritableStream
  /** Override the working directory for `init`. */
  cwd?: string
  /** Inject a logger; defaults to one driven by `--log-level`. */
  loggerFactory?: (level: LogLevel) => CliLogger
}

const DEFAULT_CONFIG_PATH = "./mcp-authkit.config.ts"

interface GlobalOpts {
  config: string
  logLevel: LogLevel
  json: boolean
}

function readGlobalOpts(program: Command): GlobalOpts {
  const opts = program.opts<{ config?: string; logLevel?: string; json?: boolean }>()
  const level = opts.logLevel ?? "info"
  if (!isLogLevel(level)) {
    throw new CliError(
      ExitCode.userError,
      `--log-level must be one of trace|debug|info|warn|error|fatal|silent (got "${level}")`,
    )
  }
  return {
    config: opts.config ?? DEFAULT_CONFIG_PATH,
    logLevel: level,
    json: opts.json === true,
  }
}

function parseScopesCsv(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function parsePositiveInt(value: string, flagName: string): number {
  const n = Number.parseInt(value, 10)
  if (!Number.isInteger(n) || n < 1 || String(n) !== value.trim()) {
    throw new CliError(
      ExitCode.userError,
      `${flagName} must be a positive integer (got "${value}")`,
    )
  }
  return n
}

/**
 * Build the commander tree. Exported so a programmatic caller can inspect
 * the help / option matrix without invoking the runner. The optional
 * `streams` argument redirects commander's own help/error output to caller-
 * supplied sinks, which keeps tests free of stdout/stderr pollution.
 */
export function buildProgram(streams?: {
  stdout?: NodeJS.WritableStream
  stderr?: NodeJS.WritableStream
}): Command {
  const out = streams?.stdout ?? process.stdout
  const err = streams?.stderr ?? process.stderr
  const program = new Command()
  program
    .name("mcp-authkit")
    .description("Command-line companion for mcp-authkit.")
    .addOption(
      new Option("--config <path>", "path to mcp-authkit.config.ts").default(DEFAULT_CONFIG_PATH),
    )
    .addOption(
      new Option("--log-level <level>", "pino log level")
        .choices(["trace", "debug", "info", "warn", "error", "fatal", "silent"])
        .default("info"),
    )
    .addOption(new Option("--json", "machine-readable JSON output where applicable"))
    .exitOverride()
    .configureOutput({
      writeOut: (str) => out.write(str),
      writeErr: (str) => err.write(str),
    })
  return program
}

type PendingAction = () => Promise<void> | void

interface DispatchState {
  pending: PendingAction | null
  parseErrorCode: ExitCodeValue | null
}

/**
 * Run the CLI and return the resolved exit code. The caller (the bin) is
 * responsible for `process.exit(code)`; this function never calls it
 * directly, which keeps tests free of mock-process-exit gymnastics.
 */
export async function run(options: RunOptions = {}): Promise<ExitCodeValue> {
  const argv = options.argv ?? process.argv.slice(2)
  const stdout = options.stdout ?? process.stdout
  const stderr = options.stderr ?? process.stderr

  try {
    assertNoSecretFlags(argv)
  } catch (err) {
    if (err instanceof ArgvSecretLeakError) {
      stderr.write(`error: ${err.message}\n`)
      return ExitCode.userError
    }
    throw err
  }

  const program = buildProgram({ stdout, stderr })
  // Annotated through `DispatchState` so the compiler does not narrow
  // `pending` to `null` after `parseAsync`. Commander invokes the action
  // callbacks from inside `parseAsync`, but TypeScript's control-flow
  // analysis does not model that side effect.
  const state: DispatchState = { pending: null, parseErrorCode: null }

  program
    .command("init [path]")
    .description("Scaffold a project (config, env, hello-world).")
    .option("--force", "overwrite existing files / write into a non-empty directory")
    .action((path: string | undefined, cmdOpts: { force?: boolean }) => {
      const g = readGlobalOpts(program)
      const logger = (options.loggerFactory ?? createLogger)(g.logLevel)
      state.pending = () => {
        const args: Parameters<typeof init>[0] = {
          force: cmdOpts.force === true,
          logger,
          stdout,
        }
        if (path !== undefined) args.path = path
        if (options.cwd !== undefined) args.cwd = options.cwd
        init(args)
      }
    })

  program
    .command("mint-pat")
    .description("Mint a PAT against the configured store.")
    .requiredOption("--user <id>", "user identifier the PAT belongs to")
    .requiredOption("--name <name>", "human-readable PAT name")
    .requiredOption("--scopes <csv>", "comma-separated list of scopes", parseScopesCsv)
    .option("--expires-in-days <n>", "expiry override in days", (v) =>
      parsePositiveInt(v, "--expires-in-days"),
    )
    .action((cmdOpts: { user: string; name: string; scopes: string[]; expiresInDays?: number }) => {
      const g = readGlobalOpts(program)
      const logger = (options.loggerFactory ?? createLogger)(g.logLevel)
      state.pending = async () => {
        const mintArgs: Parameters<typeof mintPatCommand>[0] = {
          configPath: g.config,
          user: cmdOpts.user,
          name: cmdOpts.name,
          scopes: cmdOpts.scopes,
          json: g.json,
          logger,
          stdout,
        }
        if (cmdOpts.expiresInDays !== undefined) {
          mintArgs.expiresInDays = cmdOpts.expiresInDays
        }
        await mintPatCommand(mintArgs)
      }
    })

  program
    .command("verify-config")
    .description("Load and validate the config file.")
    .action(() => {
      const g = readGlobalOpts(program)
      const logger = (options.loggerFactory ?? createLogger)(g.logLevel)
      state.pending = () =>
        verifyConfig({
          configPath: g.config,
          json: g.json,
          logger,
          stdout,
        })
    })

  program
    .command("jwks-fetch")
    .description("Fetch JWKS for a configured issuer.")
    .option("--issuer <url>", "discover JWKS via the given issuer instead of the config")
    .action((cmdOpts: { issuer?: string }) => {
      const g = readGlobalOpts(program)
      const logger = (options.loggerFactory ?? createLogger)(g.logLevel)
      state.pending = async () => {
        const args: Parameters<typeof jwksFetch>[0] = {
          configPath: g.config,
          json: g.json,
          logger,
          stdout,
        }
        if (cmdOpts.issuer !== undefined) {
          args.issuer = cmdOpts.issuer
        }
        await jwksFetch(args)
      }
    })

  program
    .command("gen-secret [length]")
    .description("Generate a cryptographically strong secret (base64url).")
    .action((lengthArg: string | undefined) => {
      const g = readGlobalOpts(program)
      state.pending = () => {
        const opts: Parameters<typeof genSecret>[0] = { json: g.json, stdout }
        if (lengthArg !== undefined) {
          opts.length = parsePositiveInt(lengthArg, "length")
        }
        genSecret(opts)
      }
    })

  try {
    await program.parseAsync(argv, { from: "user" })
  } catch (err) {
    const ce = err as { code?: string; message?: string; exitCode?: number }
    if (
      ce.code === "commander.helpDisplayed" ||
      ce.code === "commander.help" ||
      ce.code === "commander.version"
    ) {
      return ExitCode.success
    }
    if (err instanceof CliError) {
      stderr.write(`error: ${err.message}\n`)
      return err.exitCode
    }
    const message = ce.message ?? "argument parsing failed"
    if (!message.includes("(outputHelp)")) {
      stderr.write(`error: ${message}\n`)
    }
    state.parseErrorCode = ExitCode.userError
  }

  if (state.parseErrorCode !== null) return state.parseErrorCode

  const action = state.pending
  if (action === null) {
    return ExitCode.userError
  }

  try {
    await action()
    return ExitCode.success
  } catch (err) {
    if (err instanceof CliError) {
      stderr.write(`error: ${err.message}\n`)
      return err.exitCode
    }
    const message = err instanceof Error ? err.message : String(err)
    stderr.write(`error: ${message}\n`)
    return ExitCode.runtimeError
  }
}
