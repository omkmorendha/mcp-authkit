/**
 * Minimal stderr logger for the CLI.
 *
 * The framework itself uses pino (spec §2). The CLI deliberately avoids
 * taking a runtime dependency on pino to keep the bin small and startup
 * fast: most subcommands are short-lived and only emit a handful of lines.
 * The `--log-level` flag accepts the pino level names so the developer
 * experience matches the framework.
 *
 * Output goes to stderr; the subcommand's data output goes to stdout. This
 * separation lets `--json` pipelines `mcp-authkit ... | jq` work cleanly
 * even at `--log-level debug`.
 */

// Matches pino's level set (spec §5.7). `silent` is included because pino
// itself supports it and tests use it to suppress runtime chatter without
// touching the assertion path. Operator-facing docs list the six core levels.
const LEVELS = ["trace", "debug", "info", "warn", "error", "fatal", "silent"] as const

export type LogLevel = (typeof LEVELS)[number]

export function isLogLevel(value: string): value is LogLevel {
  return (LEVELS as readonly string[]).includes(value)
}

const ORDER: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
  silent: 70,
}

export interface CliLogger {
  level: LogLevel
  trace(message: string, fields?: Record<string, unknown>): void
  debug(message: string, fields?: Record<string, unknown>): void
  info(message: string, fields?: Record<string, unknown>): void
  warn(message: string, fields?: Record<string, unknown>): void
  error(message: string, fields?: Record<string, unknown>): void
  fatal(message: string, fields?: Record<string, unknown>): void
}

function emit(
  threshold: number,
  level: LogLevel,
  message: string,
  fields: Record<string, unknown> | undefined,
): void {
  if (ORDER[level] < threshold) return
  const payload =
    fields !== undefined && Object.keys(fields).length > 0 ? ` ${JSON.stringify(fields)}` : ""
  process.stderr.write(`[${level}] ${message}${payload}\n`)
}

export function createLogger(level: LogLevel = "info"): CliLogger {
  const threshold = ORDER[level]
  return {
    level,
    trace: (m, f) => emit(threshold, "trace", m, f),
    debug: (m, f) => emit(threshold, "debug", m, f),
    info: (m, f) => emit(threshold, "info", m, f),
    warn: (m, f) => emit(threshold, "warn", m, f),
    error: (m, f) => emit(threshold, "error", m, f),
    fatal: (m, f) => emit(threshold, "fatal", m, f),
  }
}
