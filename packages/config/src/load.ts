/**
 * Bounded config file loader.
 *
 * Loads a TypeScript or JavaScript config file via `tsx`'s programmatic
 * `tsImport` API, validates the default export against `authKitConfigSchema`,
 * and returns the typed `AuthKitConfig`. Spec §12 mandates the load is
 * bounded: 10s timeout, paths outside CWD rejected unless the caller opts
 * in explicitly (the CLI does so for `--config <abs-path>`).
 *
 * Spec: docs/spec/v0.2.md#58-config-file-format
 *       docs/spec/v0.2.md#12-security-non-negotiables-additions
 */
import { existsSync } from "node:fs"
import { isAbsolute, relative, resolve, sep } from "node:path"
import { pathToFileURL } from "node:url"
import { tsImport } from "tsx/esm/api"
import type { z } from "zod"
import { authKitConfigSchema } from "./schema.js"
import type { AuthKitConfig } from "./types.js"

export interface LoadConfigOptions {
  /** Total budget for the import + default-export resolution. Default 10_000 ms. */
  timeoutMs?: number
  /**
   * When false (default), reject any path that, after resolution, does not
   * live under `process.cwd()`. The CLI uses `true` to honour an explicit
   * `--config <abs-path>` from the operator.
   */
  allowOutsideCwd?: boolean
  /**
   * Override for tests so they can verify the CWD check without `chdir`.
   * Not part of the documented public surface.
   */
  cwd?: string
}

export class ConfigLoadError extends Error {
  readonly filePath: string
  constructor(filePath: string, message: string, options?: { cause?: unknown }) {
    super(`${message} (config: ${filePath})`, options)
    this.name = "ConfigLoadError"
    this.filePath = filePath
  }
}

const DEFAULT_TIMEOUT_MS = 10_000

/**
 * Returns true when `child`, after resolution, is the same as `parent` or a
 * descendant directory entry. Uses path separator boundaries to avoid the
 * `/foo` vs `/foobar` false-positive.
 */
function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child)
  if (rel === "") return true
  if (rel.startsWith("..")) return false
  if (isAbsolute(rel)) return false
  return !rel.split(sep).includes("..")
}

/**
 * Format a Zod issue path as a dotted string. Numeric path segments use
 * `[i]` so the rendered message reads like a JS property path.
 */
function formatIssuePath(path: ReadonlyArray<PropertyKey>): string {
  if (path.length === 0) return "(root)"
  let out = ""
  for (const seg of path) {
    if (typeof seg === "number") {
      out += `[${seg}]`
    } else {
      out += out === "" ? String(seg) : `.${String(seg)}`
    }
  }
  return out
}

function formatZodError(error: z.ZodError): string {
  const lines = error.issues.map((iss) => `  - ${formatIssuePath(iss.path)}: ${iss.message}`)
  return `Config schema validation failed:\n${lines.join("\n")}`
}

/**
 * Race the supplied promise against a timer. The timer is cleared on
 * settle so the process can exit cleanly even when the import is fast.
 */
function withTimeout<T>(p: Promise<T>, timeoutMs: number, onTimeout: () => Error): Promise<T> {
  return new Promise<T>((resolveOuter, rejectOuter) => {
    const timer = setTimeout(() => rejectOuter(onTimeout()), timeoutMs)
    timer.unref?.()
    p.then(
      (value) => {
        clearTimeout(timer)
        resolveOuter(value)
      },
      (err) => {
        clearTimeout(timer)
        rejectOuter(err)
      },
    )
  })
}

interface ModuleNamespaceLike {
  default?: unknown
}

/**
 * Indirection over `tsImport` so tests can inject a slow or rejecting stub
 * without needing a real on-disk file that actually blocks for 11 seconds.
 * Internal — not exported from the package index.
 */
export type TsImportFn = (specifier: string, parentUrl: string) => Promise<unknown>
let importer: TsImportFn = (specifier, parentUrl) =>
  tsImport(specifier, parentUrl) as Promise<unknown>

/** Test-only seam to override the module importer. Returns a restore fn. */
export function _setTsImportForTests(next: TsImportFn): () => void {
  const prev = importer
  importer = next
  return () => {
    importer = prev
  }
}

/**
 * Load an `AuthKitConfig` from a file path.
 *
 * @throws {ConfigLoadError} when the file is missing, the path escapes the
 * CWD without `allowOutsideCwd`, the import times out, the import throws, or
 * the default export fails schema validation.
 */
export async function loadConfig(
  filePath: string,
  options: LoadConfigOptions = {},
): Promise<AuthKitConfig> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const allowOutsideCwd = options.allowOutsideCwd ?? false
  const cwd = options.cwd ?? process.cwd()

  const absPath = isAbsolute(filePath) ? filePath : resolve(cwd, filePath)

  if (!allowOutsideCwd && !isInside(cwd, absPath)) {
    throw new ConfigLoadError(
      absPath,
      `Refusing to load config outside the working directory. Pass allowOutsideCwd: true (CLI: --config <abs-path>) to override`,
    )
  }

  if (!existsSync(absPath)) {
    throw new ConfigLoadError(absPath, "Config file not found")
  }

  const parentUrl = pathToFileURL(`${cwd}${sep}`).href

  let mod: ModuleNamespaceLike
  try {
    mod = (await withTimeout(
      importer(absPath, parentUrl) as Promise<ModuleNamespaceLike>,
      timeoutMs,
      () =>
        new ConfigLoadError(
          absPath,
          `Config file load timed out after ${timeoutMs}ms (spec §12: bounded load)`,
        ),
    )) as ModuleNamespaceLike
  } catch (err) {
    if (err instanceof ConfigLoadError) throw err
    throw new ConfigLoadError(absPath, "Failed to evaluate config file", { cause: err })
  }

  const exported = mod.default
  if (exported === undefined) {
    throw new ConfigLoadError(absPath, "Config file has no default export")
  }

  const parsed = authKitConfigSchema.safeParse(exported)
  if (!parsed.success) {
    throw new ConfigLoadError(absPath, formatZodError(parsed.error))
  }
  // The Zod schema mirrors `AuthKitConfig` structurally; the parsed value
  // is typed as the inferred shape of the schema and is assignable to
  // `AuthKitConfig` (function fields go through `z.custom` which preserves
  // the caller-supplied implementation).
  return parsed.data as unknown as AuthKitConfig
}
