/**
 * Spec §14: "Constant-time comparison for all hash/token equality."
 * Issue #41 acceptance: "all hash/token equality uses `crypto.timingSafeEqual`
 * (code review criterion; enforced by grep in CI)."
 *
 * This test scans every production .ts file under `packages/*\/src` and flags
 * any line that does a `===` / `!==` comparison against a secret-bearing
 * identifier (token hashes, raw bearer tokens, refresh tokens, static tokens,
 * PAT plaintext). Allowed comparisons (length checks, null checks, typeof,
 * etc.) are not flagged because the trigger is the secret identifier itself.
 *
 * Test files (`*.test.ts`) are excluded — tests are allowed to use `===` for
 * setup/assertion.
 */
import { readdirSync, readFileSync, statSync } from "node:fs"
import { join, relative } from "node:path"
import { describe, expect, it } from "vitest"

// Identifiers that always carry a secret in this codebase. Any `===` or `!==`
// adjacent to one of these names must instead go through `timingSafeEqual` or
// `timingSafeStringEqual`. The check is intentionally pattern-based, not
// AST-based — false negatives are tolerable (test re-runs on every PR) but
// the false-positive surface stays empty.
const SECRET_IDENTIFIERS = [
  "tokenHash",
  "patHash",
  "refreshHash",
  "rawToken",
  "plaintextToken",
  "staticToken.token",
  "bearerToken",
]

// Patterns that are *safe* equality (null / undefined / length checks).
// We strip every occurrence of these from the line before scanning for an
// unsafe `===` / `!==`, so that a mixed line ("safe AND unsafe on the same
// line") cannot slip past the check.
const SAFE_EQUALITY_PATTERNS: readonly RegExp[] = [
  /[!=]==\s*null/g,
  /[!=]==\s*undefined/g,
  /\.length\s*[!=]==\s*\d+/g,
  /\.length\s*[!=]==\s*[A-Za-z_$][\w$.]*\.length/g,
]

function isCommentLine(line: string): boolean {
  const trimmed = line.trim()
  return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
}

/**
 * Remove every safe equality sub-expression from a line so the unsafe-check
 * sees only the remainder. This ensures a line that contains both a safe
 * (`x === null`) and an unsafe (`tokenHash === other`) comparison still
 * fails the test.
 */
function stripSafeEquality(line: string): string {
  let out = line
  for (const pattern of SAFE_EQUALITY_PATTERNS) {
    out = out.replace(pattern, "")
  }
  return out
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === "coverage") continue
    const p = join(dir, entry)
    const st = statSync(p)
    if (st.isDirectory()) {
      walk(p, out)
    } else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) {
      out.push(p)
    }
  }
}

interface Offence {
  readonly file: string
  readonly line: number
  readonly text: string
  readonly identifier: string
}

/**
 * Discover every `packages/*\/src` directory at the repo root. Dynamic
 * discovery means the grep automatically picks up new workspace packages
 * (e.g. future stores/adapters) without a code change here.
 */
function discoverPackageSrcDirs(repoRoot: string): string[] {
  const root = join(repoRoot, "packages")
  const out: string[] = []
  let entries: string[]
  try {
    entries = readdirSync(root)
  } catch {
    return out
  }
  for (const entry of entries) {
    const src = join(root, entry, "src")
    try {
      if (statSync(src).isDirectory()) out.push(src)
    } catch {
      // No src/ in this package — skip.
    }
  }
  return out
}

function findOffences(repoRoot: string): Offence[] {
  const files: string[] = []
  for (const dir of discoverPackageSrcDirs(repoRoot)) {
    walk(dir, files)
  }

  const offences: Offence[] = []
  for (const file of files) {
    const content = readFileSync(file, "utf8")
    const lines = content.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? ""
      if (isCommentLine(raw)) continue
      // Strip safe sub-expressions so a mixed line is still flagged on its
      // unsafe portion.
      const stripped = stripSafeEquality(raw)
      if (!/===|!==/.test(stripped)) continue
      for (const id of SECRET_IDENTIFIERS) {
        if (!stripped.includes(id)) continue
        offences.push({
          file: relative(repoRoot, file),
          line: i + 1,
          text: raw.trim(),
          identifier: id,
        })
      }
    }
  }
  return offences
}

describe("constant-time secret comparison (spec §14)", () => {
  it("never uses === / !== on a secret-bearing identifier", () => {
    // Tests run with cwd = monorepo root (vitest config at repo root).
    const repoRoot = process.cwd()
    const offences = findOffences(repoRoot)
    if (offences.length > 0) {
      const report = offences
        .map((o) => `  ${o.file}:${o.line}  [${o.identifier}]  ${o.text}`)
        .join("\n")
      throw new Error(
        `Secret equality must use crypto.timingSafeEqual (spec §14). ` +
          `Found ${offences.length} offending line(s):\n${report}`,
      )
    }
    expect(offences).toEqual([])
  })
})
