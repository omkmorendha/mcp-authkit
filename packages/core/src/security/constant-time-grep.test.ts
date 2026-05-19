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

// Lines that legitimately compare these names against `null`, `undefined`, or
// `length` are not secret-equality. We strip those before searching.
const SAFE_OPERATORS = [/===\s*null/, /!==\s*null/, /===\s*undefined/, /!==\s*undefined/]

function shouldSkipLine(line: string): boolean {
  // Comments and JSDoc are fine.
  const trimmed = line.trim()
  if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
    return true
  }
  // Whitelist null/undefined/length comparisons — those aren't secret equality.
  for (const safe of SAFE_OPERATORS) {
    if (safe.test(line)) return true
  }
  // `.length ===` or `.length !==` is a length check, not a value compare.
  if (/\.length\s*[!=]==/.test(line)) return true
  return false
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

function findOffences(repoRoot: string): Offence[] {
  const packages = [
    "packages/core/src",
    "packages/store-memory/src",
    "packages/adapter-express/src",
  ]
  const files: string[] = []
  for (const pkg of packages) {
    const abs = join(repoRoot, pkg)
    try {
      walk(abs, files)
    } catch {
      // Package may not exist in this branch — skip.
    }
  }

  const offences: Offence[] = []
  for (const file of files) {
    const content = readFileSync(file, "utf8")
    const lines = content.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? ""
      if (shouldSkipLine(line)) continue
      for (const id of SECRET_IDENTIFIERS) {
        if (!line.includes(id)) continue
        // Look for `===` or `!==` on the same line.
        if (!/===|!==/.test(line)) continue
        offences.push({
          file: relative(repoRoot, file),
          line: i + 1,
          text: line.trim(),
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
