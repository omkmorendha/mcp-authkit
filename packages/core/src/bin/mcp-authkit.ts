#!/usr/bin/env node
/**
 * Bin entry for the `mcp-authkit` command, published from the primary
 * `mcp-authkit` package.
 *
 * Installing `mcp-authkit` as a direct dependency makes `pnpm exec
 * mcp-authkit ...` (and the equivalent for npm/yarn) work without the
 * caller having to add `mcp-authkit-cli` to their package.json. The
 * CLI's `bin` of the same name remains for callers who depend on the
 * CLI package directly; both bins delegate to the same `run()` so
 * behavior is identical regardless of which the package manager links.
 *
 * Spec: docs/spec/v0.2.md#57-cli, docs/spec/v0.2.md#9-cli-behavior-details
 */
import { run } from "mcp-authkit-cli"

run().then(
  (code) => {
    process.exit(code)
  },
  (err: unknown) => {
    const message = err instanceof Error ? err.message : String(err)
    process.stderr.write(`error: ${message}\n`)
    process.exit(3)
  },
)
