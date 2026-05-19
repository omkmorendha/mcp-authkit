#!/usr/bin/env node
/**
 * Bin entry for the `mcp-authkit` command.
 *
 * Delegates to `run()` and translates the resolved exit code to
 * `process.exit`. The wrapper is intentionally tiny so the testable surface
 * lives in `run.ts`.
 */
import { run } from "../run.js"

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
