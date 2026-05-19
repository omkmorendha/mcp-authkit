/**
 * Scope vocabulary and matching engine (spec §7).
 *
 * Exports both named functions and a `scope` namespace object for the
 * `mcp-authkit` entrypoint (spec §6.3, §7.6).
 */

import { expand } from "./expand.js"
import { matchesAny, scopeMatches } from "./matcher.js"
import { satisfies } from "./satisfies.js"
import { intersect, normalize, subtract } from "./set.js"

export { expand } from "./expand.js"
export { matchesAny, scopeMatches } from "./matcher.js"
export { satisfies } from "./satisfies.js"
export { intersect, normalize, subtract } from "./set.js"

export const scope = {
  intersect,
  subtract,
  normalize,
  expand,
  matches: scopeMatches,
  matchesAny,
  satisfies,
} as const
