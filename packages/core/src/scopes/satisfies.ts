import type { AuthContext, ScopeMatcher } from "../types.js"
import { assertRequiredScope, matchesAny } from "./matcher.js"

/**
 * Decide whether a required scope is satisfied by the held scope set,
 * combining the built-in string matcher with optional custom matchers
 * (spec §7.5).
 *
 * The string matcher is tried first; if it does not approve, each custom
 * matcher is tried in order. Custom matchers may be sync or async; the
 * first one that returns true wins.
 */
export async function satisfies(
  required: string,
  held: readonly string[],
  ctx: { auth: AuthContext; input: unknown },
  customMatchers: readonly ScopeMatcher[] = [],
): Promise<boolean> {
  assertRequiredScope(required)
  if (matchesAny(required, held)) return true
  for (const matcher of customMatchers) {
    if (await matcher(required, held, ctx)) return true
  }
  return false
}
