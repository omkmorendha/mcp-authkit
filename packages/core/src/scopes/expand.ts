import type { ScopeVocabulary } from "../types.js"
import { assertHeldScope } from "./matcher.js"

/**
 * Resolve `implies` transitively against the vocabulary (spec §7.3, §7.6).
 *
 * For each held scope, look up the vocabulary entry by its key (first two
 * segments: `<namespace>:<operation>`). If the entry has `implies`, emit
 * those implied keys with the same trailing segments as the original
 * scope, then recurse. Cycles are detected and terminate.
 *
 * The result is sorted, deduplicated, and frozen.
 */
export function expand(scopes: readonly string[], vocabulary: ScopeVocabulary): readonly string[] {
  const out = new Set<string>()
  for (const s of scopes) {
    assertHeldScope(s)
    expandOne(s, vocabulary, out)
  }
  return Object.freeze([...out].sort())
}

function expandOne(scope: string, vocabulary: ScopeVocabulary, out: Set<string>): void {
  if (out.has(scope)) return
  out.add(scope)

  const segments = scope.split(":")
  // Vocabulary keys are `<namespace>:<operation>`. Look up the first two
  // segments; preserve any trailing segments for the implied scopes.
  const key = `${segments[0]}:${segments[1]}`
  const trailing = segments.slice(2)

  const entry = vocabulary[key]
  if (!entry?.implies) return

  for (const impliedKey of entry.implies) {
    const implied = trailing.length > 0 ? `${impliedKey}:${trailing.join(":")}` : impliedKey
    expandOne(implied, vocabulary, out)
  }
}
