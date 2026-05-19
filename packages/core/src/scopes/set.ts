import { assertHeldScope } from "./matcher.js"

/**
 * Validate, dedupe, and stably sort a scope set.
 *
 * Throws `TypeError` on malformed input. The returned array is frozen to
 * make accidental mutation a type error in strict mode.
 */
export function normalize(scopes: readonly string[]): readonly string[] {
  const seen = new Set<string>()
  for (const s of scopes) {
    assertHeldScope(s)
    seen.add(s)
  }
  return Object.freeze([...seen].sort())
}

/**
 * Set intersection by exact string equality. Both inputs are normalized
 * first; the result is normalized.
 *
 * Note: intersection is *string-level*, not match-level — `db:select:*`
 * and `db:select:foo` do NOT intersect to anything. This matches how PAT
 * minting will use it (the held set and the user's granted set are both
 * literal scope sets; wildcards live in policy, not in storage).
 */
export function intersect(a: readonly string[], b: readonly string[]): readonly string[] {
  const left = new Set(normalize(a))
  const out: string[] = []
  for (const s of normalize(b)) {
    if (left.has(s)) out.push(s)
  }
  return Object.freeze(out)
}

/**
 * Set difference: scopes in `a` that are not in `b`. Inputs are
 * normalized; the result is normalized.
 */
export function subtract(a: readonly string[], b: readonly string[]): readonly string[] {
  const remove = new Set(normalize(b))
  const out: string[] = []
  for (const s of normalize(a)) {
    if (!remove.has(s)) out.push(s)
  }
  return Object.freeze(out)
}
