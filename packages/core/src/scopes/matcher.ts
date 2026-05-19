/**
 * String-level scope matcher.
 *
 * A scope is a colon-delimited string `<namespace>:<operation>[:<resource>...]`
 * (spec §7). The required scope is always a concrete literal — wildcards in a
 * required scope are rejected with `TypeError` to prevent a buggy policy
 * callback from accidentally granting itself permissions.
 *
 * In the *held* scope, `*` matches exactly one segment and `**` matches one or
 * more segments. Wildcards are only honored at or after the third segment
 * (resource position) — a literal `*` or `**` appearing in the namespace or
 * operation position is matched as a literal byte string, never as a
 * wildcard (spec §7.2).
 */

const WILDCARD_ONE = "*"
const WILDCARD_MANY = "**"

/** Position (0-indexed) at or after which wildcards are honored. */
const FIRST_WILDCARD_POSITION = 2

/**
 * Throws `TypeError` if `scope` is not a syntactically valid scope string for
 * use as a *required* scope (no wildcards, at least namespace + operation).
 */
export function assertRequiredScope(scope: string): void {
  if (typeof scope !== "string" || scope.length === 0) {
    throw new TypeError("scope must be a non-empty string")
  }
  const segments = scope.split(":")
  if (segments.length < 2) {
    throw new TypeError(`scope "${scope}" must have at least namespace and operation segments`)
  }
  for (const seg of segments) {
    if (seg.length === 0) {
      throw new TypeError(`scope "${scope}" contains an empty segment`)
    }
    if (seg === WILDCARD_ONE || seg === WILDCARD_MANY) {
      throw new TypeError(`required scope "${scope}" may not contain wildcards`)
    }
  }
}

/**
 * Throws `TypeError` if `scope` is not a syntactically valid scope string.
 * Held scopes may contain wildcards at or after the resource position.
 */
export function assertHeldScope(scope: string): void {
  if (typeof scope !== "string" || scope.length === 0) {
    throw new TypeError("scope must be a non-empty string")
  }
  const segments = scope.split(":")
  if (segments.length < 2) {
    throw new TypeError(`scope "${scope}" must have at least namespace and operation segments`)
  }
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i] as string
    if (seg.length === 0) {
      throw new TypeError(`scope "${scope}" contains an empty segment`)
    }
  }
}

/**
 * Returns true iff `held` satisfies `required`.
 *
 * Both arguments must be syntactically valid scope strings; pass them through
 * `assertRequiredScope` / `assertHeldScope` first if you can't trust the
 * source.
 */
export function scopeMatches(required: string, held: string): boolean {
  if (required === held) return true

  const req = required.split(":")
  const hld = held.split(":")

  return walkMatch(req, hld, 0, 0)
}

function walkMatch(
  req: readonly string[],
  hld: readonly string[],
  ri: number,
  hi: number,
): boolean {
  // Advance segment-by-segment. Wildcards in `hld` are only honored at
  // positions >= FIRST_WILDCARD_POSITION.
  while (hi < hld.length) {
    const hSeg = hld[hi] as string
    const wildcardsHonored = hi >= FIRST_WILDCARD_POSITION

    // `**` is only meaningful as the final segment of the held pattern.
    // Spec §7.2 defines `**` as "one or more segments"; restricting it to
    // the trailing position keeps the semantics unambiguous. A mid-pattern
    // `**` is matched literally (and therefore will not match any
    // syntactically valid required scope).
    if (wildcardsHonored && hSeg === WILDCARD_MANY && hi === hld.length - 1) {
      return req.length - ri >= 1
    }

    if (ri >= req.length) return false
    const rSeg = req[ri] as string

    if (wildcardsHonored && hSeg === WILDCARD_ONE) {
      // matches exactly one segment
    } else if (hSeg !== rSeg) {
      return false
    }
    ri++
    hi++
  }
  return ri === req.length
}

/**
 * Returns true iff at least one scope in `held` satisfies `required`.
 *
 * Held scopes that are syntactically invalid are skipped silently — the
 * normalization step is responsible for rejecting malformed input before it
 * reaches the matcher. Callers that have not normalized should validate
 * explicitly first.
 */
export function matchesAny(required: string, held: readonly string[]): boolean {
  for (const h of held) {
    if (scopeMatches(required, h)) return true
  }
  return false
}
