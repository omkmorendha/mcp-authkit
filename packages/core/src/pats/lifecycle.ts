/**
 * PAT lifecycle: mint, lookup, list, revoke, rotate, touch-last-used.
 *
 * Pure orchestration over the {@link TokenStore} interface plus the format
 * helpers in {@link ./format.ts}. No transport concerns — HTTP routes that
 * surface these operations live in Stage 2 adapter packages.
 *
 * Spec anchors:
 *   - docs/spec/v0.1.md#82-storage
 *   - docs/spec/v0.1.md#83-rest-endpoints-consumer-mounted (lifecycle semantics)
 *   - docs/spec/v0.1.md#84-scope-constraint-at-validation
 *   - docs/spec/v0.1.md#85-expiry
 *   - docs/spec/v0.1.md#14-security-non-negotiables
 *
 * @module
 */
import { timingSafeEqual } from "node:crypto"
import type { Logger } from "pino"
import { intersect, normalize } from "../scopes/index.js"
import type {
  AuditEvent,
  CreatePatInput,
  StoredPat,
  StoredPatPublic,
  TokenStore,
} from "../types.js"
import { mintPat } from "./format.js"

/** Config subset relevant to lifecycle operations. */
export interface PatLifecycleConfig {
  /** Token prefix, e.g. "mcp_pat_". */
  readonly prefix: string
  /** Expiry default when the request omits `expiresInDays`. */
  readonly defaultExpiryDays: number
  /** Hard upper bound on `expiresInDays`. */
  readonly maxExpiryDays: number
  /** Seconds the rotated-out PAT remains valid. 0 = revoke immediately. */
  readonly rotationGraceSeconds: number
}

export interface CreatePatRequest {
  readonly userIdentifier: string
  readonly name: string
  readonly scopes: readonly string[]
  /** Optional override; must be in [1, maxExpiryDays]. */
  readonly expiresInDays?: number
}

export interface CreatePatResult {
  /** Plaintext token. Surface to the user exactly once; never persist. */
  readonly token: string
  readonly stored: StoredPat
}

export interface ResolvedPat {
  readonly stored: StoredPat
  /**
   * Scopes after intersection with the current `resolveUserScopes` result.
   * Spec §8.4 — revoking a user grant immediately shrinks live PATs.
   */
  readonly effectiveScopes: readonly string[]
}

export type AuditSink = (event: AuditEvent) => void | Promise<void>

export type PatLifecycleErrorCode = "expiry_out_of_range"

export class PatLifecycleError extends Error {
  readonly code: PatLifecycleErrorCode
  constructor(code: PatLifecycleErrorCode, message: string) {
    super(message)
    this.name = "PatLifecycleError"
    this.code = code
  }
}

export interface LifecycleOptions {
  readonly now?: () => Date
  readonly logger?: Logger
  readonly audit?: AuditSink
}

/** First 4 chars of the random portion, hidden middle, last 4 of checksum. */
function buildDisplay(prefix: string, token: string): string {
  // token = prefix + random(43) + "_" + checksum(6)
  const body = token.slice(prefix.length)
  const sep = body.lastIndexOf("_")
  const random = body.slice(0, sep)
  const checksum = body.slice(sep + 1)
  return `${prefix}${random.slice(0, 4)}…${checksum.slice(-4)}`
}

async function emit(audit: AuditSink | undefined, event: AuditEvent): Promise<void> {
  if (!audit) return
  await audit(event)
}

/**
 * Mint a new PAT. Returns the plaintext token (show once) and the stored row.
 *
 * Throws {@link PatLifecycleError} with code `expiry_out_of_range` if a
 * caller-supplied `expiresInDays` is below 1 or above `maxExpiryDays`.
 */
export async function createPat(
  store: TokenStore,
  config: PatLifecycleConfig,
  req: CreatePatRequest,
  options: LifecycleOptions = {},
): Promise<CreatePatResult> {
  const now = options.now?.() ?? new Date()
  const days = req.expiresInDays ?? config.defaultExpiryDays
  if (!Number.isInteger(days) || days < 1 || days > config.maxExpiryDays) {
    throw new PatLifecycleError(
      "expiry_out_of_range",
      `expiresInDays must be an integer in [1, ${config.maxExpiryDays}]`,
    )
  }
  const expiresAt = new Date(now.getTime() + days * 24 * 60 * 60 * 1000)

  const minted = mintPat(config.prefix)
  const input: CreatePatInput = {
    userIdentifier: req.userIdentifier,
    name: req.name,
    scopes: normalize(req.scopes),
    expiresAt,
    tokenHash: minted.tokenHash,
    display: buildDisplay(config.prefix, minted.token),
  }
  const stored = await store.createPat(input)
  await emit(options.audit, {
    type: "pat.mint",
    at: now,
    subject: stored.userIdentifier,
    tokenId: stored.id,
    detail: { name: stored.name, scopes: stored.scopes, expiresAt: stored.expiresAt },
  })
  return { token: minted.token, stored }
}

/**
 * Look up a PAT by SHA-256 hash. Returns null for unknown, revoked, or
 * expired rows. On hit, computes effective scopes by intersecting the
 * stamped scopes with `resolveUserScopes(subject)` — spec §8.4.
 *
 * The lookup itself is delegated to the store; the byte equality between
 * the presented hash and the stored hash is reconfirmed via
 * `crypto.timingSafeEqual` (CLAUDE.md §2) before returning a hit.
 *
 * This function does NOT emit `pat.use` and does NOT touch `lastUsedAt` —
 * those belong to the request-handling pipeline (call
 * {@link updatePatLastUsed} after a successful validation).
 */
export async function findPatByHash(
  store: TokenStore,
  hash: Buffer,
  resolveUserScopes: (subject: string) => Promise<readonly string[]>,
  options: { readonly now?: () => Date } = {},
): Promise<ResolvedPat | null> {
  const stored = await store.findPatByHash(hash)
  if (!stored) return null

  // Constant-time confirm the store returned the right row.
  if (stored.tokenHash.length !== hash.length) return null
  if (!timingSafeEqual(stored.tokenHash, hash)) return null

  const now = options.now?.() ?? new Date()
  if (stored.revokedAt !== null && stored.revokedAt.getTime() <= now.getTime()) return null
  if (stored.expiresAt.getTime() <= now.getTime()) return null

  const userScopes = await resolveUserScopes(stored.userIdentifier)
  const effectiveScopes = intersect(stored.scopes, userScopes)
  return { stored, effectiveScopes }
}

/** List the caller's PATs (public projection — no secrets). */
export async function listPats(
  store: TokenStore,
  userIdentifier: string,
): Promise<StoredPatPublic[]> {
  return store.listPatsByUser(userIdentifier)
}

/**
 * Revoke a PAT. Idempotent: re-revoking a row already revoked is a no-op
 * (no error). The store implementation is responsible for that semantics;
 * callers may rely on it.
 */
export async function revokePat(
  store: TokenStore,
  id: string,
  userIdentifier: string,
  options: LifecycleOptions = {},
): Promise<void> {
  await store.revokePat(id, userIdentifier)
  await emit(options.audit, {
    type: "pat.revoke",
    at: options.now?.() ?? new Date(),
    subject: userIdentifier,
    tokenId: id,
    detail: {},
  })
}

/**
 * Rotate a PAT: mint a new one with the same scopes and expiry-from-now
 * (per `defaultExpiryDays`). The previous PAT is scheduled for revocation
 * after `rotationGraceSeconds`. When grace is 0, revocation is immediate.
 *
 * The grace-window timer is best-effort and unref'd; in long-running
 * processes it lets clients refresh in-flight. Servers that restart inside
 * the grace window will leave the old PAT live until its expiry — that's
 * acceptable; the new PAT also exists so callers can switch.
 */
export async function rotatePat(
  store: TokenStore,
  config: PatLifecycleConfig,
  id: string,
  userIdentifier: string,
  options: LifecycleOptions = {},
): Promise<CreatePatResult> {
  const now = options.now?.() ?? new Date()

  // We need the existing row to copy name + scopes. listPatsByUser returns
  // the public projection which includes scopes and name.
  const current = (await store.listPatsByUser(userIdentifier)).find((p) => p.id === id)
  if (!current) {
    // Defer to the store's own behavior on missing — call rotatePat anyway?
    // Simpler: throw a generic Error; this is an internal logic error since
    // the REST handler (Stage 2) does the 404 mapping.
    throw new Error(`PAT not found: ${id}`)
  }

  const expiresAt = new Date(now.getTime() + config.defaultExpiryDays * 24 * 60 * 60 * 1000)
  const minted = mintPat(config.prefix)
  const nextInput: CreatePatInput = {
    userIdentifier,
    name: current.name,
    scopes: normalize(current.scopes),
    expiresAt,
    tokenHash: minted.tokenHash,
    display: buildDisplay(config.prefix, minted.token),
  }

  const newStored = await store.rotatePat(id, userIdentifier, nextInput)

  if (config.rotationGraceSeconds <= 0) {
    await store.revokePat(id, userIdentifier)
  } else {
    const handle = setTimeout(() => {
      void store.revokePat(id, userIdentifier).catch((err: unknown) => {
        options.logger?.warn({ err, patId: id }, "deferred revocation of rotated PAT failed")
      })
    }, config.rotationGraceSeconds * 1000)
    handle.unref?.()
  }

  await emit(options.audit, {
    type: "pat.rotate",
    at: now,
    subject: userIdentifier,
    tokenId: newStored.id,
    detail: { previousId: id, graceSeconds: config.rotationGraceSeconds },
  })

  return { token: minted.token, stored: newStored }
}

/**
 * Best-effort update of `lastUsedAt`. Never throws to the caller — store
 * failures are warned and swallowed. Spec §9 step 3 ("update lastUsedAt
 * best-effort, non-blocking").
 */
export async function updatePatLastUsed(
  store: TokenStore,
  id: string,
  timestamp: Date,
  options: { readonly logger?: Logger } = {},
): Promise<void> {
  try {
    await store.updatePatLastUsed(id, timestamp)
  } catch (err) {
    options.logger?.warn({ err, patId: id }, "updatePatLastUsed failed")
  }
}
