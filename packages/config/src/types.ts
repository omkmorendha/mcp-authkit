/**
 * Public types for the config package.
 *
 * Mirrors `AuthKitConfig` from `packages/core/src/types.ts` so the config
 * package can stay free of a core dependency (core depends transitively on
 * stores and adapters; introducing the reverse edge here would cycle).
 *
 * The structural match is enforced by core re-exporting `defineConfig` from
 * `mcp-authkit/config`: TypeScript checks the call site against the core
 * `AuthKitConfig`. Any drift between this file and
 * `packages/core/src/types.ts` is a spec violation.
 *
 * Spec: docs/spec/v0.1.md#61-core-types-this-is-the-contract
 *       docs/spec/v0.2.md#58-config-file-format
 */
import type { TokenStore } from "mcp-authkit-store-memory"

export interface AuthContextLike {
  subject: string
  tokenType: "oauth" | "pat" | "bypass" | "static"
  tokenId: string
  scopes: readonly string[]
  expiresAt: Date | null
  raw: Record<string, unknown>
}

export type ScopeMatcher = (
  required: string,
  held: readonly string[],
  ctx: { auth: AuthContextLike; input: unknown },
) => boolean | Promise<boolean>

export interface ScopeVocabularyEntry {
  description: string
  resource?: string
  implies?: readonly string[]
}

export type ScopeVocabulary = Record<string, ScopeVocabularyEntry>

export interface AuditEvent {
  type:
    | "pat.mint"
    | "pat.use"
    | "pat.revoke"
    | "pat.rotate"
    | "oauth.validate"
    | "oauth.reject"
    | "scope.allow"
    | "scope.deny"
  at: Date
  subject: string | null
  tokenId: string | null
  detail: Record<string, unknown>
}

/**
 * `pino`'s `Logger` is structurally large; the config loader only needs to
 * know the slot exists. The core `AuthKitConfig.logger` field types as
 * `Logger` from `pino`, but at the config-file boundary we accept `unknown`
 * and rely on core's type system to verify when `createAuthKit` is called.
 */
export type LoggerLike = unknown

export interface AuthKitConfig {
  resourceIndicator: string
  auth: {
    authorizationServer?: {
      issuer: string
      jwksUri: string
      introspectionEndpoint?: string
      jwksCacheTtlMs?: number
    }
    tokenStore: TokenStore
    pat: {
      enabled: boolean
      prefix?: string
      defaultExpiryDays?: number
      maxExpiryDays?: number
      rotationGraceSeconds?: number
    }
    bypass?: {
      enabled: boolean
      user: string
      scopes: readonly string[]
      allowInProduction?: boolean
    }
    staticToken?: {
      token: string
      user: string
      scopes: readonly string[]
    }
  }
  scopes: {
    vocabulary: ScopeVocabulary
    customMatchers?: readonly ScopeMatcher[]
  }
  resolveUserScopes: (userIdentifier: string) => Promise<readonly string[]>
  logger?: LoggerLike
  audit?: {
    onEvent?: (event: AuditEvent) => void | Promise<void>
  }
  http?: {
    allowedHosts?: readonly string[]
  }
}
