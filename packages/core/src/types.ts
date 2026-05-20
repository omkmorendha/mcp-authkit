import type { IncomingMessage, ServerResponse } from "node:http"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { Logger } from "pino"
import type { z } from "zod"

export interface AuthContext {
  /** Stable user identifier from the token (sub claim, or PAT owner). */
  subject: string
  /** Token kind, useful for audit and conditional logic. */
  tokenType: "oauth" | "pat" | "bypass" | "static"
  /** Opaque token id; for OAuth this is jti, for PAT it's the store row id. */
  tokenId: string
  /** Effective scopes after PAT-vs-user intersection. Always normalized. */
  scopes: readonly string[]
  /** Token expiry; null only in bypass / static-token modes. */
  expiresAt: Date | null
  /** Raw claims for OAuth (jwt payload) or PAT metadata. */
  raw: Record<string, unknown>
}

export interface CreatePatInput {
  userIdentifier: string
  name: string
  scopes: readonly string[]
  expiresAt: Date
  /** SHA-256 of the token, computed by the framework. */
  tokenHash: Buffer
  /** Prefix + first/last chars for display; never the full token. */
  display: string
}

export interface StoredPat extends CreatePatInput {
  id: string
  createdAt: Date
  lastUsedAt: Date | null
  revokedAt: Date | null
}

export interface StoredPatPublic {
  id: string
  name: string
  scopes: readonly string[]
  display: string
  createdAt: Date
  expiresAt: Date
  lastUsedAt: Date | null
}

export interface CreateRefreshTokenInput {
  familyId: string
  tokenHash: Buffer
  subject: string
  scopes: readonly string[]
  expiresAt: Date
}

export interface StoredRefreshToken extends CreateRefreshTokenInput {
  id: string
  createdAt: Date
  rotatedAt: Date | null
}

export interface TokenStore {
  createPat(input: CreatePatInput): Promise<StoredPat>
  findPatByHash(hash: Buffer): Promise<StoredPat | null>
  listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]>
  revokePat(id: string, userIdentifier: string): Promise<void>
  rotatePat(id: string, userIdentifier: string, next: CreatePatInput): Promise<StoredPat>
  updatePatLastUsed(id: string, timestamp: Date): Promise<void>

  createRefreshToken(input: CreateRefreshTokenInput): Promise<void>
  findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null>
  rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void>
  revokeRefreshTokenFamily(familyId: string): Promise<void>

  init?(): Promise<void>
  close?(): Promise<void>
}

export type ScopeMatcher = (
  required: string,
  held: readonly string[],
  ctx: { auth: AuthContext; input: unknown },
) => boolean | Promise<boolean>

export interface ScopeVocabularyEntry {
  /** Human description for UIs and docs. */
  description: string
  /**
   * Optional parameter name. If present, the scope is a template:
   * the effective scope is `<key>:<param-value>` at runtime.
   */
  resource?: string
  /**
   * Other scope keys this one implies. Holder of this scope is treated
   * as also holding the implied scopes.
   */
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

export interface AuthKitConfig {
  /** RFC 8707 audience for tokens accepted by this server. */
  resourceIndicator: string

  auth: {
    /**
     * Authorization server config for OAuth token validation.
     * Optional when using bypass mode or stdio auto-enable (spec §11.2):
     * if absent and transport is stdio, bypass activates automatically.
     */
    authorizationServer?: {
      issuer: string
      jwksUri: string
      /** Optional; used for RFC 7662 introspection of opaque AS tokens. */
      introspectionEndpoint?: string
      /** ms; default 3_600_000 (1h). */
      jwksCacheTtlMs?: number
    }
    tokenStore: TokenStore
    pat: {
      enabled: boolean
      /** Token prefix, e.g. "mcp_pat_". Required if enabled. */
      prefix?: string
      defaultExpiryDays?: number
      maxExpiryDays?: number
      /** Grace period for rotated PATs, in seconds. Default 0. */
      rotationGraceSeconds?: number
    }
    bypass?: {
      enabled: boolean
      user: string
      scopes: readonly string[]
      /** Required to enable when NODE_ENV === "production". */
      allowInProduction?: boolean
    }
    /** Single env-var token for stdio / CI. Treated as a synthetic PAT. */
    staticToken?: {
      token: string
      user: string
      scopes: readonly string[]
    }
    /**
     * Production stdio transport (spec v0.2 §11). Opt-in; when present,
     * the framework HMAC-signs every response and verifies every inbound
     * frame. Bypass mode is REFUSED when this is set. Only the static
     * token or PATs authenticate inside signed stdio.
     */
    stdio?: {
      mode: "signed"
      hmacKey: Buffer | string
    }
  }

  scopes: {
    vocabulary: ScopeVocabulary
    /** Custom matchers for rules the string system can't express. */
    customMatchers?: readonly ScopeMatcher[]
  }

  /**
   * Returns the user's currently-granted scope set. Called on every PAT
   * validation to compute the effective intersection.
   */
  resolveUserScopes: (userIdentifier: string) => Promise<readonly string[]>

  /** Optional pino instance; one is created if absent. */
  logger?: Logger

  /** Audit hooks. Awaited; throw to abort the triggering operation. */
  audit?: {
    onEvent?: (event: AuditEvent) => void | Promise<void>
  }

  /**
   * HTTP-level configuration shared across all handlers.
   *
   * Spec §14 mandates DNS-rebinding protection (Host header validation) on
   * by default with a configurable allowlist. When `allowedHosts` is
   * omitted, the host of `resourceIndicator` is used. Pass an empty array
   * to disable explicitly (NOT recommended).
   */
  http?: {
    allowedHosts?: readonly string[]
  }
}

export interface RegisterToolOptions<I extends z.ZodRawShape> {
  name: string
  description: string
  inputSchema: I
  /**
   * Either a static list or a function of the call. The function form is
   * what makes per-input scope policy expressible.
   */
  requireScopes:
    | readonly string[]
    | ((args: {
        input: z.infer<z.ZodObject<I>>
        auth: AuthContext
      }) => readonly string[] | Promise<readonly string[]>)
  handler: (args: {
    input: z.infer<z.ZodObject<I>>
    auth: AuthContext
  }) => Promise<{ content: Array<{ type: "text"; text: string }> }>
}

export interface Handlers {
  /** Mount as the MCP request handler. */
  mcp: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  /** RFC 9728 protected resource metadata. */
  metadata: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  /** PAT REST endpoints. Routes: POST /, GET /, DELETE /:id, POST /:id/rotate. */
  pats: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  /** Build a 401 challenge with the right WWW-Authenticate header. */
  challenge: (res: ServerResponse, reason?: string) => void
}

export interface AuthKit {
  registerTool<I extends z.ZodRawShape>(mcp: McpServer, options: RegisterToolOptions<I>): void
  handlers(mcp: McpServer): Handlers
}

export { createAuthKit } from "./authkit.js"
