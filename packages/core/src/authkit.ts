/**
 * `createAuthKit` factory — token validation pipeline and scope-gate.
 *
 * Spec: docs/spec/v0.1.md#9-token-validation-pipeline
 *       docs/spec/v0.1.md#12-audit-callbacks
 *       docs/spec/v0.1.md#14-security-non-negotiables
 *
 * @module
 */
import { AsyncLocalStorage } from "node:async_hooks"
import { createHash, timingSafeEqual } from "node:crypto"
import type { IncomingMessage } from "node:http"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import pino from "pino"
import { z } from "zod"
import { type AuditSink, dispatchAudit } from "./audit/index.js"
import { createIntrospectionValidator } from "./auth/introspection.js"
import { createJwksRegistry, type JwksRegistry } from "./auth/jwt.js"
import { resolveAuthorizationServer } from "./auth/tenant.js"
import {
  checkBypassConfig,
  synthesizeBypassContext,
  synthesizeStaticContext,
} from "./bypass/index.js"
import { metadataUrlFor, writeChallenge } from "./handlers/challenge.js"
import { type HostValidationOptions, hostFromResourceIndicator } from "./handlers/host.js"
import { createMcpHandler } from "./handlers/mcp.js"
import { createMetadataHandler } from "./handlers/metadata.js"
import { createPatsHandler } from "./handlers/pats.js"
import { findPatByHash, type PatLifecycleConfig, updatePatLastUsed } from "./pats/lifecycle.js"
import { satisfies } from "./scopes/satisfies.js"
import { checkSignedStdioConfig } from "./stdio/index.js"
import type {
  AuthContext,
  AuthKit,
  AuthKitConfig,
  AuthorizationServerConfig,
  Handlers,
  RegisterToolOptions,
  UpstreamCredential,
  UpstreamForArgs,
} from "./types.js"
import { createUpstreamFor } from "./upstream/index.js"

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Internal pipeline result — not part of the public API.
 *
 * `kind` on the failure branch lets HTTP handlers distinguish a token-level
 * 401 (`kind: "unauthorized"`, the default) from a server-side failure to
 * resolve the authorization server (`kind: "server-error"`) which spec v0.2
 * §7 requires to surface as HTTP 503, not 401.
 */
export type PipelineResult =
  | { ok: true; auth: AuthContext }
  | { ok: false; reason: string; kind?: "unauthorized" | "server-error" }

/**
 * Extract the Bearer token from an Authorization header value.
 * Returns null if the header is absent or not a Bearer token.
 */
export function extractBearer(authHeader: string | undefined): string | null {
  if (!authHeader) return null
  const match = /^Bearer\s+(\S+)$/i.exec(authHeader)
  return match?.[1] ?? null
}

/**
 * True if the token looks like a compact JWS (three non-empty segments
 * separated by dots). Structural heuristic only; the JWT validator verifies.
 */
export function looksLikeJwt(token: string): boolean {
  const parts = token.split(".")
  return parts.length === 3 && parts.every((p) => p.length > 0)
}

/**
 * Constant-time comparison for two strings (spec §14).
 *
 * Encodes both as UTF-8 and uses `crypto.timingSafeEqual`. When lengths
 * differ, a dummy comparison still runs so runtime is not a function of
 * attacker-supplied input length. Always returns false on mismatch.
 */
export function timingSafeStringEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8")
  const bBuf = Buffer.from(b, "utf8")
  if (aBuf.length !== bBuf.length) {
    // Run a dummy comparison to prevent length-based timing leaks.
    const dummy = Buffer.alloc(aBuf.length, 0)
    timingSafeEqual(dummy, dummy)
    return false
  }
  return timingSafeEqual(aBuf, bBuf)
}

/**
 * Select the authorization server config visible to {@link runPipeline}.
 *
 * - Static-object form: returned as-is.
 * - Function form: requires the caller (typically an HTTP handler) to have
 *   pre-resolved the AS and passed it in `extras.resolvedAuthorizationServer`.
 *   Spec v0.2 §7 puts tenant resolution BEFORE token parsing, so this
 *   function never invokes the consumer's resolver itself.
 *
 * Returns `null` when no AS is available — either because the config has
 * none (bypass-only deployments) or because the caller forgot to pre-resolve
 * a function-form config (a programmer error; pipeline degrades to 401).
 */
function resolveAsForPipeline(
  config: AuthKitConfig,
  extras: RunPipelineExtras | undefined,
): AuthorizationServerConfig | null {
  if (extras?.resolvedAuthorizationServer !== undefined) {
    return extras.resolvedAuthorizationServer
  }
  const spec = config.auth.authorizationServer
  if (spec === undefined) return null
  if (typeof spec === "function") return null
  return spec
}

// ---------------------------------------------------------------------------
// Six-step validation pipeline (spec §9)
// ---------------------------------------------------------------------------

/**
 * Optional inputs to {@link runPipeline}. For multi-tenant deployments
 * (spec v0.2 §5.1, §7) handlers pre-resolve the AS and pass it here so the
 * pipeline can run without re-invoking the consumer's resolver mid-pipeline.
 */
export interface RunPipelineExtras {
  /**
   * Already-resolved authorization server. Required when
   * `config.auth.authorizationServer` is a function and the bearer token
   * needs JWT / introspection validation.
   */
  resolvedAuthorizationServer?: AuthorizationServerConfig
  /**
   * Issuer-keyed JWKS cache. Multi-tenant deployments share one registry
   * across requests so two tenants do not collide (spec v0.2 §7). If
   * omitted, a fresh registry is created — fine for direct unit-test use
   * but wasteful in production paths.
   */
  jwksRegistry?: JwksRegistry
}

/**
 * Run the six-step token validation pipeline for a single request.
 *
 * Returns `{ ok: true, auth }` on the first matching path, or
 * `{ ok: false, reason }` when no step authorises the request.
 *
 * The `onEvent` audit callback receives `oauth.validate`, `oauth.reject`,
 * and `pat.use` events; `scope.allow` / `scope.deny` are fired by the
 * `registerTool` scope gate, not here. The hook is awaited and any thrown
 * error propagates to the caller per spec §12.
 */
export async function runPipeline(
  config: AuthKitConfig,
  bearerToken: string | null,
  onEvent?: AuditSink,
  extras?: RunPipelineExtras,
): Promise<PipelineResult> {
  const now = new Date()

  // Step 1: Bypass mode active?
  const bypass = config.auth.bypass
  if (bypass?.enabled) {
    return { ok: true, auth: synthesizeBypassContext(bypass) }
  }

  // Step 2: Static token configured and matches (constant-time)?
  const staticToken = config.auth.staticToken
  if (staticToken !== undefined && bearerToken !== null) {
    if (timingSafeStringEqual(staticToken.token, bearerToken)) {
      return { ok: true, auth: synthesizeStaticContext(staticToken) }
    }
  }

  // Steps 3–5 require a bearer token.
  if (bearerToken === null) {
    return { ok: false, reason: "no bearer token" }
  }

  // Step 3: Bearer token has PAT prefix?
  const patConfig = config.auth.pat
  const patPrefix = patConfig.enabled ? (patConfig.prefix ?? "") : null
  if (patPrefix && bearerToken.startsWith(patPrefix)) {
    const hash = createHash("sha256").update(bearerToken).digest()
    const resolved = await findPatByHash(config.auth.tokenStore, hash, config.resolveUserScopes)
    if (resolved !== null) {
      const auth: AuthContext = {
        subject: resolved.stored.userIdentifier,
        tokenType: "pat",
        tokenId: resolved.stored.id,
        scopes: resolved.effectiveScopes,
        expiresAt: resolved.stored.expiresAt,
        raw: {
          id: resolved.stored.id,
          name: resolved.stored.name,
          display: resolved.stored.display,
          createdAt: resolved.stored.createdAt,
          lastUsedAt: resolved.stored.lastUsedAt,
        },
      }
      // Best-effort, non-blocking — never await (spec §9 step 3).
      void updatePatLastUsed(config.auth.tokenStore, resolved.stored.id, now)
      await dispatchAudit(onEvent, {
        type: "pat.use",
        at: now,
        subject: auth.subject,
        tokenId: auth.tokenId,
        detail: { scopes: auth.scopes },
      })
      return { ok: true, auth }
    }
    // PAT-shaped token the store doesn't know about — fail fast; don't try
    // JWT or introspection for PAT-prefixed tokens.
    await dispatchAudit(onEvent, {
      type: "oauth.reject",
      at: now,
      subject: null,
      tokenId: null,
      detail: { reason: "pat-not-found-or-invalid" },
    })
    return { ok: false, reason: "pat-not-found-or-invalid" }
  }

  const as = resolveAsForPipeline(config, extras)
  if (!as) {
    // No AS configured — cannot validate JWT or introspect.
    return { ok: false, reason: "no authorization server configured" }
  }

  // Per-issuer JWKS cache (spec v0.2 §7). Fresh per call only when the caller
  // didn't share one — handlers do, direct unit tests typically don't.
  const jwksRegistry = extras?.jwksRegistry ?? createJwksRegistry()

  // Step 4: Bearer token looks like JWT (3-dot structure)?
  if (looksLikeJwt(bearerToken)) {
    const validator = jwksRegistry.validator({
      issuer: as.issuer,
      audience: config.resourceIndicator,
      jwksUri: as.jwksUri,
      ...(as.jwksCacheTtlMs !== undefined ? { jwksCacheTtlMs: as.jwksCacheTtlMs } : {}),
    })
    const result = await validator.validate(bearerToken)
    if (result.ok) {
      await dispatchAudit(onEvent, {
        type: "oauth.validate",
        at: now,
        subject: result.auth.subject,
        tokenId: result.auth.tokenId,
        detail: { tokenType: "jwt" },
      })
      return { ok: true, auth: result.auth }
    }
    await dispatchAudit(onEvent, {
      type: "oauth.reject",
      at: now,
      subject: null,
      tokenId: null,
      detail: { reason: result.reason, message: result.message, tokenType: "jwt" },
    })
    // JWT-shaped token that failed validation. Fall through to introspection
    // if configured — opaque tokens can coincidentally have dots.
    if (!as.introspectionEndpoint) {
      return { ok: false, reason: `jwt-${result.reason}` }
    }
  }

  // Step 5: introspectionEndpoint configured (opaque token or failed JWT)?
  if (as.introspectionEndpoint) {
    const validator = createIntrospectionValidator({
      introspectionEndpoint: as.introspectionEndpoint,
      audience: config.resourceIndicator,
    })
    const result = await validator.validate(bearerToken)
    if (result.ok) {
      await dispatchAudit(onEvent, {
        type: "oauth.validate",
        at: now,
        subject: result.auth.subject,
        tokenId: result.auth.tokenId,
        detail: { tokenType: "introspection" },
      })
      return { ok: true, auth: result.auth }
    }
    await dispatchAudit(onEvent, {
      type: "oauth.reject",
      at: now,
      subject: null,
      tokenId: null,
      detail: { reason: result.reason, message: result.message, tokenType: "introspection" },
    })
    return { ok: false, reason: `introspection-${result.reason}` }
  }

  // Step 6: No match.
  return { ok: false, reason: "no matching auth method" }
}

/**
 * Resolve the Host-header allowlist for handlers. Falls back to the host of
 * `resourceIndicator` when not explicitly configured (spec §14).
 *
 * Throws when no allowlist is configured and the resource indicator does not
 * yield a derivable host. Falling back to an empty list would silently
 * disable DNS-rebinding protection, which spec §14 forbids.
 */
function resolveHostOptions(config: AuthKitConfig): HostValidationOptions {
  const configured = config.http?.allowedHosts
  if (configured !== undefined) return { allowedHosts: configured }
  const derived = hostFromResourceIndicator(config.resourceIndicator)
  if (derived === null) {
    throw new Error(
      `mcp-authkit: cannot derive a Host allowlist from resourceIndicator ${JSON.stringify(
        config.resourceIndicator,
      )}. Provide http.allowedHosts explicitly (pass [] only to opt out of DNS-rebinding protection).`,
    )
  }
  return { allowedHosts: [derived] }
}

/**
 * Resolve PAT lifecycle config from the `AuthKitConfig.auth.pat` block.
 * Applies spec §8.5 defaults: 90-day default expiry, 365-day cap.
 */
function resolvePatLifecycleConfig(config: AuthKitConfig): PatLifecycleConfig {
  const pat = config.auth.pat
  return {
    prefix: pat.prefix ?? "mcp_pat_",
    defaultExpiryDays: pat.defaultExpiryDays ?? 90,
    maxExpiryDays: pat.maxExpiryDays ?? 365,
    rotationGraceSeconds: pat.rotationGraceSeconds ?? 0,
  }
}

// ---------------------------------------------------------------------------
// createAuthKit
// ---------------------------------------------------------------------------

/**
 * Create an {@link AuthKit} instance bound to the given configuration.
 *
 * Throws {@link BypassProductionError} at startup if bypass mode is active in
 * a production environment without `bypass.allowInProduction: true` (spec §14).
 */
export function createAuthKit(config: AuthKitConfig): AuthKit {
  const logger = config.logger ?? pino({ level: "info" })
  const customMatchers = config.scopes.customMatchers ?? []
  const onEvent = config.audit?.onEvent

  // Validate bypass config at startup — throws BypassProductionError if unsafe.
  checkBypassConfig({ config, logger })

  // Validate signed stdio config at startup (spec v0.2 §11). Throws
  // SignedStdioConfigError if bypass is enabled alongside signed stdio, or
  // if the mode is unknown / the key is empty. Emits the loud startup warn
  // when the mode is active.
  checkSignedStdioConfig({ config, logger })

  // Resolve the Host allowlist once at startup. This throws fail-closed when
  // the resource indicator can't yield a host and the consumer didn't pass
  // http.allowedHosts explicitly — spec §14 forbids silently disabling
  // DNS-rebinding protection.
  const host = resolveHostOptions(config)

  // Process-wide JWKS cache keyed by resolved issuer (spec v0.2 §7). Shared
  // across requests so multi-tenant deployments don't re-fetch JWKS on every
  // call; isolated by issuer so two tenants don't collide.
  const jwksRegistry = createJwksRegistry()

  // AsyncLocalStorage allows the HTTP mcp handler (issue #36) to inject an
  // AuthContext into the async context so registerTool handlers can read it
  // without threading it through the MCP SDK call stack.
  const authContextStorage = new AsyncLocalStorage<AuthContext>()

  function registerTool<I extends z.ZodRawShape>(
    mcp: McpServer,
    options: RegisterToolOptions<I>,
  ): void {
    const schema = z.object(options.inputSchema)

    // biome-ignore lint/suspicious/noExplicitAny: ToolCallback generics cannot be bridged without any at this wrapper boundary
    const mcpCallback = (async (rawInput: any, extra: { authInfo?: { token?: string } }) => {
      const input = schema.parse(rawInput) as z.infer<typeof schema>

      // Prefer auth context injected by the HTTP handler via ALS (issue #36).
      // Fall back to the bearer token from the SDK's authInfo (set when the
      // MCP transport does its own auth), then no token (covers bypass/static
      // and unit tests that don't run over HTTP).
      let auth = authContextStorage.getStore()
      if (auth === undefined) {
        const bearer = extra.authInfo?.token ?? null
        const result = await runPipeline(config, bearer, onEvent)
        if (!result.ok) {
          logger.debug({ reason: result.reason }, "pipeline rejected")
          return {
            content: [{ type: "text" as const, text: "Unauthorized" }],
            isError: true,
          }
        }
        auth = result.auth
      }

      const now = new Date()

      // Resolve required scopes (static list or dynamic function).
      const required =
        typeof options.requireScopes === "function"
          ? await options.requireScopes({ input, auth })
          : options.requireScopes

      // Gate: every required scope must be satisfied (spec §7, §12).
      for (const req of required) {
        const allowed = await satisfies(req, [...auth.scopes], { auth, input }, customMatchers)
        if (!allowed) {
          await dispatchAudit(onEvent, {
            type: "scope.deny",
            at: now,
            subject: auth.subject,
            tokenId: auth.tokenId,
            detail: { tool: options.name, required: req, held: auth.scopes },
          })
          logger.debug({ tool: options.name, required: req }, "scope.deny")
          return {
            content: [{ type: "text" as const, text: `Forbidden: missing scope ${req}` }],
            isError: true,
          }
        }
      }

      // All scopes satisfied — emit allow event(s) and invoke handler (spec §12).
      for (const req of required) {
        await dispatchAudit(onEvent, {
          type: "scope.allow",
          at: now,
          subject: auth.subject,
          tokenId: auth.tokenId,
          detail: { tool: options.name, scope: req },
        })
      }
      logger.debug({ tool: options.name, scopes: required }, "scope.allow")

      return (await options.handler({ input, auth })) as unknown as CallToolResult
      // biome-ignore lint/suspicious/noExplicitAny: bridge our wrapper return type to SDK's CallToolResult
    }) as any
    mcp.tool(options.name, options.description, options.inputSchema, mcpCallback)
  }

  function handlers(mcp: McpServer): Handlers {
    const runPipelineForRequest = async (
      req: IncomingMessage,
      bearer: string | null,
    ): Promise<PipelineResult> => {
      const spec = config.auth.authorizationServer
      // No AS configured (e.g. bypass-only or stdio auto-enable). Skip the
      // resolver step entirely; the pipeline will short-circuit at step 4
      // if a JWT-shaped token arrives.
      if (spec === undefined) {
        return runPipeline(config, bearer, onEvent, { jwksRegistry })
      }
      const resolved = await resolveAuthorizationServer({
        incoming: req,
        resolverSpec: spec,
        logger,
      })
      if (!resolved.ok) {
        return {
          ok: false,
          reason: `authorization-server-resolution-failed: ${resolved.error.message}`,
          kind: "server-error",
        }
      }
      return runPipeline(config, bearer, onEvent, {
        resolvedAuthorizationServer: resolved.as,
        jwksRegistry,
      })
    }

    const mcpHandler = createMcpHandler({
      mcp,
      resourceIndicator: config.resourceIndicator,
      host,
      runPipeline: runPipelineForRequest,
      authContextStorage,
    })

    const metadataHandler = createMetadataHandler({
      resourceIndicator: config.resourceIndicator,
      ...(typeof config.auth.authorizationServer === "object"
        ? { authorizationServerIssuer: config.auth.authorizationServer.issuer }
        : {}),
      vocabulary: config.scopes.vocabulary,
      host,
    })

    const patsHandler = createPatsHandler({
      tokenStore: config.auth.tokenStore,
      lifecycleConfig: resolvePatLifecycleConfig(config),
      resourceIndicator: config.resourceIndicator,
      host,
      runPipeline: runPipelineForRequest,
      ...(onEvent ? { audit: onEvent } : {}),
    })

    return {
      mcp: mcpHandler,
      metadata: metadataHandler,
      pats: patsHandler,
      challenge: (res, reason) => {
        writeChallenge(res, {
          resourceMetadataUrl: metadataUrlFor(config.resourceIndicator),
          ...(reason ? { error: "invalid_token", errorDescription: reason } : {}),
        })
      },
    }
  }

  // upstreamFor is wired lazily so it can refuse cleanly at call time when no
  // authorization server is configured (the helper requires RFC 8693 support,
  // which implies an AS). Construction itself is cheap and is performed up
  // front so the LRU-fallback startup warning fires when the AS is present
  // but the store omits the optional cache methods.
  //
  // The function-form (multi-tenant) AS is intentionally excluded: upstreamFor
  // assumes a single static issuer at construction time. Tenants resolved
  // per-request would need a per-tenant token-exchange client and per-tenant
  // cache keys, which is a separate feature (out of scope for v0.2 §5.6).
  const as = config.auth.authorizationServer
  const upstreamForImpl =
    as && typeof as !== "function"
      ? createUpstreamFor({
          issuer: as.issuer,
          resourceIndicator: config.resourceIndicator,
          tokenStore: config.auth.tokenStore,
          ...(onEvent ? { audit: onEvent } : {}),
          logger,
        })
      : null

  const upstreamFor = (audience: string) => {
    if (upstreamForImpl === null) {
      throw new Error(
        as && typeof as === "function"
          ? "upstreamFor: function-form authorizationServer is not yet supported by upstreamFor — requires a single static AS (v0.2 §5.6)"
          : "upstreamFor: an authorizationServer must be configured to mint upstream credentials",
      )
    }
    return (args: UpstreamForArgs): Promise<UpstreamCredential> => upstreamForImpl(audience)(args)
  }

  // The _authContextStorage and _runPipeline fields are used by the HTTP
  // handler (issue #36) to inject auth context and reuse the bound pipeline.
  // Not part of the public AuthKit interface; _ prefix signals internal use.
  // For function-form authorizationServer the bearer-only signature cannot
  // resolve a tenant; callers in that mode go through `handlers()` instead.
  return {
    registerTool,
    handlers,
    upstreamFor,
    _authContextStorage: authContextStorage,
    _runPipeline: (bearer: string | null) => runPipeline(config, bearer, onEvent, { jwksRegistry }),
  } as AuthKit & {
    _authContextStorage: AsyncLocalStorage<AuthContext>
    _runPipeline: (bearer: string | null) => Promise<PipelineResult>
  }
}
