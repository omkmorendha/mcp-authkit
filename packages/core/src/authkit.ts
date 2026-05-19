/**
 * `createAuthKit` factory — token validation pipeline and scope-gate.
 *
 * Spec: docs/spec/v0.1.md#9-token-validation-pipeline
 *       docs/spec/v0.1.md#12-audit-callbacks
 *       docs/spec/v0.1.md#14-security-non-negotiables
 *
 * @module
 */
import { createHash, timingSafeEqual } from "node:crypto"
import type { IncomingMessage, ServerResponse } from "node:http"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import pino from "pino"
import { z } from "zod"
import { createIntrospectionValidator } from "./auth/introspection.js"
import { createJwtValidator, type JwtValidatorOptions } from "./auth/jwt.js"
import { synthesizeBypassContext, synthesizeStaticContext } from "./bypass/index.js"
import { findPatByHash, updatePatLastUsed } from "./pats/lifecycle.js"
import { satisfies } from "./scopes/satisfies.js"
import type {
  AuditEvent,
  AuthContext,
  AuthKit,
  AuthKitConfig,
  Handlers,
  RegisterToolOptions,
} from "./types.js"

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type PipelineResult = { ok: true; auth: AuthContext } | { ok: false }

/**
 * Extract the Bearer token from an Authorization header value.
 * Returns null if the header is absent or not a Bearer token.
 */
function extractBearer(authHeader: string | undefined): string | null {
  if (!authHeader) return null
  const match = /^Bearer\s+(\S+)$/i.exec(authHeader)
  return match?.[1] ?? null
}

/**
 * True if the token looks like a JWT (three base64url segments separated by dots).
 * This is a structural heuristic only; the JWT validator does the real verification.
 */
function looksLikeJwt(token: string): boolean {
  const parts = token.split(".")
  return parts.length === 3 && parts.every((p) => p.length > 0)
}

/**
 * Constant-time comparison for two strings.
 *
 * Encodes both to UTF-8. If lengths differ, uses the configured token length
 * as the dummy buffer length so the comparison always runs in time proportional
 * to the configured token, not the presented one (spec §14 constant-time).
 */
function timingSafeStringEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8")
  const bBuf = Buffer.from(b, "utf8")
  if (aBuf.length !== bBuf.length) {
    // Run a dummy comparison of equal-length buffers to avoid short-circuit,
    // then return false. We use a zero buffer of the configured token length.
    const dummy = Buffer.alloc(aBuf.length, 0)
    timingSafeEqual(dummy, dummy)
    return false
  }
  return timingSafeEqual(aBuf, bBuf)
}

async function emitAudit(
  config: AuthKitConfig,
  event: AuditEvent,
): Promise<void> {
  if (config.audit?.onEvent) {
    await config.audit.onEvent(event)
  }
}

// ---------------------------------------------------------------------------
// Six-step validation pipeline
// ---------------------------------------------------------------------------

async function runPipeline(
  config: AuthKitConfig,
  bearerToken: string | null,
): Promise<PipelineResult> {
  // Step 1: Bypass mode active?
  const bypass = config.auth.bypass
  if (bypass?.enabled) {
    return { ok: true, auth: synthesizeBypassContext(bypass) }
  }

  // Step 2: Static token configured and matches?
  const staticToken = config.auth.staticToken
  if (staticToken !== undefined && bearerToken !== null) {
    if (timingSafeStringEqual(staticToken.token, bearerToken)) {
      return { ok: true, auth: synthesizeStaticContext(staticToken) }
    }
  }

  // Steps 3–5 require a bearer token.
  if (bearerToken === null) {
    return { ok: false }
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
      // Best-effort, non-blocking (spec §9 step 3).
      void updatePatLastUsed(config.auth.tokenStore, resolved.stored.id, new Date())
      return { ok: true, auth }
    }
    // PAT prefix but not found/valid → fall through to 401 (no JWT/introspection for PAT-shaped tokens).
    return { ok: false }
  }

  const as = config.auth.authorizationServer
  if (!as) {
    // No AS configured — cannot validate JWT or introspect.
    return { ok: false }
  }

  // Step 4: Bearer token looks like JWT?
  if (looksLikeJwt(bearerToken)) {
    const jwtOpts: JwtValidatorOptions = {
      issuer: as.issuer,
      audience: config.resourceIndicator,
      jwksUri: as.jwksUri,
      ...(as.jwksCacheTtlMs !== undefined ? { jwksCacheTtlMs: as.jwksCacheTtlMs } : {}),
    }
    const validator = createJwtValidator(jwtOpts)
    const result = await validator.validate(bearerToken)
    if (result.ok) {
      return { ok: true, auth: result.auth }
    }
    // JWT validation failed — fall through to introspection only if the
    // failure was not a structural JWT issue; opaque tokens look like JWTs
    // only by accident, so any validation failure means we try introspection.
  }

  // Step 5: introspectionEndpoint configured?
  if (as.introspectionEndpoint) {
    const validator = createIntrospectionValidator({
      introspectionEndpoint: as.introspectionEndpoint,
      audience: config.resourceIndicator,
    })
    const result = await validator.validate(bearerToken)
    if (result.ok) {
      return { ok: true, auth: result.auth }
    }
  }

  // Step 6: No match.
  return { ok: false }
}

// ---------------------------------------------------------------------------
// createAuthKit
// ---------------------------------------------------------------------------

export function createAuthKit(config: AuthKitConfig): AuthKit {
  const logger = config.logger ?? pino({ level: "info" })
  const customMatchers = config.scopes.customMatchers ?? []

  function registerTool<I extends z.ZodRawShape>(
    mcp: McpServer,
    options: RegisterToolOptions<I>,
  ): void {
    const schema = z.object(options.inputSchema)

    // The MCP SDK callback must return CallToolResult. We use 'any' for the
    // raw input because the SDK's generic overloads are opaque to our wrapper.
    // The returned object is structurally compatible with CallToolResult at runtime.
    // biome-ignore lint/suspicious/noExplicitAny: MCP SDK overloads use complex generics; shape is correct
    const toolCb = async (rawInput: any): Promise<CallToolResult> => {
      const input = schema.parse(rawInput) as z.infer<typeof schema>

      // The pipeline needs a bearer token. In registerTool context there is no
      // IncomingMessage; issue #36 will wire the full transport pipeline. For the
      // scope gate to function (e.g. in bypass mode or tests), we run the
      // pipeline with bearerToken=null so bypass/static paths still work.
      const pipelineResult = await runPipeline(config, null)
      if (!pipelineResult.ok) {
        return {
          content: [{ type: "text" as const, text: "Unauthorized" }],
          isError: true,
        }
      }

      const auth = pipelineResult.auth
      const now = new Date()

      // Resolve required scopes (static list or function).
      const required =
        typeof options.requireScopes === "function"
          ? await options.requireScopes({ input, auth })
          : options.requireScopes

      // Gate: all required scopes must be satisfied.
      for (const req of required) {
        const allowed = await satisfies(req, [...auth.scopes], { auth, input }, customMatchers)
        if (!allowed) {
          const event: AuditEvent = {
            type: "scope.deny",
            at: now,
            subject: auth.subject,
            tokenId: auth.tokenId,
            detail: { tool: options.name, required: req, held: auth.scopes },
          }
          await emitAudit(config, event)
          logger.debug({ tool: options.name, required: req }, "scope.deny")
          return {
            content: [{ type: "text" as const, text: `Forbidden: missing scope ${req}` }],
            isError: true,
          }
        }
      }

      // All scopes satisfied — emit allow events and invoke handler.
      for (const req of required) {
        const event: AuditEvent = {
          type: "scope.allow",
          at: now,
          subject: auth.subject,
          tokenId: auth.tokenId,
          detail: { tool: options.name, scope: req },
        }
        await emitAudit(config, event)
      }
      logger.debug({ tool: options.name, scopes: required }, "scope.allow")

      return (await options.handler({ input, auth })) as unknown as CallToolResult
    }
    // biome-ignore lint/suspicious/noExplicitAny: passing typed callback through SDK's generic overload
    mcp.tool(options.name, options.description, options.inputSchema, toolCb as any)
  }

  function handlers(_mcp: McpServer): Handlers {
    // Full HTTP handler wiring is issue #36. These stubs satisfy the AuthKit
    // interface; they will be replaced when #36 lands.
    const notImplemented = async (_req: IncomingMessage, res: ServerResponse): Promise<void> => {
      res.writeHead(501, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ error: "not_implemented" }))
    }

    return {
      mcp: notImplemented,
      metadata: notImplemented,
      pats: notImplemented,
      challenge: (res: ServerResponse, reason?: string) => {
        const params = [`resource="${config.resourceIndicator}"`]
        if (reason) params.push(`error="${reason}"`)
        res.setHeader("WWW-Authenticate", `Bearer ${params.join(", ")}`)
        res.writeHead(401)
        res.end()
      },
    }
  }

  return { registerTool, handlers }
}

// Re-export pipeline for use by the HTTP handler (issue #36).
export { runPipeline }
