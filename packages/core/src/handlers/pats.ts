/**
 * PAT REST endpoints (framework-agnostic).
 *
 * Routes (relative to the mount point):
 *   POST   /              — mint
 *   GET    /              — list caller's PATs
 *   DELETE /:id           — revoke
 *   POST   /:id/rotate    — rotate
 *
 * Spec:
 *   - docs/spec/v0.1.md#83-rest-endpoints-consumer-mounted
 *   - docs/spec/v0.1.md#86-pat-cannot-manage-pats   (PAT/static → 403)
 *   - docs/spec/v0.1.md#9-token-validation-pipeline (auth required)
 *   - docs/spec/v0.1.md#14-security-non-negotiables
 *
 * @module
 */
import type { IncomingMessage, ServerResponse } from "node:http"
import { z } from "zod"
import { extractBearer, type PipelineResult } from "../authkit.js"
import {
  createPat,
  type LifecycleOptions,
  listPats,
  type PatLifecycleConfig,
  PatLifecycleError,
  revokePat,
  rotatePat,
} from "../pats/lifecycle.js"
import type { AuditEvent, AuthContext, TokenStore } from "../types.js"
import { metadataUrlFor, writeChallenge } from "./challenge.js"
import { type HostValidationOptions, validateHost } from "./host.js"
import { methodNotAllowed, notFound, readJsonBody, sendError, sendJson } from "./http-utils.js"

const createPatBodySchema = z.object({
  name: z.string().min(1).max(200),
  scopes: z.array(z.string().min(1)).min(1),
  expiresInDays: z.number().int().positive().optional(),
})

export interface PatsHandlerDeps {
  readonly tokenStore: TokenStore
  readonly lifecycleConfig: PatLifecycleConfig
  readonly resourceIndicator: string
  readonly host: HostValidationOptions
  /**
   * Pipeline bound to the current request. The `req` argument lets the
   * pipeline run multi-tenant resolution (spec v0.2 §7) before any other
   * step; for single-tenant deployments it is unused.
   */
  readonly runPipeline: (req: IncomingMessage, bearer: string | null) => Promise<PipelineResult>
  readonly audit?: (event: AuditEvent) => void | Promise<void>
}

interface RouteMatch {
  readonly method: "POST" | "GET" | "DELETE"
  readonly kind: "collection" | "by-id" | "rotate"
  readonly id?: string
}

/**
 * Match `req.method + path` against the four PAT routes. Returns null on
 * no-match so the caller can choose between 404 and 405.
 *
 * The path is normalised: leading slash optional, trailing slash tolerated.
 * IDs are non-empty segments with no `/`.
 */
export function matchPatRoute(method: string, rawPath: string): RouteMatch | null {
  const path = normalisePath(rawPath)

  if (path === "") {
    if (method === "POST") return { method: "POST", kind: "collection" }
    if (method === "GET") return { method: "GET", kind: "collection" }
    return null
  }

  // `<id>` or `<id>/rotate`
  const segments = path.split("/")
  if (segments.length === 1) {
    const id = segments[0]
    if (id === undefined || id === "") return null
    if (method === "DELETE") return { method: "DELETE", kind: "by-id", id }
    return null
  }
  if (segments.length === 2 && segments[1] === "rotate") {
    const id = segments[0]
    if (id === undefined || id === "") return null
    if (method === "POST") return { method: "POST", kind: "rotate", id }
    return null
  }
  return null
}

function normalisePath(rawPath: string): string {
  let p = rawPath
  const q = p.indexOf("?")
  if (q !== -1) p = p.slice(0, q)
  if (p.startsWith("/")) p = p.slice(1)
  if (p.endsWith("/")) p = p.slice(0, -1)
  return p
}

/**
 * Build the PAT REST handler. The returned function expects to be mounted
 * such that `req.url` is relative to the PAT root (e.g. via
 * `app.use("/pats", h.pats)` in Express, which strips the prefix).
 *
 * For raw `http.createServer` users, the handler tolerates an absolute URL
 * by treating the entire `req.url` as the route — strip your mount prefix
 * upstream if you have one.
 */
export function createPatsHandler(
  deps: PatsHandlerDeps,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req, res) => {
    // 1. DNS rebinding protection.
    const hostCheck = validateHost(req, deps.host)
    if (!hostCheck.ok) {
      sendError(res, 403, "forbidden", `Host header ${hostCheck.reason}`)
      return
    }

    // 2. Authenticate.
    const bearer = extractBearer(req.headers.authorization)
    const pipeline = await deps.runPipeline(req, bearer)
    if (!pipeline.ok) {
      if (pipeline.kind === "server-error") {
        // Spec v0.2 §7: authorization-server resolution failure is a 503,
        // not a 401 — the token is not the problem, the AS lookup is.
        if (!res.headersSent) {
          res.setHeader("WWW-Authenticate", 'Bearer error="server_error"')
          res.setHeader("Cache-Control", "no-store")
          res.writeHead(503, { "Content-Type": "application/json" })
          res.end(
            JSON.stringify({
              error: "server_error",
              error_description: "Authorization server resolution failed",
            }),
          )
        }
        return
      }
      writeChallenge(res, {
        resourceMetadataUrl: metadataUrlFor(deps.resourceIndicator),
        ...(bearer === null
          ? {}
          : { error: "invalid_token" as const, errorDescription: pipeline.reason }),
      })
      return
    }

    // 3. §8.6: PAT cannot manage PATs. Static token treated the same.
    if (pipeline.auth.tokenType === "pat" || pipeline.auth.tokenType === "static") {
      sendError(
        res,
        403,
        "forbidden",
        "PAT and static-token authentication cannot manage personal access tokens",
      )
      return
    }

    // 4. Route.
    const route = matchPatRoute(req.method ?? "", req.url ?? "/")
    if (route === null) {
      // Distinguish 404 (no such path) from 405 (path exists, wrong method).
      const path = normalisePath(req.url ?? "/")
      if (path === "") {
        methodNotAllowed(res, ["GET", "POST"])
        return
      }
      if (path.endsWith("/rotate")) {
        methodNotAllowed(res, ["POST"])
        return
      }
      if (!path.includes("/")) {
        methodNotAllowed(res, ["DELETE"])
        return
      }
      notFound(res)
      return
    }

    try {
      switch (route.kind) {
        case "collection":
          if (route.method === "POST") return await handleCreate(req, res, deps, pipeline.auth)
          return await handleList(res, deps, pipeline.auth)
        case "by-id":
          // DELETE
          return await handleRevoke(res, deps, pipeline.auth, route.id ?? "")
        case "rotate":
          return await handleRotate(res, deps, pipeline.auth, route.id ?? "")
      }
    } catch (err) {
      if (err instanceof PatLifecycleError) {
        sendError(res, 400, err.code, err.message)
        return
      }
      // Unknown error — surface as 500 with a generic message; don't leak.
      sendError(res, 500, "internal_error", "Internal server error")
      return
    }
  }
}

async function handleCreate(
  req: IncomingMessage,
  res: ServerResponse,
  deps: PatsHandlerDeps,
  auth: AuthContext,
): Promise<void> {
  const body = await readJsonBody(req)
  if (!body.ok) {
    if (body.reason === "too_large") {
      sendError(res, 413, "payload_too_large", "Request body exceeds limit")
      return
    }
    sendError(res, 400, "invalid_request", `Body ${body.reason}`)
    return
  }
  const parsed = createPatBodySchema.safeParse(body.value)
  if (!parsed.success) {
    sendError(res, 400, "invalid_request", "Invalid request body", {
      issues: parsed.error.issues,
    })
    return
  }

  const options: LifecycleOptions = deps.audit ? { audit: deps.audit } : {}
  const result = await createPat(
    deps.tokenStore,
    deps.lifecycleConfig,
    {
      userIdentifier: auth.subject,
      name: parsed.data.name,
      scopes: parsed.data.scopes,
      ...(parsed.data.expiresInDays !== undefined
        ? { expiresInDays: parsed.data.expiresInDays }
        : {}),
    },
    options,
  )
  sendJson(res, 201, {
    token: result.token,
    pat: storedToPublic(result.stored),
  })
}

async function handleList(
  res: ServerResponse,
  deps: PatsHandlerDeps,
  auth: AuthContext,
): Promise<void> {
  const items = await listPats(deps.tokenStore, auth.subject)
  sendJson(res, 200, { pats: items })
}

async function handleRevoke(
  res: ServerResponse,
  deps: PatsHandlerDeps,
  auth: AuthContext,
  id: string,
): Promise<void> {
  // Ownership check: only emit 204 + audit when the PAT actually belongs to
  // the caller. The store treats wrong-user as a silent no-op; that would
  // leak "this ID exists somewhere" via timing, so we list first.
  const owned = await listPats(deps.tokenStore, auth.subject)
  if (!owned.some((p) => p.id === id)) {
    notFound(res, "PAT not found")
    return
  }
  const options: LifecycleOptions = deps.audit ? { audit: deps.audit } : {}
  await revokePat(deps.tokenStore, id, auth.subject, options)
  if (res.headersSent) return
  res.writeHead(204)
  res.end()
}

async function handleRotate(
  res: ServerResponse,
  deps: PatsHandlerDeps,
  auth: AuthContext,
  id: string,
): Promise<void> {
  const owned = await listPats(deps.tokenStore, auth.subject)
  if (!owned.some((p) => p.id === id)) {
    notFound(res, "PAT not found")
    return
  }
  const options: LifecycleOptions = deps.audit ? { audit: deps.audit } : {}
  const result = await rotatePat(deps.tokenStore, deps.lifecycleConfig, id, auth.subject, options)
  sendJson(res, 200, {
    token: result.token,
    pat: storedToPublic(result.stored),
  })
}

function storedToPublic(stored: {
  readonly id: string
  readonly name: string
  readonly scopes: readonly string[]
  readonly display: string
  readonly createdAt: Date
  readonly expiresAt: Date
  readonly lastUsedAt: Date | null
}): {
  id: string
  name: string
  scopes: readonly string[]
  display: string
  createdAt: Date
  expiresAt: Date
  lastUsedAt: Date | null
} {
  return {
    id: stored.id,
    name: stored.name,
    scopes: stored.scopes,
    display: stored.display,
    createdAt: stored.createdAt,
    expiresAt: stored.expiresAt,
    lastUsedAt: stored.lastUsedAt,
  }
}
