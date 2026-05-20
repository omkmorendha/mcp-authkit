/**
 * Hono adapter for `mcp-authkit`.
 *
 * Spec: docs/spec/v0.2.md#59-hono-adapter
 *       docs/spec/v0.2.md#10-hono-adapter
 *       docs/spec/v0.1.md#61-core-types-this-is-the-contract
 *
 * Mirrors the Express adapter (`mcp-authkit/adapters/express`). Provides
 * a `honoMiddleware(authkit, mcp)` factory that returns a `Hono` sub-app
 * with the standard routes mounted, plus per-route helpers (`mcp`,
 * `metadata`, `pats`) for consumers who want to wire their own routing.
 *
 * Internally adapts Hono's `Context` (Web Fetch `Request`/`Response`) to
 * Node-style `IncomingMessage`/`ServerResponse` via the private
 * `adapt.ts` module. The `mcp` handler streams the response — the body
 * is never buffered.
 *
 * Like the Express adapter, this package does NOT depend on `mcp-authkit`
 * at the package.json level to avoid a workspace cycle (spec §6.3 import
 * path `mcp-authkit/adapters/hono` re-exports this package from core).
 * Core asserts structural compatibility in
 * `packages/core/src/adapters/hono.ts`, so drift fails `pnpm typecheck`.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { type Context, Hono, type MiddlewareHandler } from "hono"
import { createAdaptedResponse, toIncomingMessage } from "./adapt.js"

/**
 * Raw `Handlers` surface produced by `authkit.handlers(mcp)`. Mirrors the
 * shape declared in `mcp-authkit` core (spec §6.1) but is re-declared here
 * to avoid a package dependency cycle (see module docstring).
 */
export interface RawHandlers {
  mcp: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  metadata: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  pats: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  challenge: (res: ServerResponse, reason?: string) => void
}

/**
 * Minimal structural type of `AuthKit` accepted by the adapter — just the
 * `handlers(mcp)` factory. We intentionally do NOT model `registerTool`
 * since the adapter doesn't touch it.
 */
export interface AuthKitLike {
  handlers(mcp: McpServer): RawHandlers
}

/**
 * Hono-flavoured surface of `Handlers`. Three middleware functions that
 * cover the spec §6.1 routes plus a `challenge` helper that writes a 401
 * with the correct `WWW-Authenticate` header onto a Hono `Context`.
 *
 * Each middleware is a `MiddlewareHandler`: it adapts the incoming Hono
 * `Context` to Node-style req/res, awaits the underlying raw handler,
 * and assigns the produced streaming `Response` to `c.res`.
 */
export interface HonoHandlers {
  /** Mount on your MCP route, e.g. `app.all("/mcp", h.mcp)`. */
  mcp: MiddlewareHandler
  /** Mount on `/.well-known/oauth-protected-resource`. */
  metadata: MiddlewareHandler
  /** Mount on your PAT REST root, e.g. `app.all("/pats/*", h.pats)`. */
  pats: MiddlewareHandler
  /**
   * Write a 401 Bearer challenge to the Hono response. Mirrors
   * `Handlers.challenge` (spec §6.1) — call from your own handlers when
   * you need to force re-auth from outside the framework's routes.
   * Returns the `Response` so it can be returned from a route handler.
   */
  challenge: (c: Context, reason?: string) => Promise<Response>
}

/**
 * Adapt a single raw `Handlers` entry to a Hono `MiddlewareHandler`.
 *
 * Streaming contract: the underlying raw handler writes to a Node
 * `ServerResponse` whose writes are piped into a `PassThrough`. As soon
 * as the raw handler commits headers (via `writeHead`, `flushHeaders`,
 * or the first `write`/`end`) we resolve a `Response` and assign it to
 * `c.res`. The raw handler continues to write into the body stream
 * after we return from this function; Hono ships the unread stream as
 * the HTTP response body.
 *
 * Errors raised before headers are committed surface as rejections of
 * the underlying promise and are re-thrown for Hono's `onError` handler.
 * Errors after commit are unrecoverable at the HTTP layer — they break
 * the body stream but the status is already on the wire.
 */
function wrap(
  raw: (req: IncomingMessage, res: ServerResponse) => Promise<void>,
): MiddlewareHandler {
  return async (c: Context): Promise<Response> => {
    const req = toIncomingMessage(c.req.raw)
    const { res, response } = createAdaptedResponse()
    // Kick off the raw handler. Don't await it here — we need to return
    // the `Response` as soon as headers are committed so Hono can start
    // shipping bytes. The handler keeps writing into the body stream
    // after this function returns; `passthrough.end()` closes it.
    const work = raw(req, res)

    // Race the response-commit promise against the work promise. The
    // work promise normally settles AFTER the response is committed
    // (the handler ends the stream once it's done writing).
    //
    // If `work` rejects BEFORE commit, we re-throw so Hono's `onError`
    // can turn it into a 500. We do NOT auto-end the response stream
    // in that case — committing on the way out would mask the error as
    // a 200/whatever was on `statusCode` at the throw moment.
    //
    // If `work` resolves WITHOUT having committed (the handler never
    // wrote anything), we treat that as the handler having declined to
    // respond and surface an empty response committed via `flushHeaders`.
    const committed = await Promise.race([
      response.then((r) => ({ kind: "response" as const, response: r })),
      work.then(
        () => ({ kind: "done" as const }),
        (err: unknown) => ({ kind: "error" as const, error: err }),
      ),
    ])
    if (committed.kind === "error") {
      // Swallow any late stream errors so they don't become unhandled
      // rejections after we re-throw to Hono.
      response.catch(() => undefined)
      throw committed.error
    }
    if (committed.kind === "done") {
      // Handler finished without committing — finalise an empty body
      // with whatever status was on the response.
      if (!res.writableEnded) res.end()
      return await response
    }
    // Headers committed; ship the streaming Response. Swallow late
    // rejections of `work` to keep them from becoming unhandled — the
    // status is already on the wire and there's nothing safe to do.
    work.catch(() => undefined)
    return committed.response
  }
}

/**
 * Create Hono-compatible handlers from an `AuthKit` and an `McpServer`.
 *
 * Use this when you want to wire each route yourself. For the common
 * "mount everything under one root" case, prefer `honoMiddleware`.
 *
 * @example
 * ```ts
 * const h = honoHandlers(authkit, mcp)
 * app.all("/mcp", h.mcp)
 * app.get("/.well-known/oauth-protected-resource", h.metadata)
 * app.all("/pats/*", h.pats)
 * ```
 */
export function honoHandlers(authkit: AuthKitLike, mcp: McpServer): HonoHandlers {
  const raw = authkit.handlers(mcp)
  return {
    mcp: wrap(raw.mcp),
    metadata: wrap(raw.metadata),
    pats: wrap(raw.pats),
    challenge: async (_c, reason) => {
      const { res, response } = createAdaptedResponse()
      if (reason === undefined) {
        raw.challenge(res)
      } else {
        raw.challenge(res, reason)
      }
      return await response
    },
  }
}

/**
 * Create a Hono sub-app with the standard `mcp-authkit` routes mounted.
 *
 * Routes mounted (matching spec §6.2 / §6.3):
 *   - `ALL  /mcp`
 *   - `GET  /.well-known/oauth-protected-resource`
 *   - `ALL  /pats/*`
 *
 * Compose it into a parent Hono app via `app.route("/", honoMiddleware(...))`.
 *
 * @example
 * ```ts
 * import { Hono } from "hono"
 * import { honoMiddleware } from "mcp-authkit/adapters/hono"
 *
 * const app = new Hono()
 * app.route("/", honoMiddleware(authkit, mcp))
 * ```
 */
export function honoMiddleware(authkit: AuthKitLike, mcp: McpServer): Hono {
  const h = honoHandlers(authkit, mcp)
  const app = new Hono()
  app.all("/mcp", h.mcp)
  app.get("/.well-known/oauth-protected-resource", h.metadata)
  // PAT REST: `pats` for the collection routes, `pats/*` for the per-id
  // routes (`/:id`, `/:id/rotate`). The underlying handler does its own
  // method+path routing; we just mount both prefixes.
  app.all("/pats", h.pats)
  app.all("/pats/*", h.pats)
  return app
}
