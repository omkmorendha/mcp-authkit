/**
 * Express adapter for `mcp-authkit`.
 *
 * Spec: docs/spec/v0.1.md#62-usage-hello-world-target-under-50-lines
 *       docs/spec/v0.1.md#63-import-paths-v01
 *
 * Thin sugar over the framework-agnostic handlers returned by
 * `authkit.handlers(mcp)`. Each handler is wrapped in an Express
 * `RequestHandler` that forwards uncaught errors to `next(err)`. Express's
 * `Request`/`Response` structurally extend Node's `IncomingMessage`/
 * `ServerResponse`, so no request/response adaptation is needed — the
 * wrapper exists purely to convert promise rejections into Express's
 * error-propagation contract.
 *
 * Core has zero Express imports; Express types appear only here.
 *
 * Note on packaging: this package does NOT depend on `mcp-authkit` at the
 * package.json level — to avoid a workspace dependency cycle, since core
 * re-exports this adapter under `mcp-authkit/adapters/express` (spec §6.3).
 * Instead we declare the minimal structural surface we need from the host
 * `AuthKit`. Core asserts structural compatibility in
 * `packages/core/src/adapters/express.ts`, so drift fails `pnpm typecheck`.
 *
 * @module
 */

import type { IncomingMessage, ServerResponse } from "node:http"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { NextFunction, Request, RequestHandler, Response } from "express"

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
 * Express-flavoured surface of `Handlers`. The four entries mirror
 * spec §6.1: three middleware functions and a `challenge` helper that
 * writes a 401 with the correct `WWW-Authenticate` header.
 */
export interface ExpressHandlers {
  /** Mount on your MCP route, e.g. `app.use("/mcp", h.mcp)`. */
  mcp: RequestHandler
  /** Mount on `/.well-known/oauth-protected-resource`. */
  metadata: RequestHandler
  /** Mount on your PAT REST root, e.g. `app.use("/pats", h.pats)`. */
  pats: RequestHandler
  /**
   * Write a 401 Bearer challenge. Not middleware — call from your own
   * handlers when you need to force a re-auth from outside the framework's
   * routes. Mirrors `Handlers.challenge` (spec §6.1).
   */
  challenge: (res: Response, reason?: string) => void
}

/**
 * Wrap a framework-agnostic handler in an Express `RequestHandler`.
 *
 * Express 5 awaits returned promises and surfaces rejections automatically,
 * but we still wrap explicitly so behaviour is identical on Express 4 and
 * so the contract is obvious to readers. `next(err)` is called at most once
 * per request; if the raw handler resolves, `next` is not called and the
 * raw handler is responsible for having written/ended the response.
 *
 * Express's `Request`/`Response` structurally extend the Node primitives
 * (`IncomingMessage`/`ServerResponse`) so passing them through to the raw
 * handler is type-safe.
 */
function wrap(raw: (req: IncomingMessage, res: ServerResponse) => Promise<void>): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    raw(req, res).catch(next)
  }
}

/**
 * Create Express-compatible handlers from an `AuthKit` and an `McpServer`.
 *
 * @example
 * ```ts
 * const h = expressHandlers(authkit, mcp)
 * app.use("/mcp", h.mcp)
 * app.use("/.well-known/oauth-protected-resource", h.metadata)
 * app.use("/pats", h.pats)
 * ```
 */
export function expressHandlers(authkit: AuthKitLike, mcp: McpServer): ExpressHandlers {
  const raw = authkit.handlers(mcp)
  return {
    mcp: wrap(raw.mcp),
    metadata: wrap(raw.metadata),
    pats: wrap(raw.pats),
    challenge: (res, reason) => {
      if (reason === undefined) {
        raw.challenge(res)
      } else {
        raw.challenge(res, reason)
      }
    },
  }
}
