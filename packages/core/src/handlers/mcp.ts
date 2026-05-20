/**
 * MCP request handler — token validation pipeline + auth-context injection +
 * delegation to the MCP SDK's HTTP transport.
 *
 * Spec:
 *   - docs/spec/v0.1.md#9-token-validation-pipeline
 *   - docs/spec/v0.1.md#13-oauth-endpoints-the-framework-owns
 *   - docs/spec/v0.1.md#14-security-non-negotiables
 *
 * The transport is created once in stateless mode and reused across requests;
 * the SDK guarantees `handleRequest` is safe to call concurrently for
 * independent request/response pairs.
 *
 * @module
 */
import type { AsyncLocalStorage } from "node:async_hooks"
import { randomUUID } from "node:crypto"
import type { IncomingMessage, ServerResponse } from "node:http"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js"
import { extractBearer, type PipelineResult } from "../authkit.js"
import type { AuthContext } from "../types.js"
import { metadataUrlFor, writeChallenge } from "./challenge.js"
import { type HostValidationOptions, validateHost } from "./host.js"

export interface McpHandlerDeps {
  readonly mcp: McpServer
  readonly resourceIndicator: string
  readonly host: HostValidationOptions
  /**
   * Pipeline bound to the current request. The `req` argument lets the
   * pipeline run multi-tenant resolution (spec v0.2 §7) before any other
   * step; for single-tenant deployments it is unused.
   */
  readonly runPipeline: (req: IncomingMessage, bearer: string | null) => Promise<PipelineResult>
  readonly authContextStorage: AsyncLocalStorage<AuthContext>
}

/**
 * Build the MCP handler. The returned function is suitable for direct use
 * as a Node `http.createServer` listener or mounting under Express via
 * `app.use("/mcp", handler)`.
 *
 * On every request:
 *   1. Validate Host header (DNS rebinding mitigation, §14).
 *   2. Run the validation pipeline against the bearer token.
 *   3. On reject → 401 with RFC 6750 + RFC 9728 challenge header.
 *   4. On accept → enter `AsyncLocalStorage` with the `AuthContext`, then
 *      delegate to the SDK transport which routes to the McpServer.
 */
export function createMcpHandler(
  deps: McpHandlerDeps,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  // Stateful mode with auto-generated session IDs. The SDK's stateless mode
  // requires a fresh transport per request, which is incompatible with our
  // single-McpServer model (McpServer.connect throws if invoked twice).
  // Stateful + UUID gives us a single long-lived transport bound to the
  // server; clients send `Mcp-Session-Id` after the initialize handshake.
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  })
  let connected: Promise<void> | null = null
  const ensureConnected = (): Promise<void> => {
    // Cast: SDK's Transport interface uses optional callbacks (`onclose?:`)
    // while the transport class exposes them as accessors of `(() => void)
    // | undefined`. Under `exactOptionalPropertyTypes` these are not
    // mutually assignable; the runtime shapes are compatible.
    if (connected === null) {
      // Clear the cached promise on rejection so the next request can retry.
      // Without this, a transient failure during the first connect would
      // permanently wedge the handler.
      const p = deps.mcp.connect(transport as unknown as Transport)
      connected = p.catch((err: unknown) => {
        connected = null
        throw err
      })
    }
    return connected
  }

  return async (req, res) => {
    try {
      const hostCheck = validateHost(req, deps.host)
      if (!hostCheck.ok) {
        // Don't issue a Bearer challenge for a DNS-rebinding rejection — the
        // client is presenting a forged Host, not a credential problem.
        if (!res.headersSent) {
          res.writeHead(403, { "Content-Type": "application/json", "Cache-Control": "no-store" })
          res.end(
            JSON.stringify({
              error: "forbidden",
              error_description: `Host header ${hostCheck.reason}`,
            }),
          )
        }
        return
      }

      const bearer = extractBearer(req.headers.authorization)
      const result = await deps.runPipeline(req, bearer)
      if (!result.ok) {
        if (result.kind === "server-error") {
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
            : { error: "invalid_token" as const, errorDescription: result.reason }),
        })
        return
      }

      await ensureConnected()

      // Inject AuthContext into the async context so tool handlers (registered
      // via `authkit.registerTool`) can read it from ALS without threading
      // it through the SDK call stack.
      await deps.authContextStorage.run(result.auth, async () => {
        await transport.handleRequest(req, res)
      })
    } catch {
      // Last-resort guard: an unhandled throw in the request path must not
      // crash the server. If we can still write a status, emit a generic 500
      // (no error detail leaked); otherwise the transport has already begun
      // streaming and there is nothing safe to add.
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json", "Cache-Control": "no-store" })
        res.end(JSON.stringify({ error: "internal_error", error_description: "Internal error" }))
      } else if (!res.writableEnded) {
        res.end()
      }
    }
  }
}
