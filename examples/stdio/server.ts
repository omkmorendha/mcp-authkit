// Production stdio example (spec v0.2 §11). Wires the signed-handshake
// stdio transport from mcp-authkit to an `McpServer`. Each inbound frame
// is HMAC-verified, dispatched as a single JSON-RPC request, and the
// response is signed and framed back out.
//
// The framing is request/response: clients send one frame and read one
// frame. Server-initiated messages cannot be delivered through the signed
// transport, so this example only models the request/response path.

import { Buffer } from "node:buffer"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js"
import type { JSONRPCMessage, MessageExtraInfo } from "@modelcontextprotocol/sdk/types.js"
import { createAuthKit, createSignedStdioTransport } from "mcp-authkit"
import pino from "pino"
import { z } from "zod"
import config from "./mcp-authkit.config.js"

// Pino writes to stderr so the framed stdout channel stays binary-clean.
const logger = pino({ name: "mcp-authkit-example-stdio" }, pino.destination(2))

const authkit = createAuthKit({ ...config, logger })

const mcp = new McpServer({ name: "stdio-example", version: "0.1.0" })

authkit.registerTool(mcp, {
  name: "echo",
  description: "Echo input",
  inputSchema: { text: z.string() },
  requireScopes: ["echo:say"],
  handler: async ({ input }) => ({ content: [{ type: "text", text: input.text }] }),
})

// Bridge `createSignedStdioTransport` (raw request/response frames) to the
// MCP SDK `Transport` interface (parsed JSON-RPC with callbacks). Each
// inbound frame is delivered via `onmessage`; the next `send()` is treated
// as its paired response.
class SignedStdioMcpTransport implements Transport {
  onclose?: () => void
  onerror?: (error: Error) => void
  onmessage?: (message: JSONRPCMessage, extra?: MessageExtraInfo) => void

  private pending: ((payload: Buffer | null) => void) | null = null

  constructor(private readonly extra: MessageExtraInfo | undefined) {}

  async start(): Promise<void> {
    // The underlying signed transport begins on construction.
  }

  async send(message: JSONRPCMessage): Promise<void> {
    const resolve = this.pending
    if (resolve === null) {
      logger.warn(
        { message },
        "dropping server-initiated message: signed stdio is request/response only",
      )
      return
    }
    this.pending = null
    resolve(Buffer.from(JSON.stringify(message), "utf8"))
  }

  async close(): Promise<void> {
    // Closing is driven by the signed transport itself; nothing to do here.
  }

  deliver(payload: Buffer): Promise<Buffer | null> {
    return new Promise((resolve) => {
      let parsed: JSONRPCMessage
      try {
        parsed = JSON.parse(payload.toString("utf8")) as JSONRPCMessage
      } catch (err) {
        this.onerror?.(err instanceof Error ? err : new Error(String(err)))
        resolve(null)
        return
      }
      // Notifications carry no `id`; the signed framing has no return
      // slot for them, so drop the response after delivery.
      const isNotification = !("id" in parsed) || parsed.id === undefined
      if (isNotification) {
        try {
          this.onmessage?.(parsed, this.extra)
        } catch (err) {
          this.onerror?.(err instanceof Error ? err : new Error(String(err)))
        }
        resolve(null)
        return
      }
      this.pending = resolve
      try {
        this.onmessage?.(parsed, this.extra)
      } catch (err) {
        this.pending = null
        this.onerror?.(err instanceof Error ? err : new Error(String(err)))
        resolve(null)
      }
    })
  }
}

// Inside the signed channel the example treats every message as
// authenticated by a static token (set via MCP_AUTHKIT_STATIC_TOKEN). Real
// deployments would extract per-call credentials from the JSON-RPC payload
// — see the README for the rationale.
const bearer = process.env.MCP_AUTHKIT_STATIC_TOKEN
const extra: MessageExtraInfo | undefined =
  bearer && bearer.length > 0
    ? { authInfo: { token: bearer, clientId: "stdio-local", scopes: [] } }
    : undefined
const transport = new SignedStdioMcpTransport(extra)
const stdio = createSignedStdioTransport({
  hmacKey: process.env.MCP_AUTHKIT_HMAC_KEY ?? "",
  input: process.stdin,
  output: process.stdout,
  onRequest: (payload) => transport.deliver(payload),
  logger,
  ...(config.audit?.onEvent ? { audit: config.audit.onEvent } : {}),
})

stdio.closed.then((reason) => {
  // Map integrity failures to a non-zero exit so supervisors and alerts
  // treat them as failures rather than clean shutdowns.
  const abnormal =
    reason.kind === "stdio-replay" ||
    reason.kind === "stdio-tamper" ||
    reason.kind === "stdio-payload-too-large" ||
    reason.kind === "stdio-input-error" ||
    reason.kind === "stdio-handler-error"
  if (abnormal) {
    logger.error({ reason }, "signed stdio transport closed abnormally")
  } else {
    logger.info({ reason }, "signed stdio transport closed")
  }
  transport.onclose?.()
  process.exit(abnormal ? 1 : 0)
})

logger.info({ keyFingerprint: stdio.keyFingerprint }, "signed stdio transport ready")
await mcp.connect(transport)
