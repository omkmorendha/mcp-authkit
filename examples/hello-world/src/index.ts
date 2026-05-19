// Runnable protected MCP server (spec §6.2). Bypass default-on for local
// dev; set MCP_AUTHKIT_BYPASS=0 to require real tokens (spec §11.1).

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
import pino from "pino"
import { z } from "zod"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const resourceIndicator = process.env.RESOURCE_INDICATOR ?? `http://localhost:${port}/mcp`

const authkit = createAuthKit({
  resourceIndicator,
  auth: {
    authorizationServer: {
      issuer: "https://auth.example.com",
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
    bypass: {
      enabled: process.env.MCP_AUTHKIT_BYPASS !== "0",
      user: "local-dev",
      scopes: ["echo:say"],
    },
  },
  scopes: { vocabulary: { "echo:say": { description: "Echo a string" } } },
  resolveUserScopes: async () => ["echo:say"],
})

const mcp = new McpServer({ name: "hello", version: "0.1.0" })

authkit.registerTool(mcp, {
  name: "echo",
  description: "Echo input",
  inputSchema: { text: z.string() },
  requireScopes: ["echo:say"],
  handler: async ({ input }) => ({ content: [{ type: "text", text: input.text }] }),
})

const h = expressHandlers(authkit, mcp)
const app = express() // no express.json(): handlers read the raw stream
app.use("/mcp", h.mcp)
app.use("/.well-known/oauth-protected-resource", h.metadata)
app.use("/pats", h.pats)
app.listen(port, () => pino({ name: "hello-world" }).info({ port }, "listening"))
