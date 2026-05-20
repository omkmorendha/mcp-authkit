// Runnable protected MCP server backed by the SQLite token store.
// Mirrors `examples/postgres` but uses a single-file database — no
// container required. Loads the framework through the config-file
// loader (`mcp-authkit/config`) per spec §5.8 and uses the SQLite
// `TokenStore` from spec §6.4.
//
// Run `pnpm --filter mcp-authkit-example-filesystem dev` and the
// database file is created on first use.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { loadConfig } from "mcp-authkit/config"
import pino from "pino"
import { z } from "zod"

const log = pino({ name: "filesystem-example" })
const port = Number.parseInt(process.env.PORT ?? "3000", 10)

const config = await loadConfig("./mcp-authkit.config.ts")

// `init()` enables WAL and applies migrations idempotently (spec §6.4).
// The core `TokenStore` contract makes the call optional; invoking it
// here lets a cold start against an empty file bootstrap the schema
// without a separate migrate step.
await config.auth.tokenStore.init?.()

const authkit = createAuthKit(config)
const mcp = new McpServer({ name: "filesystem-example", version: "0.2.0" })

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
app.listen(port, () => log.info({ port }, "listening"))
