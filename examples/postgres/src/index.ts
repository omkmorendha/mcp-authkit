// Runnable protected MCP server backed by the Postgres token store.
// Mirrors `examples/hello-world` but loads the framework through the
// config-file loader (`mcp-authkit/config`) per spec §5.8 and uses the
// Postgres `TokenStore` from spec §6.3.
//
// Run `docker compose up -d` first to start a local Postgres, then
// `pnpm --filter mcp-authkit-example-postgres dev`.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { loadConfig } from "mcp-authkit/config"
import pino from "pino"
import { z } from "zod"

const log = pino({ name: "postgres-example" })
const port = Number.parseInt(process.env.PORT ?? "3000", 10)

const config = await loadConfig("./mcp-authkit.config.ts")

// `init()` applies migrations idempotently (spec §6.3). The core
// `TokenStore` contract makes it optional so the call is guarded; running
// it here lets a cold replica boot against a fresh database without a
// manual psql step.
await config.auth.tokenStore.init?.()

const authkit = createAuthKit(config)
const mcp = new McpServer({ name: "postgres-example", version: "0.2.0" })

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
