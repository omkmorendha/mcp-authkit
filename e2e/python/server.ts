// Python E2E harness — v0.2 refresh (spec §16).
//
// Loads the checked-in config (`./mcp-authkit.config.ts`), mounts the
// Hono adapter (not Express), and serves on a free port. The single
// JSON line on stdout is the handshake contract with `run.sh`. Bypass
// mode is OFF: the PAT bearer round-trips the real validation pipeline
// (spec §9), and the PAT itself is minted out-of-band by
// `mcp-authkit mint-pat` in a subprocess (spec §16, §9.2).

import type { AddressInfo } from "node:net"
import { createServer as createNetServer } from "node:net"
import { resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { serve } from "@hono/node-server"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { Hono } from "hono"
import { createAuthKit } from "mcp-authkit"
import { honoMiddleware } from "mcp-authkit/adapters/hono"
import { loadConfig } from "mcp-authkit/config"
import pino from "pino"
import { z } from "zod"

const logger = pino({ name: "e2e-python", level: process.env.LOG_LEVEL ?? "warn" })

async function pickFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createNetServer()
    s.unref()
    s.on("error", reject)
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as AddressInfo
      s.close((err) => (err ? reject(err) : resolve(port)))
    })
  })
}

async function main(): Promise<void> {
  const cliBin = process.env.MCP_AUTHKIT_E2E_CLI_BIN
  if (cliBin === undefined || cliBin === "") {
    throw new Error("MCP_AUTHKIT_E2E_CLI_BIN is required")
  }
  if (process.env.MCP_AUTHKIT_E2E_DB === undefined || process.env.MCP_AUTHKIT_E2E_DB === "") {
    throw new Error("MCP_AUTHKIT_E2E_DB is required")
  }

  const host = "127.0.0.1"
  const envPort = process.env.PORT
  const port =
    envPort !== undefined && envPort !== "" ? Number.parseInt(envPort, 10) : await pickFreePort()
  const url = `http://${host}:${port}`
  // The config reads `RESOURCE_INDICATOR` from env so the harness can
  // pick a free port at startup without `run.sh` having to know it in
  // advance. The CLI subprocess reads the same env var via `run.sh`
  // exporting it — both processes therefore see the same audience.
  process.env.RESOURCE_INDICATOR = `${url}/mcp`
  process.env.PORT = String(port)

  const here = resolve(fileURLToPath(import.meta.url), "..")
  const configPath = resolve(here, "mcp-authkit.config.ts")

  const config = await loadConfig(configPath, { allowOutsideCwd: true })

  if (config.auth.tokenStore.init !== undefined) {
    await config.auth.tokenStore.init()
  }

  const authkit = createAuthKit(config)

  const mcp = new McpServer({ name: "e2e", version: "0.1.0" })
  authkit.registerTool(mcp, {
    name: "echo",
    description: "Echo input",
    inputSchema: { text: z.string() },
    requireScopes: ["echo:say"],
    handler: async ({ input }) => ({ content: [{ type: "text", text: input.text }] }),
  })

  const app = new Hono()
  app.route("/", honoMiddleware(authkit, mcp))

  const server = await new Promise<ReturnType<typeof serve>>((resolve) => {
    const s = serve({ fetch: app.fetch, port, hostname: host }, () => resolve(s))
  })

  // Single machine-readable handshake line. Logs go to stderr (pino default).
  process.stdout.write(`${JSON.stringify({ url, configPath, cliBin })}\n`)
  logger.info({ url, configPath }, "e2e harness ready")

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, "shutting down")
    await new Promise<void>((resolve, reject) => {
      ;(server as unknown as { close: (cb: (err?: Error) => void) => void }).close((err) =>
        err ? reject(err) : resolve(),
      )
    })
    if (config.auth.tokenStore.close !== undefined) {
      await config.auth.tokenStore.close()
    }
    process.exit(0)
  }
  process.on("SIGTERM", () => void shutdown("SIGTERM"))
  process.on("SIGINT", () => void shutdown("SIGINT"))
}

main().catch((err) => {
  logger.error({ err }, "harness failed to start")
  process.exit(1)
})
