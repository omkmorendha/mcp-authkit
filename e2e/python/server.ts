// Bypass mode is deliberately OFF so the PAT-mint REST endpoint
// genuinely exercises the JWT pipeline (spec §9, §11.1) — the harness
// signs its own short-lived JWT against an in-process JWKS instead of
// pointing at the example's fake AS. The single JSON line on stdout
// is the handshake contract with `run.sh`.

import { createServer as createHttpServer } from "node:http"
import type { AddressInfo } from "node:net"
import { createServer as createNetServer } from "node:net"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { exportJWK, generateKeyPair, SignJWT } from "jose"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
import pino from "pino"
import { z } from "zod"

const logger = pino({ name: "e2e-python", level: process.env.LOG_LEVEL ?? "warn" })

interface TestAS {
  issuer: string
  jwksUri: string
  signToken: (claims: { sub: string; aud: string; scope: string }) => Promise<string>
  close: () => Promise<void>
}

async function startTestAS(): Promise<TestAS> {
  const alg = "ES256"
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true })
  const publicJwk = await exportJWK(publicKey)
  publicJwk.kid = "e2e-key-1"
  publicJwk.alg = alg

  const jwksPayload = JSON.stringify({ keys: [publicJwk] })

  const server = createHttpServer((req, res) => {
    if (req.url === "/.well-known/jwks.json") {
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(jwksPayload)
      return
    }
    res.writeHead(404)
    res.end()
  })

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve)
  })
  const { port } = server.address() as AddressInfo
  const issuer = `http://127.0.0.1:${port}`

  return {
    issuer,
    jwksUri: `${issuer}/.well-known/jwks.json`,
    signToken: async (claims) =>
      new SignJWT({ scope: claims.scope })
        .setProtectedHeader({ alg, kid: "e2e-key-1" })
        .setIssuedAt()
        .setIssuer(issuer)
        .setSubject(claims.sub)
        .setAudience(claims.aud)
        .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
        .sign(privateKey),
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  }
}

// Ask the kernel for a free port, then release it. There's a tiny TOCTOU
// window but it's acceptable for a local e2e harness.
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
  const as = await startTestAS()

  const host = "127.0.0.1"
  const envPort = process.env.PORT
  const port =
    envPort !== undefined && envPort !== "" ? Number.parseInt(envPort, 10) : await pickFreePort()
  const url = `http://${host}:${port}`
  const resourceIndicator = `${url}/mcp`

  const authkit = createAuthKit({
    resourceIndicator,
    auth: {
      authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
      tokenStore: memoryTokenStore(),
      pat: { enabled: true, prefix: "mcp_pat_" },
    },
    scopes: { vocabulary: { "echo:say": { description: "Echo a string" } } },
    resolveUserScopes: async () => ["echo:say"],
  })

  const mcp = new McpServer({ name: "e2e", version: "0.1.0" })
  authkit.registerTool(mcp, {
    name: "echo",
    description: "Echo input",
    inputSchema: { text: z.string() },
    requireScopes: ["echo:say"],
    handler: async ({ input }) => ({ content: [{ type: "text", text: input.text }] }),
  })

  const h = expressHandlers(authkit, mcp)
  const app = express()
  app.use("/mcp", h.mcp)
  app.use("/.well-known/oauth-protected-resource", h.metadata)
  app.use("/pats", h.pats)

  const httpServer = app.listen(port, host)
  await new Promise<void>((resolve) => httpServer.once("listening", resolve))

  const jwt = await as.signToken({
    sub: "e2e-user",
    aud: resourceIndicator,
    scope: "echo:say",
  })

  // Single machine-readable handshake line. Logs go to stderr (pino default).
  process.stdout.write(`${JSON.stringify({ url, jwt })}\n`)
  logger.info({ url, issuer: as.issuer }, "e2e harness ready")

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, "shutting down")
    await new Promise<void>((resolve) => httpServer.close(() => resolve()))
    await as.close()
    process.exit(0)
  }
  process.on("SIGTERM", () => void shutdown("SIGTERM"))
  process.on("SIGINT", () => void shutdown("SIGINT"))
}

main().catch((err) => {
  logger.error({ err }, "harness failed to start")
  process.exit(1)
})
