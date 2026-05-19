/**
 * `init [path]` — scaffold a project directory.
 *
 * Writes:
 *   - mcp-authkit.config.ts  (uses `defineConfig` from mcp-authkit/config)
 *   - .env.example           (required env vars)
 *   - server.ts              (hello-world server adapted to load config)
 *   - README.md              (run instructions)
 *
 * Refuses to write into a non-empty directory unless `--force` is passed.
 *
 * Spec: docs/spec/v0.2.md#91-init
 */
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs"
import { resolve } from "node:path"
import { CliError, ExitCode } from "../exit-codes.js"
import type { CliLogger } from "../logger.js"

export interface InitOptions {
  path?: string
  force?: boolean
  logger: CliLogger
  stdout?: NodeJS.WritableStream
  cwd?: string
}

export function init(options: InitOptions): void {
  const cwd = options.cwd ?? process.cwd()
  const target = resolve(cwd, options.path ?? ".")
  const out = options.stdout ?? process.stdout

  if (existsSync(target)) {
    const entries = readdirSync(target).filter((e) => !e.startsWith("."))
    if (entries.length > 0 && options.force !== true) {
      throw new CliError(
        ExitCode.userError,
        `Refusing to write into non-empty directory: ${target}. Pass --force to override.`,
      )
    }
  } else {
    mkdirSync(target, { recursive: true })
  }

  const files: Array<{ name: string; content: string }> = [
    { name: "mcp-authkit.config.ts", content: CONFIG_TEMPLATE },
    { name: ".env.example", content: ENV_TEMPLATE },
    { name: "server.ts", content: SERVER_TEMPLATE },
    { name: "README.md", content: README_TEMPLATE },
  ]

  for (const file of files) {
    const path = resolve(target, file.name)
    if (existsSync(path) && options.force !== true) {
      throw new CliError(
        ExitCode.userError,
        `Refusing to overwrite existing file: ${path}. Pass --force to overwrite.`,
      )
    }
    writeFileSync(path, file.content, { encoding: "utf8" })
    options.logger.debug("wrote file", { path })
  }

  out.write(`Initialized mcp-authkit project at ${target}\n`)
  out.write(`  - mcp-authkit.config.ts\n`)
  out.write(`  - .env.example\n`)
  out.write(`  - server.ts\n`)
  out.write(`  - README.md\n`)
  out.write(`\nNext steps:\n`)
  out.write(`  1. cp .env.example .env  and fill in real values\n`)
  out.write(`  2. pnpm add mcp-authkit pino zod express @modelcontextprotocol/sdk\n`)
  out.write(`  3. pnpm tsx server.ts\n`)
}

const CONFIG_TEMPLATE = `import { defineConfig } from "mcp-authkit/config"
import { memoryTokenStore } from "mcp-authkit/stores/memory"

// Scaffold produced by \`mcp-authkit init\`. Swap \`memoryTokenStore\` for a
// durable store (Postgres, SQLite) before going to production.
export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR ?? "http://localhost:3000/mcp",
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER ?? "https://auth.example.com",
      jwksUri:
        process.env.OAUTH_JWKS_URI ?? "https://auth.example.com/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
    bypass: {
      enabled: process.env.MCP_AUTHKIT_BYPASS !== "0",
      user: "local-dev",
      scopes: ["echo:say"],
    },
  },
  scopes: {
    vocabulary: {
      "echo:say": { description: "Echo a string" },
    },
  },
  resolveUserScopes: async () => ["echo:say"],
})
`

const ENV_TEMPLATE = `# Required for production. Each value is also documented in mcp-authkit.config.ts.
RESOURCE_INDICATOR=http://localhost:3000/mcp
OAUTH_ISSUER=https://auth.example.com
OAUTH_JWKS_URI=https://auth.example.com/.well-known/jwks.json

# Set MCP_AUTHKIT_BYPASS=0 in production to require real tokens.
MCP_AUTHKIT_BYPASS=1
`

const SERVER_TEMPLATE = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { loadConfig } from "mcp-authkit/config"
import pino from "pino"
import { z } from "zod"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const config = await loadConfig("./mcp-authkit.config.ts")
const authkit = createAuthKit(config)

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
app.listen(port, () => pino({ name: "server" }).info({ port }, "listening"))
`

const README_TEMPLATE = `# mcp-authkit project

Scaffolded by \`mcp-authkit init\`.

## Run

\`\`\`
cp .env.example .env
pnpm add mcp-authkit pino zod express @modelcontextprotocol/sdk
pnpm tsx server.ts
\`\`\`

## Layout

- \`mcp-authkit.config.ts\` — framework configuration (issuer, JWKS, store, scopes).
- \`server.ts\` — Express host that wires \`createAuthKit\` to an MCP server.
- \`.env.example\` — required environment variables.

## CLI helpers

\`\`\`
mcp-authkit verify-config        # validate the config file
mcp-authkit jwks-fetch           # inspect the configured JWKS
mcp-authkit mint-pat --user u1 --name "demo" --scopes echo:say
mcp-authkit gen-secret           # 32 random bytes, base64url
\`\`\`
`
