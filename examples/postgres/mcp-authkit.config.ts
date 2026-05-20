// Postgres example config. Loaded by `server.ts` via
// `loadConfig("./mcp-authkit.config.ts")` from `mcp-authkit/config`.
// The same file is what CLI helpers (`mcp-authkit verify-config`,
// `mcp-authkit mint-pat`, …) read.
//
// Spec: docs/spec/v0.2.md#58-config-file-format
//       docs/spec/v0.2.md#63-postgres-store

import { defineConfig } from "mcp-authkit/config"
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { Pool } from "pg"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const resourceIndicator = process.env.RESOURCE_INDICATOR ?? `http://localhost:${port}/mcp`

// The pool belongs to the consumer (spec §6.3); `store.close()` is a no-op.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? "postgres://authkit@localhost:5432/authkit_test",
})

export default defineConfig({
  resourceIndicator,
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER ?? "https://auth.example.com",
      jwksUri: process.env.OAUTH_JWKS_URI ?? "https://auth.example.com/.well-known/jwks.json",
    },
    tokenStore: postgresTokenStore({ pool }),
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
