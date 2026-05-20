// Filesystem (SQLite) example config. Loaded by `server.ts` via
// `loadConfig("./mcp-authkit.config.ts")` from `mcp-authkit/config`.
// The same file is what CLI helpers (`mcp-authkit verify-config`,
// `mcp-authkit mint-pat`, …) read.
//
// Spec: docs/spec/v0.2.md#58-config-file-format
//       docs/spec/v0.2.md#64-sqlite-store

import Database from "better-sqlite3"
import { defineConfig } from "mcp-authkit/config"
import { sqliteTokenStore } from "mcp-authkit/stores/sqlite"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const resourceIndicator = process.env.RESOURCE_INDICATOR ?? `http://localhost:${port}/mcp`

// The database handle belongs to the consumer (spec §6.4); `store.close()`
// is a no-op. A single file at `./mcp-authkit.db` is created on first use
// alongside WAL sidecar files (`-wal`, `-shm`).
const database = new Database(process.env.SQLITE_PATH ?? "./mcp-authkit.db")

export default defineConfig({
  resourceIndicator,
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER ?? "https://auth.example.com",
      jwksUri: process.env.OAUTH_JWKS_URI ?? "https://auth.example.com/.well-known/jwks.json",
    },
    tokenStore: sqliteTokenStore({ database }),
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
