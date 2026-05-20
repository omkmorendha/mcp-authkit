// Python E2E config (spec §16). Loaded by both the harness `server.ts`
// and the `mcp-authkit mint-pat` CLI subprocess. The SQLite file path
// comes from `MCP_AUTHKIT_E2E_DB`, the resource indicator from
// `RESOURCE_INDICATOR`, so a single config file serves both processes
// with consistent state.

import Database from "better-sqlite3"
import { defineConfig } from "mcp-authkit/config"
import { sqliteTokenStore } from "mcp-authkit/stores/sqlite"

const dbPath = process.env.MCP_AUTHKIT_E2E_DB
if (dbPath === undefined || dbPath === "") {
  throw new Error("MCP_AUTHKIT_E2E_DB is required")
}
const resourceIndicator = process.env.RESOURCE_INDICATOR
if (resourceIndicator === undefined || resourceIndicator === "") {
  throw new Error("RESOURCE_INDICATOR is required")
}

// Each process opens its own handle to the same file. The store's
// `close()` will close the handle on shutdown (server) or after
// `mint-pat` completes (CLI).
const database = new Database(dbPath)

export default defineConfig({
  resourceIndicator,
  auth: {
    // No real Authorization Server is needed for this E2E — the PAT is
    // minted via the CLI and the only inbound token is that PAT. We
    // still provide a dummy AS because the schema requires `issuer` /
    // `jwksUri`; it is never contacted because no JWT is ever presented.
    authorizationServer: {
      issuer: "https://as.example.test",
      jwksUri: "https://as.example.test/.well-known/jwks.json",
    },
    tokenStore: sqliteTokenStore({ database }),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: { "echo:say": { description: "Echo a string" } } },
  resolveUserScopes: async () => ["echo:say"],
})
