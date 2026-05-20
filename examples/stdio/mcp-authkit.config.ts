// Production stdio example config (spec v0.2 §11). The signed-handshake
// stdio mode HMAC-signs every response and verifies every inbound frame;
// bypass mode is refused. Only PATs or the static token authenticate.

import { defineConfig } from "mcp-authkit/config"
import { memoryTokenStore } from "mcp-authkit/stores/memory"

const hmacKey = process.env.MCP_AUTHKIT_HMAC_KEY
if (!hmacKey || hmacKey.length === 0) {
  throw new Error(
    "MCP_AUTHKIT_HMAC_KEY is required. Generate one with `pnpm --filter mcp-authkit-cli exec mcp-authkit gen-secret`.",
  )
}

const staticToken = process.env.MCP_AUTHKIT_STATIC_TOKEN
if (!staticToken || staticToken.length === 0) {
  throw new Error(
    "MCP_AUTHKIT_STATIC_TOKEN is required. Generate one with `pnpm --filter mcp-authkit-cli exec mcp-authkit gen-secret`.",
  )
}

export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR ?? "mcp-authkit://stdio/local",
  auth: {
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
    staticToken: {
      token: staticToken,
      user: "stdio-local",
      scopes: ["echo:say"],
    },
    stdio: { mode: "signed", hmacKey },
  },
  scopes: { vocabulary: { "echo:say": { description: "Echo a string" } } },
  resolveUserScopes: async () => ["echo:say"],
})
