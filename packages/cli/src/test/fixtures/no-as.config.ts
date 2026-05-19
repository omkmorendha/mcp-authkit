// No authorizationServer block. Used by jwks-fetch tests to exercise the
// "config has no jwksUri, --issuer not supplied" failure path.
import { memoryTokenStore } from "mcp-authkit-store-memory"

export default {
  resourceIndicator: "https://mcp.example.test/",
  auth: {
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
}
