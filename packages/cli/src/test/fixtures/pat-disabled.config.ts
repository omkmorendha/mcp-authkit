import { memoryTokenStore } from "mcp-authkit-store-memory"

export default {
  resourceIndicator: "https://mcp.example.test/",
  auth: {
    authorizationServer: {
      issuer: "https://as.example.test/",
      jwksUri: "https://as.example.test/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
    pat: { enabled: false },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
}
