// Fixture using the real workspace memory store, for tests that exercise
// `mint-pat` end-to-end (the store's `createPat` must actually succeed).
import { memoryTokenStore } from "mcp-authkit-store-memory"

export default {
  resourceIndicator: "https://mcp.example.test/",
  auth: {
    authorizationServer: {
      issuer: "https://as.example.test/",
      jwksUri: "https://as.example.test/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: {
    vocabulary: {
      "echo:say": { description: "Echo a string" },
    },
  },
  resolveUserScopes: async () => ["echo:say"],
}
