// A self-contained valid config fixture. We construct a tokenStore shaped
// like the contract without importing `mcp-authkit-store-memory` so the
// fixture works even before the workspace has been built. The schema only
// checks that required slots are functions; a real createAuthKit caller
// would supply the workspace store.
const noopAsync = async () => {
  throw new Error("test fixture store: not implemented")
}

const tokenStore = {
  createPat: noopAsync,
  findPatByHash: noopAsync,
  listPatsByUser: noopAsync,
  revokePat: noopAsync,
  rotatePat: noopAsync,
  updatePatLastUsed: noopAsync,
  createRefreshToken: noopAsync,
  findRefreshToken: noopAsync,
  rotateRefreshToken: noopAsync,
  revokeRefreshTokenFamily: noopAsync,
}

export default {
  resourceIndicator: "https://mcp.example.test/",
  auth: {
    authorizationServer: {
      issuer: "https://as.example.test/",
      jwksUri: "https://as.example.test/.well-known/jwks.json",
    },
    tokenStore,
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: {
    vocabulary: {
      "files:read": { description: "Read files" },
    },
  },
  resolveUserScopes: async () => ["files:read"],
}
