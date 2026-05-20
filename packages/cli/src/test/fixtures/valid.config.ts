// Self-contained fixture mirroring `packages/config`. Uses an in-memory
// store-shaped object so the fixture loads without the workspace build.
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
