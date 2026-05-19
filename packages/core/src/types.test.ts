import type { IncomingMessage, ServerResponse } from "node:http"
import { z } from "zod"
import type { AuthContext, AuthKitConfig, createAuthKit, Handlers } from "./index.js"

type Assert<T extends true> = T
type IsExact<T, U> =
  (<V>() => V extends T ? 1 : 2) extends <V>() => V extends U ? 1 : 2
    ? (<V>() => V extends U ? 1 : 2) extends <V>() => V extends T ? 1 : 2
      ? true
      : false
    : false

const auth = {
  subject: "user_123",
  tokenType: "oauth",
  tokenId: "jwt_123",
  scopes: ["mcp:read"],
  expiresAt: new Date("2030-01-01T00:00:00.000Z"),
  raw: { sub: "user_123" },
} satisfies AuthContext

const handlers = {
  async mcp(_req: IncomingMessage, _res: ServerResponse): Promise<void> {},
  async metadata(_req: IncomingMessage, _res: ServerResponse): Promise<void> {},
  async pats(_req: IncomingMessage, _res: ServerResponse): Promise<void> {},
  challenge(_res: ServerResponse, _reason?: string): void {},
} satisfies Handlers

const tokenStore: AuthKitConfig["auth"]["tokenStore"] = {
  async createPat(input) {
    return {
      ...input,
      id: "pat_123",
      createdAt: new Date("2030-01-01T00:00:00.000Z"),
      lastUsedAt: null,
      revokedAt: null,
    }
  },
  async findPatByHash(_hash) {
    return null
  },
  async listPatsByUser(_userIdentifier) {
    return []
  },
  async revokePat(_id, _userIdentifier) {},
  async rotatePat(_id, _userIdentifier, next) {
    return {
      ...next,
      id: "pat_456",
      createdAt: new Date("2030-01-01T00:00:00.000Z"),
      lastUsedAt: null,
      revokedAt: null,
    }
  },
  async updatePatLastUsed(_id, _timestamp) {},
  async createRefreshToken(_input) {},
  async findRefreshToken(_hash) {
    return null
  },
  async rotateRefreshToken(_oldHash, _next) {},
  async revokeRefreshTokenFamily(_familyId) {},
}

const config = {
  resourceIndicator: "https://api.example.com/mcp",
  auth: {
    authorizationServer: {
      issuer: "https://issuer.example.com",
      jwksUri: "https://issuer.example.com/.well-known/jwks.json",
    },
    tokenStore,
    pat: {
      enabled: true,
      prefix: "mcp_pat_",
    },
    bypass: {
      enabled: false,
      user: "dev",
      scopes: ["mcp:read"],
    },
    staticToken: {
      token: "static-token",
      user: "ci",
      scopes: ["mcp:read"],
    },
  },
  scopes: {
    vocabulary: {
      "mcp:read": {
        description: "Read MCP resources",
      },
      "mcp:tool": {
        description: "Call a tool for a resource",
        resource: "toolName",
        implies: ["mcp:read"],
      },
    },
    customMatchers: [
      (required, held, ctx) =>
        required === "mcp:read" && held.includes("mcp:read") && ctx.auth.subject === auth.subject,
    ],
  },
  async resolveUserScopes(userIdentifier) {
    return userIdentifier === "user_123" ? ["mcp:read"] : []
  },
  audit: {
    onEvent(event) {
      event.detail
    },
  },
} satisfies AuthKitConfig

const options = {
  name: "hello",
  description: "Say hello",
  inputSchema: {
    name: z.string(),
  },
  requireScopes({ input, auth: toolAuth }) {
    return [`mcp:tool:${input.name}`, ...toolAuth.scopes]
  },
  async handler({ input, auth: toolAuth }) {
    return {
      content: [
        {
          type: "text",
          text: `${toolAuth.subject}: ${input.name}`,
        },
      ],
    }
  },
} satisfies import("./index.js").RegisterToolOptions<{ name: z.ZodString }>

type FactorySignature = typeof createAuthKit
type ExpectedFactorySignature = (config: AuthKitConfig) => import("./index.js").AuthKit

const factorySignatureMatches: Assert<IsExact<FactorySignature, ExpectedFactorySignature>> = true

void config
void factorySignatureMatches
void handlers
void options
