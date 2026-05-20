---
layout: home

hero:
  name: mcp-authkit
  text: OAuth + PAT for MCP servers.
  tagline: >-
    Validate spec-compliant OAuth 2.1 tokens, mint Personal Access Tokens for
    scripts and CI, and enforce per-tool scopes — without wiring auth into
    every handler.
  image:
    src: /logo.svg
    alt: mcp-authkit
  actions:
    - theme: brand
      text: Quickstart
      link: /quickstart
    - theme: alt
      text: View on GitHub
      link: https://github.com/omkmorendha/mcp-authkit
    - theme: alt
      text: npm
      link: https://www.npmjs.com/package/mcp-authkit

features:
  - icon: 🔐
    title: OAuth 2.1 the right way
    details: >-
      Audience validation, JWKS caching, signature checks, expiry — all
      enforced before your handler runs. Spec §14 non-negotiables are
      hard-coded; you can't accidentally skip them.

  - icon: 🎟️
    title: Personal Access Tokens
    details: >-
      Long-lived tokens for scripts, CI, and humans. SHA-256 hashed at rest,
      constant-time compared, scoped per token. Rotation mints a new token
      and revokes the previous family.

  - icon: 🎯
    title: Per-tool scope enforcement
    details: >-
      requireScopes can be static or a function of the call. The framework
      runs the matcher before your handler, so a missing scope is a 401, not
      a leaked side effect.

  - icon: 🧩
    title: Bring your framework
    details: >-
      Express and Hono adapters ship in-tree. The core is framework-agnostic —
      the adapters are thin wrappers over Handlers that any Node HTTP stack
      can mount.

  - icon: 🗄️
    title: Pluggable token stores
    details: >-
      In-memory, Postgres, SQLite, with an optional Redis cache decorator.
      Same TokenStore interface; pick the one that matches your deployment.

  - icon: 🛰️
    title: Multi-tenant ready
    details: >-
      authorizationServer is either a static config or a per-request resolver.
      Two tenants on two different ASs share a JWKS cache safely; tokens
      never cross audience boundaries.

  - icon: 🤝
    title: Upstream credentials (RFC 8693)
    details: >-
      upstreamFor() exchanges the caller's subject token for a downstream
      token bound to an upstream API. No token passthrough; the framework
      enforces the boundary.

  - icon: 🧪
    title: Production-grade defaults
    details: >-
      Bypass mode refuses production unless explicitly opted-in. DNS-rebinding
      protection on by default. Refresh-token reuse revokes the family. PATs
      can't manage PATs.

  - icon: 📜
    title: Spec is law
    details: >-
      docs/spec/v0.2.md is the source of truth. Every behavior is anchored to
      a section number. No undocumented surface, no surprise breaking changes
      between minors.
---

<div style="max-width: 960px; margin: 4rem auto 0; padding: 0 1.5rem;">

## Install

```bash
pnpm add mcp-authkit
# or: npm install mcp-authkit / yarn add mcp-authkit / bun add mcp-authkit
```

## A complete protected MCP server

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
import { z } from "zod"

const authkit = createAuthKit({
  resourceIndicator: "https://api.example.com/mcp",
  auth: {
    authorizationServer: {
      issuer: "https://auth.example.com",
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "ex_pat_" },
  },
  scopes: { vocabulary: { "echo:say": { description: "Echo a string" } } },
  resolveUserScopes: async () => ["echo:say"],
})

const mcp = new McpServer({ name: "echo", version: "0.1.0" })

authkit.registerTool(mcp, {
  name: "echo",
  description: "Echo input",
  inputSchema: { text: z.string() },
  requireScopes: ["echo:say"],
  handler: async ({ input }) => ({ content: [{ type: "text", text: input.text }] }),
})

const h = expressHandlers(authkit, mcp)
const app = express()
app.use("/mcp", h.mcp)
app.use("/.well-known/oauth-protected-resource", h.metadata)
app.use("/pats", h.pats)
app.listen(3000)
```

That's a working, spec-compliant, production-shaped MCP server with audience-validated
JWT auth, PAT support, scope enforcement, and RFC 9728 protected resource metadata —
in under 30 lines.

[**Continue to the quickstart →**](/quickstart)

</div>
