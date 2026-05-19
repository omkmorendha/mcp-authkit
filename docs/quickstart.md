# Quickstart

This guide takes you from an empty directory to a running, OAuth-protected
[Model Context Protocol (MCP)](https://modelcontextprotocol.io) server in a
few minutes. By the end you will:

1. Install `mcp-authkit` and start an Express MCP server.
2. Mint a Personal Access Token (PAT) with `curl`.
3. Call a tool with that PAT and see the expected response.

It assumes Node.js 20+ and a recent `pnpm` (or `npm`/`yarn` — examples use
`pnpm`). No prior MCP experience required.

> **Spec reference.** This guide implements the v0.1 happy path defined in
> [`docs/spec/v0.1.md`](spec/v0.1.md). When something here is ambiguous, the
> spec wins.

---

## 1. What is mcp-authkit?

MCP servers expose tools to AI clients over HTTP (or stdio). The MCP
authorization spec (2025-06-18) requires those servers to:

- Validate **OAuth 2.1 bearer tokens** issued by an external authorization
  server (Auth0, WorkOS, Keycloak, Cognito, your own).
- Reject tokens whose `aud` claim does not match the server's
  **resource indicator** ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)).
- Publish [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)
  protected-resource metadata at a well-known URL.
- Never forward an MCP-audience token to an upstream API.

`mcp-authkit` implements that pipeline once, so your server code only deals
with **tools and scopes**. It also issues
[Personal Access Tokens](spec/v0.1.md#8-personal-access-tokens) for the
people and CI jobs that cannot run an OAuth dance — scripts, smoke tests,
the curl examples below.

This quickstart uses:

- The core `mcp-authkit` package.
- The in-memory token store (`mcp-authkit/stores/memory`).
- The Express adapter (`mcp-authkit/adapters/express`).
- The `@modelcontextprotocol/sdk` server runtime.

---

## 2. Project setup

```bash
mkdir hello-mcp && cd hello-mcp
pnpm init
pnpm pkg set type=module
pnpm add mcp-authkit @modelcontextprotocol/sdk express pino zod
pnpm add -D typescript tsx @types/node @types/express
```

Create a minimal `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist"
  },
  "include": ["src"]
}
```

---

## 3. Write the server

Save the following as `src/index.ts`. This is the entire server — well
under 50 lines, matching the [§6.2 target](spec/v0.1.md#62-usage-hello-world-target-under-50-lines).

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express from "express"
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
import pino from "pino"
import { z } from "zod"

const port = Number.parseInt(process.env.PORT ?? "3000", 10)
const resourceIndicator =
  process.env.RESOURCE_INDICATOR ?? `http://localhost:${port}/mcp`

const authkit = createAuthKit({
  resourceIndicator,
  auth: {
    authorizationServer: {
      issuer: "https://auth.example.com",
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
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

const mcp = new McpServer({ name: "hello", version: "0.1.0" })

authkit.registerTool(mcp, {
  name: "echo",
  description: "Echo input",
  inputSchema: { text: z.string() },
  requireScopes: ["echo:say"],
  handler: async ({ input }) => ({
    content: [{ type: "text", text: input.text }],
  }),
})

const h = expressHandlers(authkit, mcp)
const app = express() // no express.json(): handlers read the raw stream
app.use("/mcp", h.mcp)
app.use("/.well-known/oauth-protected-resource", h.metadata)
app.use("/pats", h.pats)
app.listen(port, () =>
  pino({ name: "hello" }).info({ port }, "listening"),
)
```

### What just happened

- `createAuthKit(config)` wires up the
  [token-validation pipeline](spec/v0.1.md#9-token-validation-pipeline):
  every accepted token must have `aud === resourceIndicator`. No exceptions.
- `tokenStore: memoryTokenStore()` stores PATs and refresh tokens in
  process memory. Fine for dev and tests; replace with a durable store
  before production (deferred to v0.2).
- `bypass` is **on by default for local dev**. Every request is
  synthesised as user `local-dev` with the `echo:say` scope. Set
  `MCP_AUTHKIT_BYPASS=0` to require real tokens. Bypass refuses to start
  in `NODE_ENV=production` unless you explicitly opt in
  ([spec §11](spec/v0.1.md#11-bypass-mode-and-stdio),
  [§14](spec/v0.1.md#14-security-non-negotiables)).
- `registerTool` enforces the `requireScopes` list before invoking your
  handler — scopes the calling token does not hold result in a 403-style
  MCP error, audited as `scope.deny`.
- `expressHandlers(authkit, mcp)` returns three mount points:
  - `/mcp` — MCP requests (Streamable HTTP).
  - `/.well-known/oauth-protected-resource` — RFC 9728 metadata.
  - `/pats` — PAT CRUD (mint, list, revoke, rotate).

> Do **not** mount `express.json()` in front of `/mcp` or `/pats` — the
> handlers read the raw request stream themselves.

---

## 4. Run it

```bash
pnpm exec tsx src/index.ts
```

You should see:

```json
{"level":30,"time":...,"name":"hello","port":3000,"msg":"listening"}
```

Leave it running and open a second terminal.

---

## 5. Mint a PAT with curl

PATs are the human/script equivalent of OAuth tokens. The plaintext token
is returned **exactly once**; only its SHA-256 hash is kept on the server
([spec §8](spec/v0.1.md#8-personal-access-tokens)).

```bash
curl -sX POST http://localhost:3000/pats \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke","scopes":["echo:say"]}'
```

Response:

```json
{
  "token": "mcp_pat_AAAA...BBBB",
  "pat": {
    "id": "...",
    "name": "smoke",
    "scopes": ["echo:say"],
    "createdAt": "...",
    "expiresAt": "..."
  }
}
```

Copy the `token` value. Export it for the next step:

```bash
export PAT='mcp_pat_AAAA...BBBB'
```

You can list (`GET /pats`), revoke (`DELETE /pats/:id`) and rotate
(`POST /pats/:id/rotate`) at any time. PAT-authenticated requests cannot
manage PATs themselves — that endpoint requires an OAuth-authenticated
caller ([spec §8.6](spec/v0.1.md#8-personal-access-tokens),
[§14](spec/v0.1.md#14-security-non-negotiables)).

---

## 6. Call the echo tool

MCP's Streamable HTTP transport requires an `Mcp-Session-Id` header on
every request after `initialize`. Initialize first:

```bash
curl -isX POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $PAT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2025-06-18","capabilities":{},
       "clientInfo":{"name":"smoke","version":"0"}}}'
```

Look at the response headers for `Mcp-Session-Id: <uuid>` and export it:

```bash
export SID='<uuid-from-headers>'
```

Now call the tool:

```bash
curl -sX POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $PAT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"echo","arguments":{"text":"hello"}}}'
```

Expected (Streamable HTTP wraps the JSON-RPC response in an SSE event):

```text
event: message
data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hello"}]}}
```

That's the round trip: PAT → token-validation pipeline → scope gate
(`echo:say` satisfied) → your handler.

---

## 7. Turning off bypass

In real deployments you'll want OAuth tokens, not bypass:

```bash
MCP_AUTHKIT_BYPASS=0 pnpm exec tsx src/index.ts
```

With bypass off, every request needs either a valid OAuth bearer (for
`/pats` and `/mcp`) or a PAT (for `/mcp` only). Requests to `/pats` with a
PAT return `403`. Replace the placeholder `authorizationServer` config
with your real issuer's `issuer` URL and `jwksUri`.

---

## 8. What to read next

- [`docs/spec/v0.1.md`](spec/v0.1.md) — the full v0.1 specification.
- [`examples/hello-world/`](../examples/hello-world/) — a runnable copy of
  the server above, used by the CI smoke and Python E2E suites.
- [`CHANGELOG.md`](../CHANGELOG.md) — what shipped in 0.1.0.

If something in this quickstart doesn't work, please open an issue with
the failing command and the response you got. The quality bar for v0.1
([spec §18](spec/v0.1.md#18-quality-bar-for-v01)) explicitly includes
"reads cleanly to someone who's never used MCP" — discrepancies are bugs.
