# Cookbook: Hono adapter

Drop-in replacement for the Express adapter when your server is built
on [Hono](https://hono.dev). Same routes, same auth pipeline, streaming
response bodies. Spec references:
[§5.9](../spec/v0.2.md#59-hono-adapter),
[§10](../spec/v0.2.md#10-hono-adapter).

## Imports

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { serve } from "@hono/node-server"
import { Hono } from "hono"
import { createAuthKit } from "mcp-authkit"
import { honoMiddleware } from "mcp-authkit/adapters/hono"
import { loadConfig } from "mcp-authkit/config"
```

## Snippet

```ts
const config = await loadConfig("./mcp-authkit.config.ts")
const authkit = createAuthKit(config)
const mcp = new McpServer({ name: "hello", version: "0.1.0" })

// Register tools the usual way:
authkit.registerTool(mcp, { /* ... */ })

const app = new Hono()
app.route("/", honoMiddleware(authkit, mcp))

serve({ fetch: app.fetch, port: 3000 })
```

`honoMiddleware` returns a Hono sub-app with three routes mounted:

| Route                                       | Handler          |
| ------------------------------------------- | ---------------- |
| `ALL  /mcp`                                 | MCP requests     |
| `GET  /.well-known/oauth-protected-resource`| RFC 9728 metadata|
| `ALL  /pats`, `ALL /pats/*`                 | PAT CRUD         |

If you want to wire the routes yourself (custom prefixes, additional
middleware, etc.), use `honoHandlers` instead:

```ts
import { honoHandlers } from "mcp-authkit/adapters/hono"

const h = honoHandlers(authkit, mcp)
app.all("/v1/mcp", h.mcp)
app.get("/.well-known/oauth-protected-resource", h.metadata)
app.all("/v1/pats", h.pats)
app.all("/v1/pats/*", h.pats)
```

## Env vars

The adapter itself has no env vars. Configuration comes from
`mcp-authkit.config.ts` — see [postgres-store](postgres-store.md) or
[sqlite-store](sqlite-store.md) for examples.

## Body parsing

Do **not** mount a JSON body parser in front of `/mcp` or `/pats`. The
handlers read the raw request stream themselves. Hono does not parse
bodies by default, so the common path is fine — just don't add
`bodyLimit` middleware that pre-buffers.

## Streaming response

The adapter streams the MCP response body — it does not buffer. This
matters for `tools/call` results that exceed Node's default high-water
mark or for long-running SSE-style responses. The adaptation layer
attaches a `PassThrough` between the framework's `ServerResponse` and
Hono's `Response`; bytes flow as the framework writes them.

## Host header

Hono's adapter passes `c.req.raw` (a Web `Request`) through to the
underlying handler so the framework's DNS-rebinding host check sees the
real `Host` header. Behind a reverse proxy, make sure the proxy
forwards `Host` (or rewrites it to the hostname in `RESOURCE_INDICATOR`).

## What to test

- **Route parity with Express.** The Hono adapter passes the same
  handler matrix as Express (spec [§10](../spec/v0.2.md#10-hono-adapter)).
  Run the same smoke flow (mint PAT → initialize → tools/call).
- **Streaming.** Register a tool that returns a large response
  (e.g. 1 MB of text); confirm bytes arrive at the client before the
  handler finishes if your tool yields incrementally.
- **Challenge from a custom route.** Call `honoHandlers(...).challenge(c)`
  from a handler you wrote yourself; should return a 401 with
  `WWW-Authenticate: Bearer ...`.
- **Custom prefix.** Move `/mcp` to `/v1/mcp` via `honoHandlers` and
  confirm `/.well-known/oauth-protected-resource` still advertises the
  correct `resource` value (it tracks `resourceIndicator`, not the
  Hono mount point).

## Common mistakes

- **Mounting under a prefix without updating `resourceIndicator`.**
  Moving `/mcp` to `/v1/mcp` means tokens must have
  `aud: "https://host/v1/mcp"`. The config's `resourceIndicator` is the
  contract — change both together or your AS will keep issuing tokens
  the framework rejects.
- **Wrapping `app.fetch` in a custom adapter that buffers.** Don't
  parse the body upstream of the adapter. The `mcp` handler needs the
  raw `ReadableStream` from `c.req.raw`.
- **Using `app.use("*", ...)` for global middleware that returns
  early.** The auth pipeline runs inside the framework's handler; a
  global middleware that returns `c.text(...)` from a path that should
  reach `/mcp` will short-circuit the pipeline.
