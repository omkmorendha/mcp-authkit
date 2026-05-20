# mcp-authkit-adapter-hono

Hono adapter for `mcp-authkit`.

Most users should import it through the core package:

```ts
import { honoMiddleware } from "mcp-authkit/adapters/hono"
```

The adapter mounts the framework-agnostic MCP, metadata, and PAT handlers
on a Hono app. Internally it adapts Hono's `Context` (Web Fetch
`Request`/`Response`) to Node-style `IncomingMessage`/`ServerResponse`,
streaming responses without buffering.

See [`docs/spec/v0.2.md#59-hono-adapter`](../../docs/spec/v0.2.md#59-hono-adapter)
for the contract and
[`docs/cookbook/hono-adapter.md`](../../docs/cookbook/hono-adapter.md)
for the operator-facing recipe (route layout, streaming, host header).
