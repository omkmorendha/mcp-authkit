# Cookbook

Per-store, per-adapter, per-flow recipes. Each page is a focused, working
configuration — no hidden defaults, no missing imports — for one specific
deployment shape. Pick the one closest to your target and adapt.

## Storage

- [**Postgres token store**](./postgres-store) — durable, multi-process,
  battle-tested. Use this in production unless you have a reason not to.
- [**SQLite token store**](./sqlite-store) — single-node, file-backed.
  Right for stateful CLIs and filesystem-style MCP servers.
- [**Redis cache decorator**](./redis-cache) — wraps an underlying store
  with a read-mostly cache. Not a primary store; pair with Postgres or
  SQLite.

## Web framework

- [**Hono adapter**](./hono-adapter) — Express adapter ships in the
  quickstart; this is the Hono mirror. Same Handlers surface underneath.

## OAuth shapes

- [**Multi-tenant**](./multi-tenant) — function-form `authorizationServer`
  with per-issuer JWKS caching. One server, many ASs.
- [**Upstream credentials**](./upstream-credentials) — RFC 8693 token
  exchange. Mint a downstream token for a third-party API without
  exposing the caller's subject token.

## Transports

- [**Production stdio**](./production-stdio) — HMAC-signed-handshake
  stdio transport. Every frame verified; bypass mode refuses to coexist.
