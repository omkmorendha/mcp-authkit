# mcp-authkit

[![CI](https://github.com/omkmorendha/mcp-authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/omkmorendha/mcp-authkit/actions/workflows/ci.yml)

> **Status: v0.2.0 shipped (2026-05-20).** The active spec is
> [`docs/spec/v0.2.md`](docs/spec/v0.2.md); the v0.1 baseline lives at
> [`docs/spec/v0.1.md`](docs/spec/v0.1.md).

mcp-authkit is a framework-agnostic auth toolkit for Model Context Protocol servers: it helps server authors validate spec-compliant OAuth 2.1 tokens, issue Personal Access Tokens for scripts and CI, and enforce per-tool authorization without wiring auth logic into every handler.

## What's in v0.2

- Core package with token validation, PATs, scope matching, framework-agnostic handlers, bypass mode, and audit callbacks.
- Token stores: in-process `memoryTokenStore`, durable Postgres and SQLite stores, optional Redis cache decorator.
- Web framework adapters: Express and Hono.
- OAuth consumer flows: Dynamic Client Registration (RFC 7591), JWT Bearer Assertion (RFC 7523), Client Credentials (RFC 6749 §4.4), Token Exchange (RFC 8693).
- Multi-tenant `authorizationServer(req)` function form with per-issuer JWKS caching.
- Upstream credential helper (`authkit.upstreamFor(audience)`) for on-behalf-of token minting.
- Production stdio transport with signed handshake.
- `mcp-authkit` CLI (`init`, `mint-pat`, `verify-config`, `jwks-fetch`, `gen-secret`) and `mcp-authkit.config.ts` loader.
- Examples: `hello-world`, `postgres`, `filesystem` (SQLite), `stdio`.
- Production deployment guide and per-store cookbook.

See [`CHANGELOG.md`](CHANGELOG.md) for the full release notes.

## Quickstart

The [`docs/quickstart.md`](docs/quickstart.md) guide walks you from
`pnpm add mcp-authkit` to a running OAuth-protected MCP server,
minting a PAT with `curl`, and calling a tool — in a few minutes,
with no prior MCP experience required.

## Docs

- Quickstart: [`docs/quickstart.md`](docs/quickstart.md) — local dev to a
  running protected server.
- Production guide: [`docs/production.md`](docs/production.md) — operator
  walkthrough from a Postgres URL to a running server.
- Cookbook: [`docs/cookbook/`](docs/cookbook/) — per-store, per-adapter,
  per-flow recipes (Postgres, SQLite, Redis, Hono, multi-tenant,
  upstream credentials, production stdio).
- Spec: [`docs/spec/v0.2.md`](docs/spec/v0.2.md) (active),
  [`docs/spec/v0.1.md`](docs/spec/v0.1.md) (baseline).
- Release notes: [`CHANGELOG.md`](CHANGELOG.md)
