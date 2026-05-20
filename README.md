# mcp-authkit

[![CI](https://github.com/omkmorendha/mcp-authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/omkmorendha/mcp-authkit/actions/workflows/ci.yml)

> **Status: v0.2 in development.** The active spec is
> [`docs/spec/v0.2.md`](docs/spec/v0.2.md); the v0.1 baseline lives at
> [`docs/spec/v0.1.md`](docs/spec/v0.1.md).

mcp-authkit is a framework-agnostic auth toolkit for Model Context Protocol servers: it helps server authors validate spec-compliant OAuth 2.1 tokens, issue Personal Access Tokens for scripts and CI, and enforce per-tool authorization without wiring auth logic into every handler.

## v0.1 scope

- Core package with token validation, PATs, scope matching, framework-agnostic handlers, bypass mode, and audit callbacks.
- In-process `memoryTokenStore` for tests and local development.
- Express adapter as the first web framework integration.
- `hello-world` example with a minimal protected HTTP server and PAT issuance.
- Unit, integration, and security tests for the core package.
- Quickstart documentation that gets a developer to a running protected server.

## Deferred

The full deferred list lives in [spec §0](docs/spec/v0.1.md#0-v01-scope). v0.1 will not include:

- Postgres, SQLite, Redis, filesystem, or production stdio support.
- Hono adapter or additional examples beyond `hello-world`.
- CLI commands or `mcp-authkit.config.ts`.
- Multi-tenant authorization server mode.
- Dynamic Client Registration, JWT Bearer Assertion, Client Credentials, token exchange, or on-behalf-of helpers.

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
