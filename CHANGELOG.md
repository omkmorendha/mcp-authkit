# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-19

First release. Implements the full v0.1 spec
([`docs/spec/v0.1.md`](docs/spec/v0.1.md)) and nothing beyond it.

### Added

- **Core package (`mcp-authkit`)** — `createAuthKit(config)` factory; token
  validation pipeline (JWT via JWKS, RFC 7662 introspection for opaque
  tokens); RFC 8707 audience enforcement; scope vocabulary with wildcard,
  implication and set utilities; framework-agnostic `Handlers`
  (`mcp`, `metadata`, `pats`); audit callbacks for every accept / reject /
  scope decision; bypass mode (default-on for local dev, refuses
  production without explicit opt-in); stdio auto-enable.
- **Personal Access Tokens** — mint / list / revoke / rotate, SHA-256
  hashed at rest, CRC32-checksum format, constant-time hash comparison,
  `lastUsedAt` tracking. PAT-authenticated requests to `/pats` return
  403 (cannot mint or manage other PATs).
- **Memory token store (`mcp-authkit/stores/memory`)** — single-process,
  non-durable; implements the full `TokenStore` interface. Suitable for
  tests and local development.
- **Express adapter (`mcp-authkit/adapters/express`)** — thin wrappers
  over the framework-agnostic handlers. Core has zero Express imports.
- **Hello-world example** (`examples/hello-world`) — runnable protected
  MCP server in under 50 lines.
- **Python end-to-end test** (`e2e/python`) — mints a PAT and calls the
  echo tool with `requests` only, on every CI run.
- **Quickstart documentation** (`docs/quickstart.md`).
- **Security test matrix** covering every item in spec §14: audience
  validation, no token passthrough, constant-time secret comparison,
  PAT hashing at rest, PAT self-management refusal, DNS rebinding
  (Host header) protection, refresh-token rotation with family
  revocation, bypass production refusal.

### Security

This release enforces the spec §14 non-negotiables:

- Every accepted token has `aud === resourceIndicator`.
- The framework never forwards MCP-audience tokens upstream.
- All secret-equality checks use `crypto.timingSafeEqual` with length guards.
- PATs are SHA-256 hashed at rest; plaintext is returned exactly once at mint.
- Host header validation is on by default (DNS rebinding protection).
- Refresh-token rotation revokes the entire family on reuse.
- Bypass refuses to start when `NODE_ENV=production` unless
  `bypass.allowInProduction: true` is set explicitly and is logged loudly
  on startup.

### Public API

- Zero exposed `any` types in the published surface
  (`packages/core/src/index.ts`, `packages/store-memory/src/index.ts`,
  `packages/adapter-express/src/index.ts`). The two internal `any`s in
  `registerTool` are at the MCP SDK callback boundary, suppressed with
  explicit `biome-ignore` comments, and do not appear in any exported
  type signature.
- `pnpm audit --audit-level high` exits clean.

### Deferred (not in this release)

Per spec §0: Postgres / SQLite / Redis stores, Hono adapter, the
`mcp-authkit` CLI, `mcp-authkit.config.ts` config file format,
multi-tenant authorization server, Dynamic Client Registration
(RFC 7591), JWT Bearer Assertion (RFC 7523), Client Credentials
(RFC 6749 §4.4), token exchange (RFC 8693), production stdio support,
and on-behalf-of upstream flows.

[0.1.0]: https://github.com/omkmorendha/mcp-authkit/releases/tag/v0.1.0
