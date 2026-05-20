# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] — 2026-05-20

First release published via **npm Trusted Publishers** (OIDC, no
`NPM_TOKEN` secret). Each package on npmjs.com now carries a Provenance
attestation tying the tarball to a specific GitHub Actions run and
commit SHA.

### Changed

- **CI / release** — `.github/workflows/release.yml` publishes every
  public workspace package to npmjs.org on `v*` tag push, using OIDC.
  `pnpm -r publish --access public --provenance --no-git-checks`. No
  source changes; same artifact contents as 0.2.0 plus the provenance
  attestation.
- Dependabot dev-dep updates from the `types` group and the GitHub
  Actions group (`actions/checkout`, `actions/setup-node`,
  `actions/setup-python`). Test- and CI-only; no runtime surface
  changed.

## [0.2.0] — 2026-05-20

First npm release: all 9 packages published to the public registry on
2026-05-20 from `304ef2b`. Released to `latest` under unscoped names
(`mcp-authkit`, `mcp-authkit-adapter-{express,hono}`,
`mcp-authkit-store-{memory,postgres,sqlite,redis}`, `mcp-authkit-config`,
`mcp-authkit-cli`). The published tarballs include three fixes (#108,
#110, #111) that landed after the original release-prep commit (#104);
they are listed under "Fixed" below.

Second release. Implements the full v0.2 spec
([`docs/spec/v0.2.md`](docs/spec/v0.2.md)) and nothing beyond it. v0.2
turns the v0.1 core into a production-deployable framework by shipping
every item that v0.1 §0 deferred.

### Added

- **Postgres token store (`mcp-authkit-store-postgres`)** — durable
  `TokenStore` backed by `node-postgres`. Stores PATs, refresh-token
  families, and the upstream-credential cache. Integration tests run
  against a real Postgres in CI.
- **SQLite token store (`mcp-authkit-store-sqlite`)** — durable
  single-node `TokenStore` backed by `better-sqlite3`. Same interface
  as Postgres; suitable for filesystem-style deployments.
- **Redis cache decorator (`mcp-authkit-store-redis`)** — wraps an
  underlying store and caches read-mostly paths. Not a primary store:
  writes go through to the underlying store; cache invalidates on
  revoke / rotate.
- **Hono adapter (`mcp-authkit-adapter-hono`)** — thin wrappers over
  the framework-agnostic handlers, passing the same handler matrix
  as Express. Core has zero Hono imports.
- **`mcp-authkit` CLI (`mcp-authkit-cli`)** — `init`, `mint-pat`,
  `verify-config`, `jwks-fetch`, `gen-secret`. Each subcommand is
  covered by a subprocess test.
- **Config file format (`mcp-authkit-config`)** — `defineConfig()`
  identity helper plus a bounded `tsx`-backed loader that the CLI
  consumes (`mcp-authkit.config.ts`).
- **Multi-tenant authorization server** — `authorizationServer` now
  also accepts a function `(req) => AuthorizationServer | Promise<...>`,
  resolved per-request. Single-AS form is unchanged.
- **RFC 7591 Dynamic Client Registration consumer** — registers the
  framework as a client at startup against AS metadata; persists the
  resulting `client_id` / `client_secret` via the configured store.
- **RFC 7523 JWT Bearer Assertion grant** — exchange a signed
  assertion for an upstream access token.
- **RFC 6749 §4.4 Client Credentials grant** — service-to-service
  token acquisition for upstream APIs.
- **RFC 8693 Token Exchange** — generic token-exchange helper plus
  on-behalf-of (`actor_token`) flow built on it.
- **Upstream credential helper (`mcp-authkit/upstream`)** — resolves a
  cached upstream credential for an authenticated MCP request, with
  audience-bound caching keyed on the MCP subject and the upstream
  resource indicator. Refuses cleanly when `authorizationServer` is
  in function form.
- **Production stdio support (`mcp-authkit/stdio`)** —
  signed-handshake transport for non-browser deployments. HMAC
  comparison is constant time; the bypass-mode local-dev path is
  unchanged.
- **Examples** — `postgres` (Postgres store), `filesystem` (SQLite
  store), and `stdio` (signed-handshake stdio).
- **Production deployment guide and cookbooks** — walks an operator
  from "I have a Postgres URL" to "I have a running server", with
  per-store and per-adapter cookbook pages covering the matrix.
- **v0.2 security test matrix** — covers spec §12 additions on top
  of the v0.1 §14 matrix.
- **Python E2E test (refresh)** — mints a PAT through the CLI as a
  subprocess and exercises a Hono server.

### Fixed

- **CLI binary now ships from the primary `mcp-authkit` package** (#108).
  Previously only `mcp-authkit-cli` exposed the `mcp-authkit` bin, so a
  user running `pnpm add mcp-authkit` followed by `pnpm exec mcp-authkit`
  (as the README and production guide instruct) hit "command not found".
  A thin ESM shebang wrapper under `packages/core/src/bin/mcp-authkit.ts`
  delegates to `mcp-authkit-cli`'s `run()`.
- **Token-exchange subject audience is validated before the AS request**
  (#110). Spec v0.2 §8 requires the subject token passed to
  `exchangeToken` to have `aud == resourceIndicator`. The previous
  implementation only validated the minted token returned by the AS,
  allowing a wrong-audience subject token to reach the AS first.
  `exchangeToken` gains an `expectedSubjectAudience` input; opaque
  (non-JWT) subject tokens fail closed.
- **`upstreamFor` supports the function-form `authorizationServer`**
  (#111). Previously the helper refused at call time when the AS was
  configured as a per-request resolver (spec v0.2 §5.1), making the
  multi-tenant code path incompatible with RFC 8693 token exchange.
  The issuer is now resolved per call from `auth.raw.iss` and included
  in the upstream-credential cache key so two tenants minting tokens
  for the same upstream audience cannot collide. PAT-, static-, and
  bypass-authenticated `AuthContext`s are rejected with a clear error
  naming the `tokenType`. No public API change.

### Changed

- All publishable packages bumped to `0.2.0`; examples and the Python
  E2E harness are aligned to the same version.

### Security

This release extends the spec §14 non-negotiables (still enforced)
with the v0.2 §12 additions:

- Every new OAuth consumer (DCR, JWT Bearer, Client Credentials,
  Token Exchange) enforces audience binding; tokens minted for MCP
  are never forwarded upstream, and upstream-bound tokens never
  satisfy MCP audience checks.
- The upstream credential helper refuses to operate when
  `authorizationServer` is in function form, avoiding cross-tenant
  credential reuse in multi-tenant deployments.
- Signed-handshake stdio uses `crypto.timingSafeEqual` for HMAC
  comparison.
- All durable stores hash PATs at rest with SHA-256 and perform
  constant-time hash comparison; the Redis cache decorator never
  caches plaintext PAT material.
- Refresh-token rotation, family revocation, and bypass production
  refusal carry over unchanged through the durable stores.

### Public API

- Zero exposed `any` types in the published surface of every v0.2
  package.
- `pnpm audit --audit-level high` exits clean.

### Deferred (not in this release)

Per spec §0: UI components for PAT management, gRPC adapter, a
built-in authorization server (Mode B), cloud-vendor IAM helpers,
token revocation broadcast, and anomaly-detection / rate-limiting
middleware. v0.2 remains Mode A only.

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

[0.2.0]: https://github.com/omkmorendha/mcp-authkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/omkmorendha/mcp-authkit/releases/tag/v0.1.0
