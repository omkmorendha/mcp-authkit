# mcp-authkit Roadmap

v0.1 shipped. This roadmap now tracks v0.2. The source of truth for
scope is [`docs/spec/v0.2.md`](docs/spec/v0.2.md); the v0.1 spec
([`docs/spec/v0.1.md`](docs/spec/v0.1.md)) remains the source of truth
for everything it covered. Anything not in either document is out of
scope for v0.2.

Stages map to the build order in spec §17. Concrete issues for each
stage are created when the prior stage is roughly 80% complete, so
plans stay grounded in what we've actually learned.

## v0.1 — shipped (2026-05-19)

All four stages and 17 issues are closed. See
[`CHANGELOG.md`](CHANGELOG.md#010--2026-05-19) for the release notes
and the [`stage-0`](https://github.com/omkmorendha/mcp-authkit/labels/stage-0)
through [`stage-4`](https://github.com/omkmorendha/mcp-authkit/labels/stage-4)
labels for the historical record.

## Stage 1 — Storage (issues live now)

Durable backends for the `TokenStore` contract. All three are
independent and can run in parallel.

- **Postgres token store**: full `TokenStore` + upstream-cache
  methods, idempotent migrations, parameterized queries, integration
  test against a real Postgres in CI. Spec §6.3.
- **SQLite token store**: same surface as Postgres against
  `better-sqlite3`, WAL mode, single-file durability. Spec §6.4.
- **Redis cache decorator**: `redisCache(innerStore, {...})`
  with HMAC-tagged values, write-invalidation, optional negative
  caching. Spec §6.5.

Recommended start: **Postgres** — exercises the migration
pattern the other stores reuse.

## Stage 2 — OAuth flows

Four independent RFC-conformance clients consumed against the AS. Each
ships with unit tests against a mock AS and an integration smoke test
against the test fixture AS.

- **Dynamic Client Registration consumer** (RFC 7591). Spec §5.2.
- **JWT Bearer Assertion grant** (RFC 7523). Spec §5.3.
- **Client Credentials grant** (RFC 6749 §4.4). Spec §5.4.
- **Token Exchange** (RFC 8693). Spec §5.5 + §8.

Build in any order. **Token Exchange** is a prerequisite for Stage 3's
upstream helper, so prioritize it if Stage 2 contributors are looking
for the critical path.

## Stage 3 — Multi-tenant and upstream credentials

Compose Stage 2 primitives into framework-level features.

- **Multi-tenant `authorizationServer` as a function form.**
  Pipeline-step ordering, per-issuer JWKS cache key, request-scoped
  memoization. Spec §5.1 + §7.
- **Upstream credential helper**: `authkit.upstreamFor(audience)`
  and `onBehalfOf(...)`. Builds on token exchange. Spec §5.6 + §8.

## Stage 4 — Adapters, CLI, config

Make v0.2 usable from outside a Node entry point.

- **Hono adapter**: streaming-response, host header passthrough,
  per-route helpers. Spec §5.9 + §10.
- **Config file format**: `defineConfig`, TS loader via `tsx`
  register hook, 10s timeout, redacted summary. Spec §5.8.
- **CLI `mcp-authkit`**: `init`, `mint-pat`, `verify-config`,
  `jwks-fetch`, `gen-secret`. Spec §5.7 + §9. Gated on the config
  loader.

## Stage 5 — Production stdio

Independent of Stages 1–4.

- **Production stdio**: signed-handshake transport with HMAC,
  monotonic counter, bypass-refused mode. Spec §11.

## Stage 6 — Examples and docs

Lands after Stages 1–5 are mostly done so examples can demonstrate the
real APIs.

- **Postgres example.**
- **Filesystem example** (SQLite store).
- **Stdio example** (production stdio).
- **Production deployment doc** + per-store cookbook entries.

## Stage 7 — Hardening and release

- **v0.2 security test matrix** per spec §12 + §13.
- **Python E2E refresh**: mint a PAT via CLI, call a tool on a Hono
  server. Spec §16.
- **Release prep**: changelog, per-package version bumps, publish
  dry-run, dependency audit. Spec §16.

## After v0.2

Deferred items live in spec §0 ("Deferred to v0.3+"). Do not start them
or stub them in v0.2 work. When v0.2 ships, the next planning pass
turns selected deferred items into v0.3 work.
