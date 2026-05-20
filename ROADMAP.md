# mcp-authkit Roadmap

v0.1 and v0.2 have shipped. The source of truth for v0.2 scope is
[`docs/spec/v0.2.md`](docs/spec/v0.2.md); the v0.1 spec
([`docs/spec/v0.1.md`](docs/spec/v0.1.md)) remains authoritative for
everything it covered.

## v0.1 — shipped (2026-05-19)

All four stages and 17 issues are closed. See
[`CHANGELOG.md`](CHANGELOG.md#010--2026-05-19) for the release notes
and the [`stage-0`](https://github.com/omkmorendha/mcp-authkit/labels/stage-0)
through [`stage-4`](https://github.com/omkmorendha/mcp-authkit/labels/stage-4)
labels for the historical record.

## v0.2 — shipped (2026-05-20)

All seven stages closed. Release notes:
[`CHANGELOG.md`](CHANGELOG.md#020--2026-05-20).

- **Stage 1 — Storage.** Postgres and SQLite token stores; Redis cache
  decorator with HMAC-tagged values and write-invalidation. Spec §6.3–§6.5.
- **Stage 2 — OAuth flows.** RFC 7591 Dynamic Client Registration, RFC
  7523 JWT Bearer Assertion, RFC 6749 §4.4 Client Credentials, RFC 8693
  Token Exchange. Spec §5.2–§5.5 + §8.
- **Stage 3 — Multi-tenant and upstream credentials.** Function-form
  `authorizationServer(req)` with per-issuer JWKS cache; `authkit.upstreamFor`
  / `onBehalfOf` helper. Spec §5.1, §5.6, §7, §8.
- **Stage 4 — Adapters, CLI, config.** Hono adapter; `mcp-authkit.config.ts`
  loader with `defineConfig`; `mcp-authkit` CLI (`init`, `mint-pat`,
  `verify-config`, `jwks-fetch`, `gen-secret`). Spec §5.7–§5.9, §9, §10.
- **Stage 5 — Production stdio.** Signed-handshake transport (HMAC,
  monotonic counter, bypass-refused). Spec §11.
- **Stage 6 — Examples and docs.** Postgres, filesystem (SQLite), and
  stdio examples; production deployment guide and per-store cookbook.
- **Stage 7 — Hardening and release.** v0.2 security test matrix per
  spec §12 + §13; Python E2E refresh against Hono + CLI mint; release
  prep (changelog, version bumps, publish dry-run, dependency audit).
  Spec §16.

## After v0.2

Deferred items live in spec §0 ("Deferred to v0.3+"). They are not
in-scope for any open work. The next planning pass turns selected
deferred items into v0.3 issues.
