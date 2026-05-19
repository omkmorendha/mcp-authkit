# mcp-authkit Roadmap

This roadmap tracks the path to v0.1. The source of truth for scope is
[`docs/spec/v0.1.md`](docs/spec/v0.1.md); anything not in that document is
out of scope for v0.1.

Stages map to the build order in spec §19. Only **Stage 0** issues are
created up front. Stages 1–4 are listed here as prose; concrete issues for
each are created when the prior stage is roughly 80% complete, so plans
stay grounded in what we've actually learned.

## Stage 0 — Foundation (issues live now)

Scaffolding the workspace, tooling, package skeletons, public type
definitions, the AS test fixture, CI, and a README. See the GitHub
[`stage-0`](https://github.com/omkmorendha/mcp-authkit/labels/stage-0)
label for the live list. Dependency graph: [`docs/dependency-graph.md`](docs/dependency-graph.md).

## Stage 1 — Auth primitives

The primitives every later stage composes from. Implementation order
follows spec §19 steps 3–6.

- Scope matcher: exact match → wildcards (`*`, `**`) → implications →
  set utilities (`scope.intersect`, `scope.subtract`, `scope.normalize`,
  `scope.expand`). Spec §7.
- PAT format: `<prefix><random>_<checksum>`, mint + parse + verify.
  Spec §8.1.
- PAT lifecycle: create, find-by-hash, list, revoke, rotate,
  `lastUsedAt`. Spec §8.2–§8.5.
- JWT validation: signature against cached JWKS, `iss`, `aud ==
  resourceIndicator`, `exp`, `nbf`. Spec §9 step 4.
- Introspection (RFC 7662) for opaque AS tokens when
  `introspectionEndpoint` is configured. Spec §9 step 5.
- Memory token store: full `TokenStore` implementation including
  refresh-token rotation and family revocation. Spec §6.1 + §14.

## Stage 2 — Pipeline and handlers

Compose the primitives into the per-request pipeline and the
framework-agnostic surface.

- Token validation pipeline: bypass → static → PAT → JWT →
  introspection → 401. Spec §9.
- Framework-agnostic handlers: `mcp`, `metadata` (RFC 9728), `pats`,
  `challenge`. Spec §6.1 Handlers.
- `createAuthKit` factory + `registerTool` (scope gate runs before tool
  handler). Spec §6.1.
- Bypass mode + stdio auto-enable + production refusal. Spec §11.
- Audit dispatch wired through every event site
  (`pat.mint|use|revoke|rotate`, `oauth.validate|reject`,
  `scope.allow|deny`). Spec §12.
- Host header validation (DNS rebinding mitigation). Spec §14.
- PAT REST endpoints enforce "PAT cannot manage PATs" (403). Spec §8.6.

## Stage 3 — Express adapter + hello-world

Make the public API usable end-to-end on a real web framework.

- Express adapter: thin sugar over the raw handlers, mounted at
  `/mcp`, `/.well-known/oauth-protected-resource`, `/pats`. Spec §6.2.
- hello-world example: under 50 lines of consumer code, runs locally
  with the memory store and the test-fixture AS. Spec §6.2 + §18.
- Manual end-to-end run notes (recorded in PR; full quickstart lands in
  Stage 4).

## Stage 4 — Hardening and release

Close the gap to release-ready.

- Security test matrix per spec §15: wrong audience, missing audience,
  expired/revoked tokens, PAT scope escalation attempts, cross-user PAT
  access, refresh reuse → family revoke, PKCE mismatch, disallowed Host
  header, PAT-managing-PAT (403), bypass-in-prod refusal, static-token
  insufficient scopes.
- Python E2E acceptance test (`requests` only): mint a PAT via REST
  after OAuth auth, call the echo tool, assert output. Targets <5
  minutes first run, <10s repeat. Spec §18.
- Quickstart doc at `docs/quickstart.md` — reads cleanly to someone
  new to MCP. Spec §18.
- Dependency audit: no high/critical CVEs. Spec §18.
- Public API audit: zero exposed `any`. Spec §18 + CLAUDE.md §2.
- Release prep: changelog, version bump, branch protection verified,
  publish dry-run.

## After v0.1

Deferred items live in spec §0 ("Deferred to v0.2+"). Do not start them
or stub them in v0.1 work. When v0.1 ships, the next planning pass
turns selected deferred items into Stage 5+ work.
