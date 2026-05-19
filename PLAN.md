# Plan: chore: biome lint+format config (#2)

## Spec anchors
- docs/spec/v0.1.md#0-v01-scope
- docs/spec/v0.1.md#2-hard-constraints-locked-decisions
- docs/spec/v0.1.md#14-security-non-negotiables
- docs/spec/v0.1.md#15-testing
- docs/spec/v0.1.md#18-quality-bar-for-v01
- CLAUDE.md#8-tooling

## Approach
Add Biome as the repository's single lint and format tool at the root, matching the locked tooling decision and avoiding ESLint, Prettier, package-specific overrides, or source-level changes. Use one `biome.json` that enables formatting, linting, and assist actions for TypeScript/JavaScript and JSON files, with explicit formatting options for 2-space indentation, double quotes, semicolons as needed, and a 100-column line width. Promote the issue-required rules to errors, including `suspicious.noExplicitAny`, `correctness.noUnusedVariables`, import organization through Biome assist, and an ESM-oriented rule set that rejects CommonJS where supported by the installed Biome version. Wire root `package.json` scripts so `pnpm lint` performs a non-mutating Biome check, `pnpm lint:fix` applies safe check fixes and import organization, `pnpm format` writes formatting changes, and `pnpm format:check` verifies formatting only. Pin `@biomejs/biome` as a root dev dependency and update the pnpm lockfile without introducing runtime code.

## Files to create / change
- `biome.json` — root Biome configuration for TypeScript/JavaScript and JSON linting, formatting, import organization, and excludes.
- `package.json` — add `@biomejs/biome` as a dev dependency and root scripts: `lint`, `lint:fix`, `format`, and `format:check`.
- `pnpm-lock.yaml` — update the lockfile for the Biome dev dependency.

## Public API surface
None. This issue is tooling-only and must not add exports, package entry points, source files, public types, or any config-file API for consumers.

## Test plan
- Unit: N/A; no runtime logic is introduced.
- Integration: Run `pnpm install --lockfile-only` or equivalent dependency installation for the dev dependency, then run `pnpm lint`, `pnpm format:check`, and `pnpm lint:fix` against the current scaffold to verify the configured commands succeed.
- Security: Verify `suspicious.noExplicitAny` is configured as an error so future source cannot use explicit `any`, supporting spec §14 and §18's public API quality requirements. No token, PAT, host, OAuth, or request-handling behavior is touched.

## Risks / open questions
- Biome's `noExplicitAny` and `noUnusedVariables` rules are documented and available in current Biome; before implementation, confirm the exact installed Biome version accepts the selected ESM/CommonJS rule name so the config does not fail schema validation.
- `pnpm lint:fix` will likely need `biome check --write .` rather than `biome lint --write .` because import organization is an assist action included by `check`, not plain `lint`.
- The current scaffold includes Markdown files, which Biome does not format as project prose; the implementation should scope Biome includes/excludes so `pnpm lint` exits 0 on the empty/scaffold tree without pretending to validate docs.

## Out of scope (reaffirmed from issue)
- ESLint or Prettier.
- Per-package Biome overrides.
- Source files, tests, package skeletons, CI workflow changes, or auth behavior.
- Any v0.2+ config file format such as `mcp-authkit.config.ts`.
