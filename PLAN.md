# Plan: chore: vitest config + sample test (#3)

## Spec anchors
- docs/spec/v0.1.md#15-testing
- docs/spec/v0.1.md#16-project-structure-v01
- docs/spec/v0.1.md#18-quality-bar-for-v01
- CLAUDE.md#8-tooling

## Approach
Add the repository-level Vitest wiring that later package and CI work can rely on, while keeping the change limited to test tooling and one harmless proof test. Use a root `vitest.config.ts` with an explicit include for `packages/*/src/**/*.test.ts` so tests stay colocated with package source as required by the repo conventions. Add root scripts for normal, watch, and coverage runs, and install Vitest plus its coverage provider as root dev dependencies. Because `packages/core` now exists on `origin/main`, place the sample test under `packages/core/src/` without adding exports, package entry points, public types, auth logic, or other public API.

## Files to create / change
- `package.json` — add `test`, `test:watch`, and `test:coverage` scripts plus root dev dependencies for `vitest` and `@vitest/coverage-v8`.
- `pnpm-lock.yaml` — update through `pnpm install` for the new dev dependencies.
- `vitest.config.ts` — configure Vitest to discover `packages/*/src/**/*.test.ts` and run in the Node environment.
- `packages/core/src/sample.test.ts` — add a single trivial passing test to verify the configured include pattern.

## Public API surface
None. This issue must not add exports, package entry points, public types, auth logic, or package manifests.

## Test plan
- Unit: Run `pnpm test` and verify the sample test passes through the root Vitest config.
- Integration: N/A; this issue only establishes the test runner pipeline and does not exercise cross-component behavior.
- Security: N/A; no auth, token, secret, request, or comparison logic is introduced.
- Tooling: Run `pnpm test:coverage` and verify it produces a coverage summary. Optionally smoke-check `pnpm test:watch -- --run` if a non-interactive equivalent is needed for local verification, but do not require an interactive watch session for CI.

## Risks / open questions
- Coverage thresholds are explicitly out of scope, so the coverage script should emit a summary only and avoid enforcing minimums.

## Out of scope (reaffirmed from issue)
- Coverage thresholds.
- Test fixtures for the authorization server.
- CI workflow changes.
- Core package skeleton, package manifests, exports maps, public types, or runtime implementation.
