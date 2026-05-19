# Plan: ci: GitHub Actions for lint/typecheck/test/build (#10)

## Spec anchors
- CLAUDE.md §3 Testing Gate
- CLAUDE.md §4 Version Control

## Approach
Create a single `.github/workflows/ci.yml` that triggers on `push` to `main` and `pull_request` targeting `main`. It uses `pnpm/action-setup` with the version pinned from the `packageManager` field, `actions/setup-node@v4` with the Node version from `.nvmrc` (currently 20), and pnpm store caching. Steps run sequentially: install, lint, typecheck, test, build. A Node 22 matrix leg is added and marked `continue-on-error: true` so it is informational, not blocking. The CI badge in `README.md` is updated to reference the real workflow status URL. No coverage or release automation is included.

## Files to create / change
- `.github/workflows/ci.yml` — the CI workflow (new file)
- `README.md` — update the placeholder CI badge to the real GitHub Actions badge

## Public API surface
None — CI config only.

## Test plan
- Unit: N/A — workflow files have no unit tests.
- Integration: the workflow itself is the test; it must be green on the PR introducing it.
- Security: N/A — no auth logic changed.

## Risks / open questions
- Issue #3 (vitest) is still open, so `pnpm test` may be a no-op on `main` today. The workflow should still pass because `pnpm -r --if-present test` exits 0 when no package defines a `test` script. This is acceptable — the step will become meaningful once #3 lands.
- Node 22 matrix leg is marked `continue-on-error: true` per the acceptance criteria ("Node 22 optional, marked non-blocking if added").

## Out of scope (reaffirmed from issue)
- Release automation / npm publish (Stage 4).
- Coverage gating / codecov (Stage 4).
- Codeowners file (manual setup by human owner).
- Any changes to source TypeScript files.
