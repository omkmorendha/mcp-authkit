# Plan: chore: pnpm workspace + tsconfig base (#1)

## Spec anchors
- docs/spec/v0.1.md#2-hard-constraints-locked-decisions
- docs/spec/v0.1.md#16-project-structure-v01

## Approach
Bootstrap only the repository-level workspace and TypeScript configuration needed by later Stage 0 issues. Keep the root package private and ESM-oriented, with Node 20 declared in both package metadata and a version pin file so contributors and CI resolve the same runtime family. Add a shared `tsconfig.base.json` that encodes the strict TypeScript defaults from CLAUDE.md and the issue, then keep the root `tsconfig.json` minimal so package skeleton issues can add project references when those packages exist. Do not create package directories, package manifests, tooling configs, CI, tests, or source code in this issue.

## Files to create / change
- `pnpm-workspace.yaml` — declare `packages/*` and `examples/*` workspace globs.
- `package.json` — private monorepo manifest named `mcp-authkit-monorepo`, ESM-only, Node >=20 engine, and minimal workspace scripts only if they can run without package/tooling setup.
- `tsconfig.base.json` — shared strict NodeNext/ES2022 TypeScript compiler options with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.
- `tsconfig.json` — root config extending the base, with no source includes and no package references until package skeletons exist.
- `.gitignore` — ignore `node_modules`, `dist`, logs, `.DS_Store`, and `coverage`.
- `.nvmrc` — pin the Node 20 family for local development.

## Public API surface
None. This issue creates repository scaffolding only and must not add exports, package entry points, source files, or public types.

## Test plan
- Unit: N/A for pure workspace scaffolding; no runtime logic is introduced.
- Integration: Run `pnpm install` from the repo root and verify it completes cleanly with the empty workspace.
- Security: N/A; no auth, token, secret, or request-handling code is introduced.
- Tooling sanity: If `tsc` is not added as a dependency in this issue, do not run `pnpm typecheck`; that belongs to the package/tooling issues. If a root script is added, verify it does not fail solely because later package skeletons are absent.

## Risks / open questions
- Should `.nvmrc` use an exact current Node 20 patch version or the broader `20` selector? I plan to use `20` to satisfy "pins Node 20.x" without forcing patch churn.
- Should root scripts be omitted until biome, vitest, and packages exist? I plan to keep scripts minimal or absent so this issue does not stub later tooling work.

## Out of scope (reaffirmed from issue)
- Per-package `package.json` files.
- Package directories and source code.
- biome, vitest, or GitHub Actions configuration.
- Any implementation of public API types or auth behavior.
