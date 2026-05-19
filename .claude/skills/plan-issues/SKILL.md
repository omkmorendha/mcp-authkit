---
name: plan-issues
description: Read the v0.1 spec, create Stage 0 GitHub issues, write ROADMAP.md, and produce a dependency graph. Run once at project kickoff (or to refresh between stages). Reads docs/spec/v0.1.md; writes ROADMAP.md and creates issues via gh.
---

# plan-issues

You are turning `docs/spec/v0.1.md` into trackable work.

## Inputs
- `docs/spec/v0.1.md` — the v0.1 spec (source of truth).
- Current GitHub repo (via `gh`).

## Outputs
1. GitHub labels: `stage-0`, `stage-1`, `stage-2`, `stage-3`, `stage-4`, plus
   `type:feat`, `type:chore`, `type:docs`, `type:test`, `priority:p0`, `priority:p1`,
   `priority:p2`, `security`, `blocked`.
2. GitHub milestone: `v0.1`.
3. **Stage 0 issues only**, each with: title, body, labels, milestone, and a
   `## Dependencies` section listing issue numbers it blocks/is blocked by.
4. `ROADMAP.md` at repo root listing Stage 1–4 as bullet points (NOT issues yet).
5. `docs/dependency-graph.md` — Mermaid diagram of Stage 0 issue dependencies.

## Stage taxonomy (from spec §19)
- **Stage 0 — Foundation:** repo scaffolding, pnpm workspaces, CI (lint/typecheck/test/build),
  biome config, vitest config, tsconfig, packages/core skeleton, types.ts (spec §6.1),
  test-fixture AS scaffold (signs JWTs, serves JWKS).
- **Stage 1 — Auth primitives:** scope matcher (§7), PAT format+lifecycle (§8),
  JWT validation (§9 step 4), introspection (§9 step 5), memory token store.
- **Stage 2 — Pipeline & handlers:** validation pipeline (§9), framework-agnostic
  handlers (§6.1 Handlers), bypass mode (§11), audit dispatch (§12).
- **Stage 3 — Express + example:** Express adapter, hello-world example.
- **Stage 4 — Hardening:** full security test matrix (§15), Python E2E test
  (§18 acceptance), quickstart doc, release prep.

## Issue body template

```markdown
## Spec reference
- [Section X.Y](docs/spec/v0.1.md#anchor)

## Goal
One-paragraph statement of what this issue delivers.

## Acceptance criteria
- [ ] Concrete, testable bullet
- [ ] ...
- [ ] Tests added (unit + integration as applicable)
- [ ] CI green

## Out of scope
Explicit list of things NOT to do in this issue.

## Dependencies
- Blocks: #
- Blocked by: #
```

## Steps

1. Read `docs/spec/v0.1.md` end to end. Confirm scope (§0) and build order (§19).
2. Create labels and milestone via `gh label create` / `gh api repos/:owner/:repo/milestones`.
   Skip if they already exist (don't error).
3. Draft Stage 0 issues (expect ~8–12). For each, identify dependencies on other
   Stage 0 issues before creating. Suggested Stage 0 issue list:
   - `chore: pnpm workspace + tsconfig base`
   - `chore: biome lint+format config`
   - `chore: vitest config + sample test`
   - `ci: GitHub Actions for lint/typecheck/test/build`
   - `chore: packages/core skeleton (package.json, exports map)`
   - `chore: packages/store-memory skeleton`
   - `chore: packages/adapter-express skeleton`
   - `chore: examples/hello-world skeleton`
   - `feat(core): public type definitions from spec §6.1`
   - `feat(test): test-fixture AS (signs JWTs, serves JWKS)`
   - `docs: README with quickstart pointer`
4. Create issues via `gh issue create` with `--label`, `--milestone`, `--body-file`.
   Capture the returned numbers so dependency cross-references can be filled in
   with a second pass of `gh issue edit`.
5. Write `ROADMAP.md` (Stage 1–4 as prose + bullets, no issues created yet).
6. Write `docs/dependency-graph.md` with a Mermaid `graph TD` of Stage 0
   issue numbers and arrows.
7. Commit: `chore: plan Stage 0 issues and roadmap` (no attribution footer).
8. Report to the user: list of created issues with numbers, link to roadmap,
   recommended starting issue (the one with no blockers).

## Hard rules

- **Stage 0 only this run.** Do not pre-create Stage 1+ issues. The roadmap
  is enough; refresh issues when Stage 0 is ~80% done.
- **No commit attribution footer.** See CLAUDE.md §4.
- If the user reruns this skill, detect existing issues by title and skip
  rather than duplicate.
- Reflect any ambiguity in the spec back to the user before creating issues.
