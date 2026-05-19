# mcp-authkit — Agent Conventions

This file is the source of truth for how AI agents (Claude Code, others)
should behave in this repository. `AGENTS.md` is a symlink to this file.

## 1. The Spec is Law

The v0.1 specification lives at [`docs/spec/v0.1.md`](docs/spec/v0.1.md).

- **Do not implement anything outside v0.1 scope** (see §0).
- **Do not stub deferred v0.2+ features.** No placeholder methods, no TODO
  comments referencing deferred work, no "future-proof" hooks. The reviewer
  blocks any such stub.
- Spec changes require their own PR with rationale — do not edit the spec
  as part of an implementation PR.
- Issues link to spec anchors (e.g. `docs/spec/v0.1.md#9-token-validation-pipeline`).
  If an issue's intent diverges from the spec, the spec wins; flag it.

## 2. Security Non-Negotiables (Spec §14)

These are hard rules. A PR violating any of them is blocking.

- **Audience validation:** every accepted token has `aud == resourceIndicator`.
- **No token passthrough:** the framework never forwards MCP tokens upstream.
- **No upstream token acceptance:** reject tokens with wrong `aud`.
- **Constant-time comparison** (`crypto.timingSafeEqual`) for all secret
  equality checks (token hashes, PAT lookups, static-token compare).
- **PATs hashed at rest** (SHA-256). Never plaintext, never reversible.
- **PKCE required** for any documented OAuth code flow.
- **DNS rebinding protection:** Host header validation on by default.
- **Refresh rotation:** each use mints a new refresh token; reuse revokes
  the family.
- **Bypass refuses production** unless `bypass.allowInProduction: true`, and
  logs loudly on startup.
- **PAT cannot manage PATs:** PAT/static-authenticated requests to `/pats`
  must 403. Enforced, not advisory.
- **No `any` in the public API.** `unknown` is acceptable when justified.

## 3. Testing Gate

Nothing merges without:

- Unit tests for all new logic.
- Integration tests for cross-component flows (see spec §15).
- Security tests for every applicable item in §14.
- `pnpm test`, `pnpm lint`, `pnpm typecheck`, `pnpm build` all green in CI.

Branch protection enforces this on `main`. Do not push around it.

## 4. Version Control

- **Conventional commits.** `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`,
  `test:`, `ci:`. Scope when useful: `feat(scopes):`, `fix(pats):`.
- **Small, focused commits.** Each commit should leave the tree in a working
  state.
- **One issue per branch.** Branch name: `<issue-number>-<kebab-slug>`,
  e.g. `12-scope-matcher-wildcards`.
- **Commit attribution is FORBIDDEN.** Do not add `Co-Authored-By: Claude`
  or any other AI/agent attribution footer to commit messages. Commits are
  authored by the human committing them; the assistant is a tool.
- **No `--no-verify`**, no skipping hooks, no `--no-gpg-sign`.
- **No force-push to `main`.** Force-push to feature branches only when
  necessary and never to a branch with an open review.
- **Never commit `PLAN.md`.** It's a worktree-local planning artifact
  produced by the `spec-issue` skill and consumed by `implement-issue`.
  Committing it causes a guaranteed rebase conflict on every PR (every
  branch writes its own PLAN.md to the repo root) and pollutes `main`
  with transient working notes. It's gitignored — keep it that way.
  The PR description is the durable record of intent.

## 5. Pull Requests

- One PR per issue. Title: `<type>: <summary> (#<issue>)`.
- Body: link the issue (`Closes #N`), summarize the change, list test
  coverage, call out any spec section touched.
- All CI checks must be green before requesting review.
- Reviewer (human or `review-pr` skill) classifies findings as **blocking**
  or **non-blocking**. Only blocking findings gate the merge. Max 3 review
  cycles before escalating to the human owner.

## 6. Out-of-Scope Findings

If, while implementing issue #N, you discover a bug or gap in unrelated code:

- Do **not** expand the scope of the current PR.
- File a new issue with the `bug` or `chore` label.
- Reference it in the current PR description ("noticed during this work,
  filed as #X").

Scope creep is the most common way these projects rot.

## 7. Code Style

- TypeScript strict mode, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`.
- ESM only. No CommonJS shims in source.
- Comments only when the *why* is non-obvious. Don't narrate what the code does.
- No emojis in code, commits, or PR bodies.
- Filenames `kebab-case.ts`. Test files `*.test.ts` colocated with source.

## 8. Tooling

- **Package manager:** pnpm (workspaces).
- **Test runner:** vitest.
- **Linter/formatter:** biome (single tool, faster than ESLint+Prettier).
- **Type checker:** `tsc --noEmit`.
- **JWT:** `jose` (locked decision, spec §2).
- **Logger:** `pino` (locked decision, spec §2).

## 9. Skills and Workflow

The repo ships skills under `.claude/skills/` that codify the workflow:

- `plan-issues` — read spec, create issues + roadmap + dependency graph.
- `spec-issue` — create worktree+branch for an issue and produce a `PLAN.md`.
- `implement-issue` — execute the plan, write tests, open PR.
- `review-pr` — review with blocking/non-blocking classification, loop ≤3x.
- `merge-pr` — verify CI green, merge, clean up worktree.
- `research-and-implement` — rollup that chains spec → implement → review → merge.

Invoke skills via the Skill tool. Do not improvise the workflow.

## 10. When in Doubt

Prioritize a clean public API and explicit security defaults over breadth
of features. A small framework that does auth correctly beats a big
framework that does it almost correctly.
