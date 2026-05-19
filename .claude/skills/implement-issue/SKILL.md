---
name: implement-issue
description: Execute the PLAN.md in the current worktree, write tests, ensure all checks pass locally, and open a PR. Must run inside a worktree created by spec-issue. Args:- none (reads PLAN.md from worktree root).
---

# implement-issue

You are executing an approved plan.

## Preconditions
- Current working directory is a worktree created by `spec-issue`.
- `PLAN.md` exists at the worktree root and has been reviewed by the human.
- The branch is the worktree's branch (verify with `git branch --show-current`).

## Steps

1. **Read `PLAN.md`.** Re-read the linked spec sections. If any open question
   in PLAN.md is unanswered, stop and ask.

2. **Implement in small commits.** Each commit:
   - Conventional commit message (CLAUDE.md §4).
   - Leaves the tree in a building state.
   - No attribution footer.
   - Group: types → core logic → tests → docs.

3. **Tests are not optional.**
   - Unit tests live next to source as `*.test.ts`.
   - Integration tests under `packages/<pkg>/test/integration/`.
   - Security tests under `packages/<pkg>/test/security/` for anything touching
     spec §14.
   - For every acceptance criterion in the issue, there must be a test that
     would fail without the change.

4. **Local quality gate.** Before pushing, all four must pass in the worktree:
   ```
   pnpm install
   pnpm lint
   pnpm typecheck
   pnpm test
   pnpm build
   ```
   Fix everything. Do not push red.

5. **Push and open PR.**
   ```
   git push -u origin <branch>
   gh pr create \
     --title "<type>(<scope>): <summary> (#<N>)" \
     --body-file <(...)
   ```
   PR body must include:
   - `Closes #<N>`
   - Summary (2–4 sentences)
   - Spec sections touched
   - Test coverage list
   - Any out-of-scope findings filed as new issues (CLAUDE.md §6)

6. **Wait for CI.** Watch with `gh pr checks <pr> --watch`. If CI fails, fix
   in the same branch with new commits (do not amend pushed commits).

7. **Stop and report.** PR URL, CI status, summary of what was implemented.
   The next step is `review-pr`.

## Hard rules

- **Do not stub deferred v0.2 features** (CLAUDE.md §1).
- **No `--no-verify`, no `--no-gpg-sign`, no `git commit --amend` on pushed commits.**
- **No commit attribution.**
- **No scope creep.** Out-of-scope findings → new issue, never bundled.
- If a security non-negotiable (§14) is at risk, stop and flag rather than
  ship a "good enough" version.
- Public API matches spec §6.1 *exactly* where the spec specifies it.
