---
name: spec-issue
description: Given a GitHub issue number, create a worktree+branch, research the codebase, and produce a PLAN.md for the implementation. Combines "research" and "spec" into one step. Use before implement-issue. Args:- the issue number (required).
---

# spec-issue

You are turning a GitHub issue into a concrete implementation plan.

## Inputs
- `$ARGUMENTS` — the issue number, e.g. `12`.

## Steps

1. **Validate the issue.** `gh issue view <N> --json number,title,body,labels,milestone,state`.
   - If state is not `OPEN`, stop and report.
   - If labeled `blocked` or has unmet `Blocked by:` deps that are still open, stop and report.

2. **Branch name.** `<N>-<kebab-slug>` derived from the issue title.
   Example: issue #12 "feat(scopes): wildcard matcher" → `12-scopes-wildcard-matcher`.

3. **Create worktree.** Use a worktree under `../mcp-authkit-worktrees/<branch>`:
   ```
   git fetch origin
   git worktree add -b <branch> ../mcp-authkit-worktrees/<branch> origin/main
   ```
   All subsequent work happens in that directory.

4. **Research.** Read:
   - The full issue body (spec links, acceptance criteria, out-of-scope).
   - The linked spec sections in `docs/spec/v0.1.md`.
   - The relevant RFCs noted in spec §4 (use WebFetch sparingly; cite section
     numbers in PLAN.md).
   - Existing code touching the same area (`grep`, `find`).
   - Any blocking-issue PRs that already merged — read their diffs.

5. **Write `PLAN.md` in the worktree root.** Sections:
   ```markdown
   # Plan: <issue title> (#<N>)

   ## Spec anchors
   - docs/spec/v0.1.md#...

   ## Approach
   2–6 sentences. The design decision, not the steps.

   ## Files to create / change
   - `path/to/file.ts` — purpose

   ## Public API surface
   Any new exports. Type signatures. Must match spec §6.1 exactly where applicable.

   ## Test plan
   - Unit: ...
   - Integration: ...
   - Security: ...

   ## Risks / open questions
   Things to confirm with the human before implementing.

   ## Out of scope (reaffirmed from issue)
   - ...
   ```

6. **Commit the plan.** `git add PLAN.md && git commit -m "docs: plan for #<N>"`.
   No attribution footer.

7. **Stop and report.** Print the worktree path, branch name, and a short
   summary of the plan. Wait for the user to approve or invoke `implement-issue`.

## Hard rules

- Never edit code in this skill — PLAN.md only.
- If the issue cannot be implemented without changing the spec, stop and
  flag it. The spec is law (CLAUDE.md §1).
- If you discover the issue is wrong (e.g., overlaps an already-merged
  issue), stop and ask before proceeding.
- Risks/open questions must be answered before `implement-issue` runs.
