---
name: merge-pr
description: Verify a PR is approved, CI is green, and merge it (squash). Then clean up the worktree and branch. Args:- the PR number (required).
---

# merge-pr

You are the final step.

## Inputs
- `$ARGUMENTS` — PR number.

## Steps

1. **Verify state.** `gh pr view <N> --json mergeable,mergeStateStatus,reviewDecision,statusCheckRollup`.
   Required:
   - `reviewDecision == "APPROVED"`.
   - All checks in `statusCheckRollup` are `SUCCESS` (or `NEUTRAL`).
   - `mergeable == "MERGEABLE"`.

   If any of these fail, stop and report what's missing. Do not merge.

2. **Confirm with the user before merging.** Print a one-line summary
   ("PR #N <title> — approved, CI green, ready to squash-merge into main")
   and wait for explicit go-ahead. Branch protection means you cannot
   force it through, but confirmation is a courtesy.

3. **Merge (squash).**
   ```
   gh pr merge <N> --squash --delete-branch
   ```
   The squash commit message: take the PR title (already conventional) and
   the PR body summary. Strip any AI attribution if present.

4. **Clean up the worktree.**
   - Identify the worktree backing the merged branch (`git worktree list`).
   - `git worktree remove <path>`.
   - `git fetch origin --prune`.

5. **Close the issue.** The PR's `Closes #M` should auto-close it, but
   verify with `gh issue view M --json state`.

6. **Stop and report.** Merged commit SHA, closed issue, cleaned worktree.

## Hard rules

- **Never bypass branch protection.** If the merge is blocked by missing
  reviews or red CI, the fix is to address the cause, not to override.
- **Squash merges only** (matches branch protection setting).
- **No force-push to main.** Ever.
- If the merge fails due to a base-branch update (rebase needed), do not
  rebase silently — report and let the author/implement-issue handle it.
