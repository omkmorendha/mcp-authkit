---
name: research-and-implement
description: End-to-end implementation of a single GitHub issue. Chains spec-issue → human-approval → implement-issue → review-pr (loop) → merge-pr, clearing context between stages. Args:- the issue number (required).
---

# research-and-implement

You are running the full pipeline for one issue. This is the primary command
for moving work from issue → merged.

## Inputs
- `$ARGUMENTS` — GitHub issue number.

## Pipeline

Each stage clears context before the next. Use `/clear` (or instruct the
user to start a fresh session) between stages — the goal is that each stage
re-grounds itself in the spec and the worktree state rather than carrying
stale assumptions.

### Stage A — Spec
1. Invoke `spec-issue <N>`.
2. **Stop.** Show the user the worktree path and `PLAN.md` contents.
3. Wait for the user to review the plan and answer any open questions.
4. **Clear context.**

### Stage B — Implement
1. `cd` into the worktree from Stage A.
2. Invoke `implement-issue` (no args; reads `PLAN.md`).
3. PR is opened, CI runs.
4. **Stop.** Show the PR URL and CI status.
5. **Clear context.**

### Stage C — Review loop
1. Invoke `review-pr <PR>`.
2. If approved → go to Stage D.
3. If changes requested → user (or `implement-issue` re-invoked) addresses
   blocking findings, pushes new commits, then re-invoke `review-pr <PR>`.
4. Max 3 review cycles. If cycle 3 still has blockers, the review skill
   escalates and this skill stops.
5. **Clear context between cycles.**

### Stage D — Merge
1. Invoke `merge-pr <PR>`.
2. Confirm merge with the user.
3. Skill cleans up worktree, closes issue.
4. Report final SHA, closed issue, and the next recommended issue to pick
   up (from the dependency graph).

## When to deviate

- **Reviewer escalation:** stop the pipeline. The human owner decides
  whether to override, rework, or close.
- **Spec ambiguity discovered mid-implementation:** stop and raise. Do not
  guess; the spec is law (CLAUDE.md §1).
- **Out-of-scope work discovered:** file a new issue, do not bundle. Note
  it in the PR body and continue.

## Hard rules

- Do not skip stages.
- Do not skip the context clears — they are the cheapest safety mechanism
  against drift.
- Do not merge without explicit user confirmation, even when all gates
  are green.
- No commit attribution at any stage.
