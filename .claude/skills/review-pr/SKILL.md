---
name: review-pr
description: Review an open PR against the spec and CLAUDE.md rules, classify findings as blocking or non-blocking, post review comments, and loop until clean (max 3 cycles). Args:- the PR number (required).
---

# review-pr

You are the gatekeeper between PR and `main`.

## Inputs
- `$ARGUMENTS` — PR number.

## Steps

1. **Fetch the PR.** `gh pr view <N> --json number,title,body,headRefName,baseRefName,mergeable,statusCheckRollup,reviews`.
   Also: `gh pr diff <N>`.

2. **Read context.**
   - The linked issue (`Closes #M`) and its acceptance criteria.
   - The spec sections referenced in the PR body.
   - `PLAN.md` from the worktree if accessible.

3. **CI gate.** If CI is not green, the only finding is "CI failing — fix
   before review." Post that as a comment, do not proceed to deeper review.

4. **Review checklist.** For each item, look at the actual diff (not the PR
   description's claims):
   - **Spec adherence (CLAUDE.md §1):** types match §6.1, behavior matches
     the relevant section, no v0.2 stubs.
   - **Security non-negotiables (CLAUDE.md §2 / spec §14):** every applicable
     rule. Be paranoid about audience validation, timing-safe comparison,
     plaintext token storage.
   - **Tests:** unit + integration + security as applicable. Each acceptance
     criterion has a corresponding test. Tests would actually fail without
     the change (look for tautologies).
   - **Public API:** zero `any`. No accidental new exports. Import paths
     match spec §6.3.
   - **Scope creep:** changes touching files unrelated to the issue.
   - **Code style (CLAUDE.md §7):** comments only when *why* is non-obvious,
     no narration, kebab-case filenames.
   - **Commit hygiene:** conventional messages, no attribution footers, no
     `--no-verify`.

5. **Classify findings.**
   - **Blocking:** spec violation, security non-negotiable miss, missing
     tests for an acceptance criterion, CI red, `any` in public API,
     v0.2 stub.
   - **Non-blocking:** style nits, naming preferences, minor refactor ideas,
     test additions beyond the acceptance criteria.

6. **Post the review.**
   ```
   gh pr review <N> --request-changes --body-file <(...)
   ```
   Body structure:
   ```markdown
   ## Blocking
   1. [path:line] — finding + suggested fix
   ...

   ## Non-blocking
   1. [path:line] — finding
   ...

   ## Verdict
   - Blocking count: N
   - Cycle: <1/2/3>
   ```
   If zero blocking findings, approve instead:
   ```
   gh pr review <N> --approve --body "LGTM. <N> non-blocking suggestions for follow-up."
   ```

7. **Loop control.**
   - Track cycle count in PR review bodies (`Cycle: 1/2/3`).
   - After posting a request-changes review, **stop**. The author (likely
     `implement-issue` or the human) addresses blocking findings and pushes.
   - When re-invoked on the same PR with new commits, increment the cycle.
   - **At cycle 3 with remaining blockers, do not request changes again.**
     Instead, post a `## Escalation` comment summarizing the deadlock and
     ping the human owner.

8. **Stop and report.** Verdict (approved / changes requested / escalated)
   and cycle count.

## Hard rules

- Read the diff, not the description. Authors describe intent; reviewers
  verify reality (trust-but-verify, see also Claude Code system prompt).
- **No approval if any acceptance criterion lacks a test.**
- **No approval on red CI**, no exceptions.
- Be terse in comments. `file:line — issue + fix` beats prose.
- Non-blocking findings are suggestions, not requirements. Do not gate on them.
