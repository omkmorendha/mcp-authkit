# Plan: docs: README with quickstart pointer (#11)

## Spec anchors
- `docs/spec/v0.1.md#0-v01-scope`
- `docs/spec/v0.1.md#1-mission`

## Approach
Update the existing top-level `README.md` so it becomes a terse front door for v0.1 without expanding project scope. Keep the elevator pitch aligned with spec §1, make the development status explicit, and mirror the in-scope/deferred lists from spec §0 at a summary level. The README should point readers to `docs/spec/v0.1.md` as the source of truth and link to `docs/quickstart.md` as the eventual quickstart location, even if that document does not exist yet in Stage 0. This is documentation-only work, so the implementation should avoid source, config, or generated-file changes.

## Files to create / change
- `README.md` — revise the top-level project introduction, add status and CI badge placeholders, summarize v0.1 scope and deferred work, and add links to the spec and eventual quickstart.

## Public API surface
No public API changes. No new exports.

## Test plan
- Unit: N/A — documentation-only change.
- Integration: N/A — documentation-only change.
- Security: N/A — documentation-only change.
- Manual: inspect rendered Markdown for valid relative links, no emojis, and exact alignment with issue acceptance criteria.
- CI: run the standard checks if the repository has them available at implementation time; otherwise note that the change is documentation-only and no package tooling exists yet.

## Risks / open questions
- Confirm whether the CI badge placeholder should be plain text, a commented placeholder, or a Markdown badge link once the CI workflow path/name is known from issue #10.
- Confirm whether linking to the not-yet-created `docs/quickstart.md` is acceptable as a broken relative link until Stage 4, as the issue says the placeholder is fine.

## Out of scope (reaffirmed from issue)
- Creating `docs/quickstart.md`.
- Adding a contributing guide.
- Adding API reference documentation.
- Implementing or stubbing any v0.2+ deferred feature.
