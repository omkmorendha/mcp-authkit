# mcp-authkit — Agent Conventions

This file is the source of truth for how AI agents (Claude Code, others)
should behave in this repository. `AGENTS.md` is a symlink to this file.

## 1. The Spec is Law

The active specification is [`docs/spec/v0.2.md`](docs/spec/v0.2.md).
The v0.1 baseline lives at [`docs/spec/v0.1.md`](docs/spec/v0.1.md) and
remains authoritative for everything it covered.

- **Do not implement anything outside the active spec's scope** (see §0
  of each spec).
- **Do not stub deferred v0.3+ features.** No placeholder methods, no TODO
  comments referencing deferred work, no "future-proof" hooks. The reviewer
  blocks any such stub.
- Spec changes require their own PR with rationale — do not edit the spec
  as part of an implementation PR.
- Issues link to spec anchors (e.g. `docs/spec/v0.2.md#7-pipeline-and-handler-flow`).
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

## 10. Releases

The npm release pipeline is fully automated via OIDC. Do not run
`pnpm publish` manually from a workstation — there is no `NPM_TOKEN`
secret and the published packages would lack the provenance
attestation that ties them to a specific commit.

### How a release happens

1. On `main` with a clean tree, bump every public workspace package to
   the new version. All nine bump together — this monorepo does **not**
   support independent versioning. Sanity check:

   ```bash
   grep -c '"version": "<new>"' packages/*/package.json   # must equal 9
   ```

2. Add a `## [<new>] — YYYY-MM-DD` entry to `CHANGELOG.md` above the
   previous one. Cover `### Added` / `### Changed` / `### Fixed` /
   `### Security` as applicable. Spec links are required when a section
   was touched (§1).

3. Run the local CI gate (§3): `pnpm install && pnpm build && pnpm
   typecheck && pnpm test`. All four must be green; do not push a
   release otherwise.

4. Commit as `chore(release): v<new>`. Push to `main`.

5. Tag and push:

   ```bash
   git tag -a v<new> -m "v<new>"
   git push origin v<new>
   ```

   The `v*` tag fires `.github/workflows/release.yml`, which runs the
   gate again in CI, then `pnpm -r publish --access public --provenance
   --no-git-checks` for every public package.

6. Verify after the workflow goes green:

   ```bash
   for p in mcp-authkit mcp-authkit-adapter-express mcp-authkit-adapter-hono \
            mcp-authkit-store-memory mcp-authkit-store-postgres \
            mcp-authkit-store-sqlite mcp-authkit-store-redis \
            mcp-authkit-config mcp-authkit-cli; do
     printf '%-32s %s\n' "$p" "$(npm view $p version)"
   done
   ```

   Each should show `<new>`. Spot-check provenance on one:

   ```bash
   npm view mcp-authkit@<new> --json | python3 -c "import json,sys; print(json.load(sys.stdin)['dist']['attestations'])"
   ```

   That should print a `slsa.dev/provenance/v1` URL.

7. Create the GitHub Release pointing at the tag:

   ```bash
   awk '/^## \[<new>\]/{flag=1; next} /^## \[/{flag=0} flag' CHANGELOG.md > /tmp/notes.md
   gh release create v<new> --title "v<new> — <one-line>" --notes-file /tmp/notes.md --verify-tag
   ```

### When a release fails mid-flight

The tag has fired but `pnpm publish` errored before any tarball was
PUT. Symptoms include npm returning **HTTP 404** on the first publish
attempt — npm returns 404 (not 401/403) when OIDC silently fails,
which is misleading. **Before retrying:** check that no package
actually published with the new version (`npm view <name> versions`).

If nothing published, the tag may be force-moved safely:

```bash
# Fix the workflow, push to main, then:
git tag -d v<new>
git push origin :refs/tags/v<new>
git tag -a v<new> -m "v<new>"
git push origin v<new>           # re-fires the workflow
```

If **any** package did publish, do not move the tag. Cut a new patch
version instead.

### Trusted Publishers, npm CLI, and Node

Each package on npmjs.com is bound to this repo + the `release.yml`
workflow under "Trusted Publishers." Three constraints follow:

- **The workflow filename must stay `release.yml`.** Renaming breaks
  every Trusted Publisher binding and the publish step will return 404.
- **Node version must include npm ≥ 11.5.1.** Trusted Publishers / OIDC
  is gated on this; pnpm shells out to npm for the OIDC handshake. Node
  22 LTS ships npm 10.x and will silently fail. Pin the runner to
  Node 24+ in `release.yml`. Do not "upgrade in place" with `npm
  install -g npm@latest` — it crashes with `MODULE_NOT_FOUND` mid-
  rebuild.
- **A new package needs its own Trusted Publisher binding** (one-time
  manual UI step on npmjs.com → package → Settings → Trusted
  Publishers). Until that's done, the first publish of that name will
  fail with 404.

### What the release pipeline does NOT do

- Independent versioning (changesets / lerna). All packages bump
  together. If you need independent versioning, that's a real
  redesign — file an issue first, don't improvise.
- Automatic CHANGELOG generation. The CHANGELOG is hand-written; this
  is intentional because the v0.2 spec demands spec-section anchors per
  entry that no commit-parser can produce.
- Pre-release tags (alpha, beta, rc). If we add them, the workflow
  needs a tag-filter (`v[0-9]+.[0-9]+.[0-9]+-*`) and the `--tag`
  argument on `pnpm publish` to keep the `latest` dist-tag stable.

## 11. When in Doubt

Prioritize a clean public API and explicit security defaults over breadth
of features. A small framework that does auth correctly beats a big
framework that does it almost correctly.
