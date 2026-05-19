# Plan: chore: packages/core skeleton (package.json, exports map) (#4)

## Spec anchors
- docs/spec/v0.1.md#63-import-paths-v01
- docs/spec/v0.1.md#16-project-structure-v01

## Approach
Create the smallest compiling `packages/core` package that satisfies the v0.1 package layout without adding any auth behavior or public type definitions. The core package should publish only the root `mcp-authkit` entry for now; the memory store and Express adapter import paths from spec §6.3 are intentionally absent because they belong to later packages. Use the existing root TypeScript base config from issue #1, add package-local build metadata, and keep `src/index.ts` as an empty module placeholder so `pnpm --filter mcp-authkit build` emits `dist/index.js` and `dist/index.d.ts`. Avoid stubbing future logic in the domain subdirectories; use empty directories tracked with `.gitkeep` only where needed.

## Files to create / change
- `packages/core/package.json` — package manifest named `mcp-authkit` at `0.1.0`, ESM-only, `sideEffects: false`, a build script, and agreeing `main`, `types`, and root-only `exports`.
- `packages/core/tsconfig.json` — extends `../../tsconfig.base.json`, compiles `src/` to `dist/`, and emits declarations for the placeholder root entry.
- `packages/core/src/index.ts` — empty module placeholder using `export {}`.
- `packages/core/src/types.ts` — empty module placeholder only if required to satisfy the spec §16 file layout; public types remain out of scope for issue #8.
- `packages/core/src/auth/.gitkeep` — track the auth source directory without logic.
- `packages/core/src/pats/.gitkeep` — track the PAT source directory without logic.
- `packages/core/src/scopes/.gitkeep` — track the scope source directory without logic.
- `packages/core/src/handlers/.gitkeep` — track the handler source directory without logic.
- `packages/core/src/bypass/.gitkeep` — track the bypass source directory without logic.
- `packages/core/src/audit/.gitkeep` — track the audit source directory without logic.
- `package.json` and `pnpm-lock.yaml` — add only the minimal TypeScript build dependency if it is still absent when implementing, so the required filtered build can run locally and in CI.

## Public API surface
New package entry point:

```typescript
// mcp-authkit
export {}
```

Package metadata should expose only:

```json
{
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    }
  }
}
```

Do not export `mcp-authkit/stores/memory` or `mcp-authkit/adapters/express` from core; those import paths are implemented by separate workspace packages in later issues.

## Test plan
- Unit: N/A; this is package skeleton only and introduces no runtime logic.
- Integration: Run `pnpm --filter mcp-authkit build` and verify it emits `packages/core/dist/index.js` plus declarations from the placeholder source.
- Security: N/A; no auth, token, secret, request-handling, or comparison logic is introduced.
- Tooling sanity: Run `pnpm install` if a TypeScript dependency is added, and inspect the package manifest to confirm there is no CommonJS fallback and no adapter/store subpath export.

## Risks / open questions
- The issue says `src/types.ts` must exist but also says public type definitions are out of scope. I plan to create it as an empty module placeholder (`export {}`) only to satisfy the directory layout, leaving all real type definitions to issue #8.
- Current `origin/main` has no TypeScript dependency or root build tooling. To make `pnpm --filter mcp-authkit build` pass, implementation likely needs to add `typescript` as a minimal dev dependency, preferably at the workspace root unless project conventions change before implementation.
- The package name `mcp-authkit` at `packages/core` means the later memory store and Express adapter packages must coordinate their own package names or publish-time export strategy; this issue should not solve that beyond keeping core's export map root-only as requested.

## Out of scope (reaffirmed from issue)
- Any auth, PAT, scope, handler, bypass, or audit logic.
- Public type definitions from spec §6.1.
- Memory store or Express adapter code or exports.
- Tests beyond verifying the skeleton build.
- Any v0.2+ deferred feature, placeholder, hook, or TODO.
