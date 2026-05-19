# Plan: feat(core): public type definitions from spec §6.1 (#8)

## Spec anchors
- docs/spec/v0.1.md#61-core-types-this-is-the-contract
- docs/spec/v0.1.md#62-usage-hello-world-target-under-50-lines
- docs/spec/v0.1.md#63-import-paths-v01
- docs/spec/v0.1.md#0-v01-scope
- docs/spec/v0.1.md#2-hard-constraints-locked-decisions
- docs/spec/v0.1.md#14-security-non-negotiables

## Approach
Replace the empty core placeholders from #4 with the exact public type contract from spec §6.1, preserving order, names, imports, comments, and signatures as the stable v0.1 API surface. Keep runtime behavior intentionally minimal: `createAuthKit` should export the spec signature and throw `new Error("not implemented")` until the later implementation issue supplies real handlers. Add only the dependencies needed for those public type imports to compile, using type-only imports where the spec shows them and keeping the core free of Express or store subpath exports. For type drift coverage, add a TypeScript-only smoke test that compiles representative `AuthContext`, `AuthKitConfig`, and `Handlers` shapes without introducing broad test-runner work that belongs to #3.

## Files to create / change
- `packages/core/src/types.ts` - translate every interface, type alias, and function signature from spec §6.1 into source in the same order, with no `any` and with `unknown` only where the spec uses it.
- `packages/core/src/index.ts` - re-export `createAuthKit` as a value and all public types from `types.ts`.
- `packages/core/src/types.test.ts` - type-level smoke test using `satisfies`, compile-time helper types, and representative values for `AuthContext`, `AuthKitConfig`, and `Handlers`.
- `packages/core/tsconfig.type-test.json` - no-emit package-local TypeScript config for the type smoke test, if keeping it out of build output requires a separate config.
- `packages/core/tsconfig.json` - exclude the type smoke test from declaration/build output if the separate type-test config is used.
- `packages/core/package.json` - add package scripts for the type smoke test and dependencies needed by the public API imports: `@modelcontextprotocol/sdk`, `pino`, and `zod`; add Node typings if `Buffer`, `IncomingMessage`, or `ServerResponse` require them.
- `package.json` and `pnpm-lock.yaml` - add workspace dependency updates only as required by the package manifest changes.

## Public API surface
Root export `mcp-authkit` should expose every type from `packages/core/src/types.ts` plus the `createAuthKit` value. The intended source surface is:

```typescript
export {
  createAuthKit,
  type AuditEvent,
  type AuthContext,
  type AuthKit,
  type AuthKitConfig,
  type CreatePatInput,
  type CreateRefreshTokenInput,
  type Handlers,
  type RegisterToolOptions,
  type ScopeMatcher,
  type ScopeVocabulary,
  type ScopeVocabularyEntry,
  type StoredPat,
  type StoredPatPublic,
  type StoredRefreshToken,
  type TokenStore,
} from "./types.js"
```

`createAuthKit` must have the exact exported signature from spec §6.1:

```typescript
export function createAuthKit(config: AuthKitConfig): AuthKit
```

Because implementation is out of scope for this issue, the source definition should include only a stub body that throws `"not implemented"` while preserving that public signature. Do not add `mcp-authkit/stores/memory`, `mcp-authkit/adapters/express`, scope utilities, handlers, validation logic, PAT logic, or OAuth behavior in this issue.

## Test plan
- Unit: Type-level smoke test compiles representative assignments for `AuthContext`, `AuthKitConfig`, and `Handlers`; no runtime unit tests are needed beyond proving the stub can be imported because runtime behavior is out of scope.
- Integration: Run `pnpm --filter mcp-authkit typecheck`, `pnpm --filter mcp-authkit build`, and the package-local type smoke script so the emitted declarations and public imports compile.
- Security: Confirm `packages/core/src/types.ts` contains zero `any`, all raw payload surfaces use `Record<string, unknown>`, and no token comparison, PAT storage, handler, upstream forwarding, or auth acceptance behavior is introduced.
- Repository gate: Run `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm build`; note that current `origin/main` has no Vitest setup until #3 lands, so `pnpm test` is expected to be a workspace no-op unless #3 merges before implementation.

## Risks / open questions
- The issue asks for `createAuthKit` to be a signature only, but also says the factory body should throw `"not implemented"` for now. I plan to implement the exported function with the exact public signature and a throwing body, since plain ambient declarations would not produce a runtime export.
- The spec imports `Logger`, `z`, and `McpServer` from packages that are not yet installed on `origin/main`. Implementation should add only those API dependencies, but the exact version constraints need to be chosen from current package metadata at implementation time.
- Vitest configuration is tracked by open issue #3 and is not yet on `origin/main`. The type-level test for #8 should use TypeScript compilation directly unless the human wants #3 merged before implementing #8.

## Out of scope (reaffirmed from issue)
- Any runtime behavior for token validation, PAT minting/listing/rotation/revocation, handlers, scope matching, audit delivery, bypass mode, metadata serving, or MCP tool wrapping.
- The real `createAuthKit` implementation beyond a throwing stub.
- Memory token store and Express adapter import paths.
- Any v0.2+ deferred feature, placeholder, hook, or TODO.
- Editing `docs/spec/v0.1.md`.
