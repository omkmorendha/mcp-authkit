/**
 * Re-export of the Express adapter under the spec-documented import path
 * `mcp-authkit/adapters/express` (spec §6.3).
 *
 * The adapter lives in `mcp-authkit-adapter-express` so it can carry its
 * own Express peer dependency without polluting core's runtime imports.
 * The adapter declares its own minimal `AuthKitLike` / `RawHandlers`
 * surface (to avoid a workspace cycle); the structural assertions below
 * keep the two declarations in lockstep — any drift fails `pnpm typecheck`.
 */
import {
  expressHandlers as _expressHandlers,
  type AuthKitLike,
  type ExpressHandlers,
  type RawHandlers,
} from "mcp-authkit-adapter-express"
import type { AuthKit, Handlers } from "../types.js"

// Compile-time checks: core's contract must satisfy the adapter's structural
// surface. Reverse-direction assignments are intentional — if either drifts,
// the next typecheck breaks.
const _checkRawHandlers: () => RawHandlers = () => ({}) as Handlers
const _checkAuthKit: () => AuthKitLike = () => ({}) as AuthKit
void _checkRawHandlers
void _checkAuthKit

export const expressHandlers: (
  authkit: AuthKit,
  mcp: Parameters<AuthKit["handlers"]>[0],
) => ExpressHandlers = _expressHandlers
export type { ExpressHandlers }
