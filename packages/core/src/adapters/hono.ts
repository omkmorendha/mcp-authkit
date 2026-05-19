/**
 * Re-export of the Hono adapter under the spec-documented import path
 * `mcp-authkit/adapters/hono` (spec v0.2 §5.10).
 *
 * The adapter lives in `mcp-authkit-adapter-hono` so it can carry its
 * own Hono peer dependency without polluting core's runtime imports.
 * The adapter declares its own minimal `AuthKitLike` / `RawHandlers`
 * surface (to avoid a workspace cycle); the structural assertions below
 * keep the two declarations in lockstep — any drift fails `pnpm typecheck`.
 */
import {
  honoHandlers as _honoHandlers,
  honoMiddleware as _honoMiddleware,
  type AuthKitLike,
  type HonoHandlers,
  type RawHandlers,
} from "mcp-authkit-adapter-hono"
import type { AuthKit, Handlers } from "../types.js"

// Compile-time checks: core's contract must satisfy the adapter's structural
// surface. Reverse-direction assignments are intentional — if either drifts,
// the next typecheck breaks.
const _checkRawHandlers: () => RawHandlers = () => ({}) as Handlers
const _checkAuthKit: () => AuthKitLike = () => ({}) as AuthKit
void _checkRawHandlers
void _checkAuthKit

export const honoHandlers: (
  authkit: AuthKit,
  mcp: Parameters<AuthKit["handlers"]>[0],
) => HonoHandlers = _honoHandlers

export const honoMiddleware: (
  authkit: AuthKit,
  mcp: Parameters<AuthKit["handlers"]>[0],
) => ReturnType<typeof _honoMiddleware> = _honoMiddleware

export type { HonoHandlers }
