/**
 * Public `mcp-authkit/config` entry point.
 *
 * Re-exports the loader and `defineConfig` from `mcp-authkit-config`, but
 * retypes `defineConfig` to the core `AuthKitConfig` so callers in user code
 * get inference on every field (including the `Logger` slot, which the
 * standalone config package types as `unknown` to avoid pulling in `pino`).
 *
 * The structural compatibility between core's `AuthKitConfig` and the config
 * package's mirror is asserted below — any drift fails `pnpm typecheck`.
 *
 * Spec: docs/spec/v0.2.md#58-config-file-format
 *       docs/spec/v0.2.md#510-import-paths-added-in-v02
 */
import {
  defineConfig as _defineConfig,
  loadConfig as _loadConfig,
  redactConfigForLog as _redactConfigForLog,
  type AuthKitConfig as ConfigAuthKitConfig,
  type LoadConfigOptions,
} from "mcp-authkit-config"
import type { AuthKitConfig } from "./types.js"

// Compile-time check: the config package's mirror must be assignable to and
// from core's authoritative AuthKitConfig. Any structural drift breaks here.
const _toConfig: (c: AuthKitConfig) => ConfigAuthKitConfig = (c) => c as ConfigAuthKitConfig
const _fromConfig: (c: ConfigAuthKitConfig) => AuthKitConfig = (c) => c as AuthKitConfig
void _toConfig
void _fromConfig

export function defineConfig(config: AuthKitConfig): AuthKitConfig {
  return _defineConfig(config as unknown as ConfigAuthKitConfig) as unknown as AuthKitConfig
}

export async function loadConfig(
  filePath: string,
  options?: LoadConfigOptions,
): Promise<AuthKitConfig> {
  const loaded = await _loadConfig(filePath, options)
  return loaded as unknown as AuthKitConfig
}

export function redactConfigForLog(config: AuthKitConfig): Record<string, unknown> {
  return _redactConfigForLog(config as unknown as ConfigAuthKitConfig)
}

export { ConfigLoadError, type LoadConfigOptions } from "mcp-authkit-config"
