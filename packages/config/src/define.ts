/**
 * Typed identity helper for `mcp-authkit.config.ts` files.
 *
 * No runtime work; exists purely so users get inference on the config
 * literal without having to spell `satisfies AuthKitConfig`. The loader
 * (`loadConfig`) is responsible for the runtime schema check.
 *
 * Spec: docs/spec/v0.2.md#58-config-file-format
 */
import type { AuthKitConfig } from "./types.js"

export function defineConfig(config: AuthKitConfig): AuthKitConfig {
  return config
}
