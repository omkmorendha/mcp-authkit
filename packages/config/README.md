# mcp-authkit-config

Config file loader and `defineConfig` helper for `mcp-authkit`.

Most users should import through the core package:

```ts
import { defineConfig } from "mcp-authkit/config"
```

## `defineConfig`

A typed identity function — purely for inference on `mcp-authkit.config.ts`
files. No runtime work.

```ts
// mcp-authkit.config.ts
import { defineConfig } from "mcp-authkit/config"
import { memoryTokenStore } from "mcp-authkit/stores/memory"

export default defineConfig({
  resourceIndicator: "https://mcp.example.com/",
  auth: {
    authorizationServer: {
      issuer: "https://as.example.com/",
      jwksUri: "https://as.example.com/.well-known/jwks.json",
    },
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
})
```

## `loadConfig`

Loads a TS or JS config file through `tsx`'s programmatic `tsImport` API,
validates the default export against the runtime schema, and returns the
typed `AuthKitConfig`.

Per spec §12 (bounded load) the loader:

- Times out after 10 seconds by default (`timeoutMs` overrides).
- Rejects any path that resolves outside `process.cwd()` unless
  `allowOutsideCwd: true` is passed. The CLI uses the override for an
  explicit `--config <abs-path>`.

```ts
import { loadConfig } from "mcp-authkit/config"

const config = await loadConfig("./mcp-authkit.config.ts")
```

Schema-validation errors include the file path and the dotted field path of
each offending entry.

## `redactConfigForLog`

Returns a safe-to-log summary: issuer, JWKS URI, audience, vocabulary
keys, token-store class name. Strips `bypass` user/scopes, the static
token, the PAT prefix, the introspection URL, and any other secret-shaped
field.

```ts
import { loadConfig, redactConfigForLog } from "mcp-authkit/config"
import { pino } from "pino"

const config = await loadConfig("./mcp-authkit.config.ts")
pino().info({ config: redactConfigForLog(config) }, "loaded mcp-authkit config")
```
