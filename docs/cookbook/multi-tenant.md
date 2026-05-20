# Cookbook: Multi-tenant authorization server

One MCP process, many tenants, each with its own authorization server.
Use when you host MCP for multiple customers and each customer has a
separate AS (or AS realm). Spec references:
[§5.1](../spec/v0.2.md#51-multi-tenant-as),
[§7](../spec/v0.2.md#7-multi-tenant-authorization-server).

## Imports

```ts
import { defineConfig } from "mcp-authkit/config"
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { Pool } from "pg"
```

## Snippet

`authorizationServer` becomes a **function** of the incoming request
instead of a static object:

```ts
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export default defineConfig({
  // Audience still includes the tenant-bearing hostname.
  resourceIndicator: process.env.RESOURCE_INDICATOR!,
  auth: {
    authorizationServer: async (selector) => {
      // selector.req: IncomingMessage (host, headers, URL — never body)
      // selector.tenantId: parsed from host, e.g. "acme" from "acme.mcp.example.com"
      const tenant = selector.tenantId
      if (!tenant) {
        throw new Error("no tenant on host header")
      }
      // Resolve from your tenant directory. Cache externally if the lookup
      // is expensive — the framework already caches JWKS per resolved
      // issuer string.
      const cfg = await lookupTenant(tenant)
      return {
        issuer: cfg.issuer,
        jwksUri: cfg.jwksUri,
      }
    },
    tokenStore: postgresTokenStore({ pool }),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
})
```

## How tenant routing works

1. Request arrives at `/mcp`. The framework calls your
   `authorizationServer(selector)` BEFORE any token parsing.
2. The resolved `{ issuer, jwksUri }` is memoized for the lifetime of
   that single request — pipeline steps (JWKS lookup, introspection,
   token exchange) all use the same resolved config.
3. The JWKS cache key includes the resolved `issuer` string, so two
   tenants with different ASs do not collide.
4. If your resolver throws, the framework returns a **503** with
   `WWW-Authenticate: Bearer error="server_error"` — NOT a 401. The
   token is not the problem; the AS lookup failed (spec
   [§7](../spec/v0.2.md#7-multi-tenant-authorization-server)).

## Tenant parsing

`selector.tenantId` is derived from the request host by the framework's
default parser (subdomain split). If your tenancy is in the path
(`/tenants/acme/mcp`) or a header (`X-Tenant-Id: acme`), parse it
yourself from `selector.req`:

```ts
authorizationServer: async ({ req }) => {
  const tenant = req.headers["x-tenant-id"]
  if (typeof tenant !== "string" || !tenant) {
    throw new Error("missing X-Tenant-Id")
  }
  return lookupTenant(tenant)
}
```

The selector exposes `req` (host, headers, URL) only — never the body.
Body parsing happens later in the pipeline.

## Env vars

None specific to multi-tenancy. The example above expects a tenant
directory (database, secret manager, config service) you control.

## What to test

- **Two tenants, two ASs.** Mint tokens at AS-A for `acme.example.com`
  and at AS-B for `globex.example.com`. A token from AS-A presented at
  `globex.example.com` must be rejected.
- **JWKS cache isolation.** Hit `acme.example.com`, then
  `globex.example.com`, with profiler/log inspection on JWKS fetches.
  Confirm the second tenant triggers a fresh fetch (the cache key is
  the resolved issuer, not the request).
- **Resolver throws -> 503.** Make `lookupTenant` throw for an unknown
  host; confirm the response is 503, not 401. Wrong status here will
  confuse OAuth clients into retrying with new tokens that will also
  fail.
- **Resolver returns invalid config.** Return an object missing
  `jwksUri`; the framework refuses to start (config validation).
- **Audience pinning.** Even with per-tenant ASs, every accepted token
  still has `aud == resourceIndicator`. If your tenants need
  per-tenant audiences, make `resourceIndicator` derive from the host
  the same way the resolver does, and verify the AS issues tokens with
  the matching `aud`.

## Common mistakes

- **Returning the same `issuer` for two tenants.** Defeats JWKS cache
  isolation and is almost certainly a configuration bug — file a
  resolver test that fails if two distinct `tenantId`s map to the same
  issuer.
- **Treating resolver failures as 401.** The framework already
  handles this correctly; don't catch and re-throw with a custom auth
  error in the resolver. Let it throw; the pipeline converts it to a
  503.
- **Putting the resolver in front of the framework.** Tempting to
  pre-resolve in your own middleware and pass a static `authorizationServer`
  per request via some side-channel — don't. The function form exists
  precisely so the framework owns the timing and memoization. Reading
  the body in your custom middleware will also break the raw-stream
  handlers downstream.
- **Forgetting to scope PATs by tenant.** PATs are stored in one
  table; `userIdentifier` is the only tenancy boundary. If your
  `resolveUserScopes` does not include the tenant in the user
  identifier, a leaked PAT from tenant A can authenticate against
  tenant B's `/mcp`. Pick a namespacing scheme
  (`acme:user-123`, `tenant-id:user-id`) and apply it everywhere.

## Upstream credentials (`upstreamFor` / `onBehalfOf`) with function-form AS

`upstreamFor` works the same way under a function-form `authorizationServer`
as it does for a single static AS. The framework resolves the issuer per call
from `auth.raw.iss` — which the JWT validator and the introspection validator
both populate from the validated token — and uses that issuer for:

- the RFC 8693 token exchange request (so each tenant exchanges against its
  own AS), and
- the upstream-credential cache key (so two tenants minting tokens for the
  same upstream audience never collide).

```ts
import { onBehalfOf } from "mcp-authkit/upstream"

authkit.registerTool(mcp, {
  name: "search-upstream",
  description: "Search the upstream API",
  inputSchema: { q: z.string() },
  requireScopes: ["mcp:read"],
  handler: async ({ input, auth }) => {
    const cred = await onBehalfOf({
      authkit,
      auth,
      audience: "https://upstream.example.com",
      scopes: ["upstream:read"],
    })
    const url = `https://upstream.example.com/search?q=${encodeURIComponent(input.q)}`
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${cred.token}` },
    })
    // ...
  },
})
```

Constraints:

- **OAuth-validated tokens only.** PAT, static-token, and bypass-authenticated
  `AuthContext`s cannot perform RFC 8693 token exchange; the helper rejects
  them with a clear error that names the `tokenType`. Plan tool-level fallback
  behaviour if your deployment mixes PATs with upstream-credential tools.
- **`iss` must be present in the validated token.** JWT validation guarantees
  this (the validator already enforced `iss == as.issuer` for the resolved
  tenant). RFC 7662 makes `iss` optional in introspection responses; if your
  AS omits it, the helper throws a typed error rather than guessing. Configure
  your AS to include `iss` in introspection results.
