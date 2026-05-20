# Cookbook: Upstream credentials (token exchange)

Call an upstream API from a tool handler using a freshly-minted,
audience-bound token. Use this when your MCP tool needs to act on
behalf of the caller against a separate API (e.g. a CRM, a search
backend, an internal microservice). Spec references:
[§5.5](../spec/v0.2.md#55-token-exchange-rfc-8693),
[§5.6](../spec/v0.2.md#56-upstream-credentials-helper),
[§8](../spec/v0.2.md#8-token-exchange-and-upstream-credentials),
[§14](../spec/v0.1.md#14-security-non-negotiables) (no token passthrough).

> **Hard rule.** The framework never forwards the caller's token to the
> upstream API. `upstreamFor` always synthesizes a new token via
> RFC 8693 token exchange. The minted token has `aud == upstream`; the
> caller's token has `aud == resourceIndicator`. Audience mismatch is a
> reject, not a fallback.

## Imports

```ts
import { onBehalfOf } from "mcp-authkit/upstream"
```

(For a long-lived audience, pre-construct the helper once at startup:
`const upstreamFetch = authkit.upstreamFor("https://upstream.example.com")`.)

## Snippet

Inside a tool handler:

```ts
authkit.registerTool(mcp, {
  name: "search-crm",
  description: "Search the upstream CRM",
  inputSchema: { query: z.string() },
  requireScopes: ["crm:read"],
  handler: async ({ input, auth }) => {
    const { token } = await onBehalfOf({
      authkit,
      auth,
      audience: "https://crm.example.com",
      scopes: ["records:read"],
    })
    const res = await fetch(
      `https://crm.example.com/search?q=${encodeURIComponent(input.query)}`,
      { headers: { Authorization: `Bearer ${token}` } },
    )
    const body = await res.json()
    return { content: [{ type: "text", text: JSON.stringify(body) }] }
  },
})
```

`auth` is the `AuthContext` the framework attaches to every authenticated
tool call. `onBehalfOf` exchanges it for an upstream token, scoped to
the upstream API.

## Caching

The helper caches per `(subject, audience, sorted-scopes)` for
`min(token.expiresIn, 5 min) − 30 s`. Cache lives in the token store's
optional methods (`cacheUpstreamCredential` / `findUpstreamCredential`)
when the store implements them (spec
[§6.2](../spec/v0.2.md#62-optional-cache-methods)) — Postgres, SQLite,
and the Redis decorator all do. Otherwise falls back to an in-process
LRU (cap 100) and the framework logs a `warn` at startup.

A cache hit returns a token with **at least 30 s** of useful life.
No need to re-check expiry in the handler.

## Multi-tenant deployments (function-form `authorizationServer`)

`upstreamFor` is supported under both the static-object and the function-form
`authorizationServer` (spec [§5.1](../spec/v0.2.md#51-multi-tenant-as)). In
multi-tenant mode the issuer is resolved per call from `auth.raw.iss` (the
`iss` claim from the validated JWT or introspection response) and is included
in the cache key so two tenants minting tokens for the same upstream audience
never collide. See [Cookbook: Multi-tenant](./multi-tenant.md#upstream-credentials-upstreamfor--onbehalfof-with-function-form-as)
for an end-to-end example. PAT-, static-, and bypass-authenticated requests
cannot perform RFC 8693 exchange and are rejected with a clear error.

## Configuring the AS

For token exchange to succeed the AS must:

- Support [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693).
- Issue tokens with `aud == upstream` (RFC 8707 `resource` parameter).
- Accept the framework's subject token (i.e. the caller's MCP token) as
  a valid input grant. Most ASs gate this on client-credentials of the
  exchanging client; configure those credentials per your AS's docs.

Audit events fired by the framework on each call (spec
[§8.2](../spec/v0.2.md#82-audit-events-for-exchange)):

- `upstream.exchange` — successful exchange. Carries audience, scopes,
  expiresAt. Does NOT carry the minted token.
- `upstream.exchange_reject` — exchange failed. Carries the error
  reason; safe to log.

## Env vars

None specific to the helper. The AS-exchange client credentials live
inside the AS-specific configuration the framework consumes via
`authorizationServer`.

## What to test

- **No passthrough.** Spy on `fetch` inside the handler; the
  `Authorization` header must be the **new** token, never the caller's
  raw token (`auth.raw.access_token`).
- **Audience pinning.** Configure the test AS to return a token with
  `aud != audience` requested. The helper must reject with
  `TokenExchangeError` — no fallback to the caller's token.
- **Cache hit.** Call the tool twice with the same `(subject, audience,
  scopes)`. Second call must not hit the AS. Verify via the audit sink:
  one `upstream.exchange` event, not two.
- **TTL ceiling.** Configure the AS to return a 1-hour token; cache
  TTL must be capped to 5 min − 30 s = 4 min 30 s.
- **Subject-token audience check.** Construct an `auth` whose
  `raw.access_token` has `aud != resourceIndicator` (this should never
  happen in production — the pipeline would have rejected it earlier —
  but the helper double-checks). Confirm the exchange throws BEFORE
  hitting the AS.

## Common mistakes

- **Passing the upstream token back to the client.** Don't. The token
  belongs in the upstream HTTP call only. Returning it from a tool
  handler defeats the no-passthrough rule (you've turned your MCP
  server into a token-laundry service for any caller).
- **Treating the cache as authoritative.** The cache exists to avoid
  re-exchanging on every call. A revoked subject token will still let
  cached upstream tokens live out the rest of their TTL window. If
  this is a problem, lower `UPSTREAM_CACHE_TTL_CEILING_SECONDS` (in
  your fork) — but really, the AS should be revoking grants and the
  upstream API should be honouring those revocations.
- **Hard-coding the upstream URL inside the audience.** Audiences
  identify the API (a logical name), not a specific URL path. Use the
  URL the AS expects; ask the AS owner if unsure.
- **Scope mismatches.** The AS may downgrade the requested scopes; the
  helper records the returned scope set, not the requested one. Tools
  that branch on scopes should check the returned set, not assume.
