# Cookbook: Production stdio (signed handshake)

MCP over stdio with HMAC-signed frames, replay protection, and no bypass.
Use when the MCP server is a long-lived subprocess of a trusted local
client (`claude-code`, an Electron app, an internal CLI). Spec reference:
[§11](../spec/v0.2.md#11-production-stdio-support).

A runnable copy of this configuration ships at
[`examples/stdio/`](../../examples/stdio/).

## Imports

```ts
import { defineConfig } from "mcp-authkit/config"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
```

(Swap `memoryTokenStore` for `sqliteTokenStore` if PATs need to survive
process restarts.)

## Snippet

```ts
const hmacKey = process.env.MCP_AUTHKIT_HMAC_KEY
if (!hmacKey) throw new Error("MCP_AUTHKIT_HMAC_KEY required")

const staticToken = process.env.MCP_AUTHKIT_STATIC_TOKEN
if (!staticToken) throw new Error("MCP_AUTHKIT_STATIC_TOKEN required")

export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR ?? "mcp-authkit://stdio/local",
  auth: {
    tokenStore: memoryTokenStore(),
    pat: { enabled: true, prefix: "mcp_pat_" },
    staticToken: {
      token: staticToken,
      user: "stdio-local",
      scopes: ["echo:say"],
    },
    stdio: { mode: "signed", hmacKey },
  },
  scopes: { vocabulary: { "echo:say": { description: "Echo a string" } } },
  resolveUserScopes: async () => ["echo:say"],
})
```

Then wire the transport in `server.ts`:

```ts
import { createSignedStdioTransport } from "mcp-authkit/stdio"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"

const mcp = new McpServer({ name: "stdio", version: "0.1.0" })
const transport = createSignedStdioTransport(authkit, mcp)
await mcp.connect(transport)
```

## Env vars

| Var                          | Required | Notes                                                       |
| ---------------------------- | -------- | ----------------------------------------------------------- |
| `MCP_AUTHKIT_HMAC_KEY`       | yes      | High-entropy symmetric key shared with the client           |
| `MCP_AUTHKIT_STATIC_TOKEN`   | yes      | Bearer used inside the framed channel for authentication    |
| `RESOURCE_INDICATOR`         | no       | Defaults to `mcp-authkit://stdio/local`                     |

Generate both with the CLI:

```bash
pnpm exec mcp-authkit gen-secret   # HMAC key
pnpm exec mcp-authkit gen-secret   # static token
```

The HMAC key is interpreted as **UTF-8 bytes** (via `normaliseHmacKey`);
both ends must derive the same buffer. Do not base64url-decode it on
the client side.

## Frame format

Each frame is `header (12 bytes) | payload | hmac tag (32 bytes)`:

| Field        | Width    | Notes                                              |
| ------------ | -------- | -------------------------------------------------- |
| counter      | 8 bytes  | Big-endian unsigned, strictly increasing           |
| payload size | 4 bytes  | Big-endian unsigned, capped at 16 MiB              |
| payload      | variable | Raw JSON-RPC message bytes                         |
| hmac         | 32 bytes | HMAC-SHA-256 over `counter \|\| size \|\| payload` |

Helpers (`encodeFrame`, `tryDecodeFrame`, `normaliseHmacKey`) are
exported from `mcp-authkit/stdio` — both server and client use the same
module.

## Bypass is refused

Setting `stdio.mode: "signed"` makes the framework refuse to enable
bypass at startup. The static token (or PATs) is the only way in. The
signed channel authenticates the *transport*, not the caller —
authentication of the request itself still goes through the v0.1
pipeline.

## What to test

- **Tamper.** Flip a byte in the payload of an encoded frame; the
  transport tears down and the process exits non-zero. The supervisor
  must restart a fresh transport.
- **Replay.** Re-send a previously-accepted frame; the counter check
  rejects it and the transport tears down.
- **Key mismatch.** Run the server with one HMAC key and the client
  with a different one; first frame fails HMAC verification.
- **Bypass refused.** Set `bypass.enabled: true` alongside
  `stdio.mode: "signed"`; the framework refuses to start.
- **Key fingerprint logged.** Startup logs include an 8-hex-char
  fingerprint of the HMAC key. Match it on the client to catch key
  drift before the first request.
- **Static token authenticates.** A frame whose payload references the
  configured static token succeeds; a wrong static token returns a
  401-equivalent JSON-RPC error inside the framed channel.

## Common mistakes

- **Encoding the HMAC key wrong on the client.** UTF-8 bytes on both
  ends. Don't base64url-decode it on the client; both should pass the
  same string into `normaliseHmacKey`.
- **Reusing counters across processes.** Counters are per-transport,
  per-direction. A fresh transport starts at zero on each side. If you
  bridge frames between two transports, you must rewrite counters.
- **Trying to send server-initiated messages.** The signed framing is
  strictly request/response. Notifications, sampling, and elicitation
  from the server are dropped (the example logs a `warn`). If you need
  bidirectional async, use HTTP with the production guide.
- **Leaving the HMAC key in argv.** The CLI refuses to read it from
  argv. Use env vars or the config file. `MCP_AUTHKIT_HMAC_KEY=...
  node server.js` is fine; `node server.js --hmac-key ...` is not.
- **Checking in the static token.** Treat it like any other long-lived
  secret. Rotate per-environment, never commit.
