# stdio (production signed-handshake)

Minimal protected MCP server that runs over stdio using the v0.2
signed-handshake transport (spec
[v0.2 §11](../../docs/spec/v0.2.md#11-production-stdio-support)). Every
outbound frame is HMAC-signed and every inbound frame is verified.
Replay (a non-increasing counter) and tampering (a bad HMAC tag) tear
the transport down.

Bypass mode is refused in this configuration; only PATs or a configured
`auth.staticToken` authenticate.

## Files

| Path                     | Purpose                                                |
| ------------------------ | ------------------------------------------------------ |
| `mcp-authkit.config.ts`  | `defineConfig` with `auth.stdio.mode: "signed"`        |
| `server.ts`              | Wires `createSignedStdioTransport` to an `McpServer`   |

The server exposes a single `echo` tool that returns its `text` input
and requires the `echo:say` scope. The example treats every message in
the signed channel as authenticated by the configured static token;
real deployments would extract per-call credentials from the JSON-RPC
payload instead.

## Setup

### 1. Generate secrets

The signed-handshake transport needs a high-entropy symmetric key shared
between server and client. The static token (used inside the channel as
the bearer) needs its own secret. Use the bundled CLI:

```bash
pnpm --filter mcp-authkit-cli exec mcp-authkit gen-secret   # HMAC key
pnpm --filter mcp-authkit-cli exec mcp-authkit gen-secret   # static token
```

Both commands print a 32-byte base64url string. Store them in your
environment manager and rotate them the same way you rotate other
long-lived server secrets.

### 2. Set env vars

```bash
export MCP_AUTHKIT_HMAC_KEY="<paste-the-first-secret>"
export MCP_AUTHKIT_STATIC_TOKEN="<paste-the-second-secret>"
# Optional: override the audience used for token validation.
export RESOURCE_INDICATOR="mcp-authkit://stdio/local"
```

The config refuses to load if either secret is empty.

### 3. Install and build

```bash
pnpm install
pnpm --filter mcp-authkit-example-stdio build
```

## Running

```bash
# From source (tsx, dev):
pnpm --filter mcp-authkit-example-stdio dev

# Or from the built artifact:
pnpm --filter mcp-authkit-example-stdio start
```

Server logs go to stderr; stdout carries the binary frame stream. The
startup line includes an 8-hex-char key fingerprint — match it on the
client to detect key drift early.

```text
WARN  Production stdio (signed-handshake) is active — every frame is HMAC-verified; ...
INFO  signed stdio transport ready { keyFingerprint: "a1b2c3d4" }
```

## Frame format

Each frame is `header (12 bytes) | payload | hmac tag (32 bytes)`:

| Field        | Width    | Notes                                          |
| ------------ | -------- | ---------------------------------------------- |
| counter      | 8 bytes  | Big-endian unsigned, strictly increasing       |
| payload size | 4 bytes  | Big-endian unsigned, capped at 16 MiB          |
| payload      | variable | The raw JSON-RPC message bytes                 |
| hmac         | 32 bytes | HMAC-SHA-256 over `counter \|\| size \|\| payload` |

See `packages/core/src/stdio/frame.ts` for the helpers
(`encodeFrame`, `tryDecodeFrame`, `normaliseHmacKey`) and
`transport.ts` for the runtime.

The HMAC key string from the env var is interpreted as **UTF-8 bytes**
(via `normaliseHmacKey`); clients that talk to this server must do the
same. A common mistake is to base64url-decode the key on the client
side — don't, both ends must derive the same buffer.

## Sending a frame

Drive the server from a small Node script that reuses the framing
helpers:

```ts
import { spawn } from "node:child_process"
import {
  encodeFrame,
  tryDecodeFrame,
  HEADER_BYTES,
  normaliseHmacKey,
} from "mcp-authkit/stdio"

const key = normaliseHmacKey(process.env.MCP_AUTHKIT_HMAC_KEY!)

const child = spawn("pnpm", ["--filter", "mcp-authkit-example-stdio", "start"], {
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
})

let outCounter = 0n
function send(obj: unknown) {
  child.stdin.write(encodeFrame(key, outCounter++, Buffer.from(JSON.stringify(obj), "utf8")))
}

send({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "smoke", version: "0" },
  },
})
send({ jsonrpc: "2.0", method: "notifications/initialized" })
send({
  jsonrpc: "2.0",
  id: 2,
  method: "tools/call",
  params: { name: "echo", arguments: { text: "hi" } },
})
```

Each request frame must use a strictly larger counter than the previous
one (per direction). Server responses arrive on stdout in the same
framing — decode them with `tryDecodeFrame(key, buffer, expectedMinCounter)`.

## Production notes

For an end-to-end walkthrough see
[`docs/production.md`](../../docs/production.md) and the
[`production-stdio`](../../docs/cookbook/production-stdio.md) cookbook
entry.

- The signed-handshake transport authenticates the *channel*, not the
  caller. Inside the framed channel you still authenticate the request
  with a PAT or the static token. The example wires the static token
  on every inbound message via the MCP SDK's `MessageExtraInfo.authInfo`
  slot.
- Treat the HMAC key and static token like any other long-lived
  secrets: rotate them, scope them per environment, never check them
  into source control.
- The transport tears down on the first tamper or replay. The wrapping
  process is expected to exit non-zero so the supervisor restarts a
  fresh transport with a fresh counter window.
- Server-initiated messages (notifications, sampling, elicitation)
  cannot be delivered through the signed framing — it's strictly
  request/response. The bridge logs and drops anything the SDK tries
  to send unsolicited.
