# mcp-authkit

Framework-agnostic auth for Model Context Protocol servers.

`mcp-authkit` validates OAuth bearer tokens for MCP resource servers, issues
hashed Personal Access Tokens for scripts and CI, serves protected-resource
metadata, and enforces per-tool scopes before handlers run.

## Install

```bash
pnpm add mcp-authkit @modelcontextprotocol/sdk pino zod
```

For the in-memory store and Express adapter:

```ts
import { createAuthKit } from "mcp-authkit"
import { expressHandlers } from "mcp-authkit/adapters/express"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
```

See the repository quickstart for a complete runnable server:
https://github.com/omkmorendha/mcp-authkit#readme
