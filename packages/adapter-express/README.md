# mcp-authkit-adapter-express

Express middleware adapter for `mcp-authkit`.

Most users should import it through the core package:

```ts
import { expressHandlers } from "mcp-authkit/adapters/express"
```

The adapter wraps the framework-agnostic MCP, metadata, and PAT handlers as
Express request handlers.
