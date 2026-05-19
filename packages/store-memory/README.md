# mcp-authkit-store-memory

In-memory `TokenStore` implementation for `mcp-authkit`.

Most users should import it through the core package:

```ts
import { memoryTokenStore } from "mcp-authkit/stores/memory"
```

This store is intended for tests and local development. It is process-local and
non-durable.
