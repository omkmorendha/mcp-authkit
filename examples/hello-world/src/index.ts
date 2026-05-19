import { createAuthKit } from "mcp-authkit"
import { memoryTokenStore } from "mcp-authkit/stores/memory"
import "mcp-authkit-adapter-express"

console.log(createAuthKit, memoryTokenStore)
