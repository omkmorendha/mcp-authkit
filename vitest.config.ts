import { defineConfig } from "vitest/config"

export default defineConfig({
  resolve: {
    alias: {
      "mcp-authkit-adapter-express": new URL(
        "./packages/adapter-express/src/index.ts",
        import.meta.url,
      ).pathname,
      "mcp-authkit-cli": new URL("./packages/cli/src/index.ts", import.meta.url).pathname,
      "mcp-authkit-config": new URL("./packages/config/src/index.ts", import.meta.url).pathname,
      "mcp-authkit-store-memory": new URL("./packages/store-memory/src/index.ts", import.meta.url)
        .pathname,
      "mcp-authkit-store-postgres": new URL(
        "./packages/store-postgres/src/index.ts",
        import.meta.url,
      ).pathname,
    },
  },
  test: {
    environment: "node",
    include: ["packages/*/src/**/*.test.ts"],
  },
})
