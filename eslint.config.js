import tseslint from "typescript-eslint"

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/node_modules/**", "**/*.tgz", "pnpm-lock.yaml"],
  },
  {
    files: ["**/*.{js,mjs,cjs,ts,tsx}"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        sourceType: "module",
      },
    },
    rules: {},
  },
)
