# mcp-authkit-cli

Command-line companion for [mcp-authkit](https://github.com/omkmorendha/mcp-authkit).

## Install

```sh
pnpm add -D mcp-authkit-cli
```

Or invoke directly:

```sh
pnpm dlx mcp-authkit-cli --help
```

## Commands

```
mcp-authkit <command> [options]

Commands:
  init [path]              Scaffold a project (config, env, hello-world).
  mint-pat                 Mint a PAT against the configured store.
  verify-config            Load and validate the config file.
  jwks-fetch               Fetch JWKS for a configured issuer.
  gen-secret [length]      Generate a cryptographically strong secret.

Global options:
  --config <path>          Path to mcp-authkit.config.ts (default: ./mcp-authkit.config.ts)
  --log-level <level>      pino log level (trace|debug|info|warn|error|fatal|silent)
  --json                   Machine-readable JSON output where applicable
```

## Exit codes

Per spec [§5.7](../../docs/spec/v0.2.md#57-cli):

- `0` success
- `1` user error (bad flag, missing arg, refusal due to a non-empty directory)
- `2` config error (invalid file, schema violation)
- `3` runtime error (network failure, store error)

## Security

The CLI never reads secrets from `argv` (spec
[§12](../../docs/spec/v0.2.md#12-security-non-negotiables-additions)). Any flag
whose name matches `secret|token|password|pat|key|apikey|credential|passphrase`
is rejected before parsing. Secrets live in environment variables or in the
loaded config file.
