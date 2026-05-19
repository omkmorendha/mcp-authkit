# mcp-authkit

Production-grade OAuth 2.1 + Personal Access Tokens for Model Context Protocol servers.

> **Status:** pre-v0.1, under active development. See [`docs/spec/v0.1.md`](docs/spec/v0.1.md)
> for what's in scope and [`ROADMAP.md`](ROADMAP.md) for what's after that.

## What it is

A framework-agnostic toolkit for building MCP servers that:

- Validate OAuth 2.1 bearer tokens from any external AS (Auth0, Keycloak, WorkOS, Cognito, …) — RFC-compliant resource server behavior.
- Issue and manage **Personal Access Tokens** so scripts and CI don't have to dread the auth.
- Enforce **per-tool, per-operation scope checks** — not just "is this caller authenticated."
- Stay out of the way: zero web-framework imports in core, Express adapter as a separate entry point.

Built on `@modelcontextprotocol/sdk`. MCP spec revision **2025-06-18**.

## Quickstart

The hello-world example will live at [`examples/hello-world`](examples/hello-world) once the corresponding issue lands. The full quickstart guide is tracked under Stage 4 of the v0.1 roadmap.

## Contributing

Read [`CLAUDE.md`](CLAUDE.md) first. It applies to every contributor (human or otherwise) and lays out the workflow, security non-negotiables, and commit hygiene.
