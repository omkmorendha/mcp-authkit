# Security Policy

## Supported versions

The latest released minor version on `latest` is the only supported line.
Older versions receive critical-security fixes at the maintainer's
discretion; do not rely on long-term backports.

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

Report privately via either:

1. **GitHub private vulnerability reporting** (preferred) — open
   <https://github.com/omkmorendha/mcp-authkit/security/advisories/new>.
   This creates a private advisory only the maintainers can see, with
   a discussion thread and a fix-tracking workflow.
2. **Email** — `omkmorendha@gmail.com` with subject `[mcp-authkit
   security]`. Encrypt with GPG if you can; ask in the email for a key
   if you don't have one yet.

When reporting, please include:

- The affected version(s).
- A description of the issue and its impact.
- A minimal reproduction (code or curl invocations) if you have one.
- Whether the report has been disclosed elsewhere, and if so, where.

## What counts as a vulnerability

mcp-authkit is an authentication framework; spec section 14 lists the
non-negotiables. The following are always in-scope:

- Token validation bypass (audience, issuer, signature, expiry).
- Scope-check bypass — any path where a tool handler runs without the
  declared scope satisfied.
- Authorization-server impersonation, JWKS poisoning, or any path that
  accepts a token signed by an untrusted key.
- PAT plaintext leakage, hash bypass, or any non-constant-time secret
  comparison.
- Refresh-token reuse / family-revocation bypass.
- DNS-rebinding bypass (Host header validation).
- PAT-management endpoints accepting PAT- or static-authenticated
  requests (spec §14).
- `bypass.allowInProduction: false` being bypassable in production.
- Production-stdio signed-handshake forging or replay.

Out of scope:

- Issues that require physical or local-machine access.
- Findings that depend on misconfiguration explicitly documented as
  unsafe (e.g. `bypass.allowInProduction: true`).
- Denial-of-service via expensive crypto on an unauthenticated path,
  unless the cost is wildly disproportionate to the request.

## Response timeline

- **Acknowledgement**: within 72 hours of report.
- **Initial assessment**: within 7 days.
- **Fix and disclosure**: target 90 days from report, sooner for
  critical issues. We will coordinate with reporters before public
  disclosure.

Thank you for helping keep mcp-authkit and its users safe.
