/**
 * RFC 9728 protected resource metadata handler.
 *
 * Spec: docs/spec/v0.1.md#13-oauth-endpoints-the-framework-owns
 *
 * Returns a JSON document at `GET /.well-known/oauth-protected-resource`:
 *   { resource, authorization_servers?, bearer_methods_supported, scopes_supported }
 *
 * `authorization_servers` is omitted when no AS is configured (bypass-only
 * deployments). `scopes_supported` is populated from the vocabulary keys.
 *
 * @module
 */
import type { IncomingMessage, ServerResponse } from "node:http"
import type { ScopeVocabulary } from "../types.js"
import { type HostValidationOptions, validateHost } from "./host.js"
import { methodNotAllowed, sendError, sendJson } from "./http-utils.js"

export interface MetadataHandlerOptions {
  readonly resourceIndicator: string
  /** Issuer URL of the authorization server, if configured. */
  readonly authorizationServerIssuer?: string
  readonly vocabulary: ScopeVocabulary
  readonly host: HostValidationOptions
}

export interface ProtectedResourceMetadata {
  resource: string
  authorization_servers?: string[]
  bearer_methods_supported: string[]
  scopes_supported: string[]
}

/**
 * Build the metadata document. Exposed for adapters that want to serve it
 * via their own routing layer.
 */
export function buildMetadataDocument(
  options: Omit<MetadataHandlerOptions, "host">,
): ProtectedResourceMetadata {
  const doc: ProtectedResourceMetadata = {
    resource: options.resourceIndicator,
    bearer_methods_supported: ["header"],
    scopes_supported: Object.keys(options.vocabulary).sort(),
  }
  if (options.authorizationServerIssuer) {
    doc.authorization_servers = [options.authorizationServerIssuer]
  }
  return doc
}

export function createMetadataHandler(
  options: MetadataHandlerOptions,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const document = buildMetadataDocument(options)
  return async (req, res) => {
    const hostCheck = validateHost(req, options.host)
    if (!hostCheck.ok) {
      sendError(res, 403, "forbidden", `Host header ${hostCheck.reason}`)
      return
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      methodNotAllowed(res, ["GET", "HEAD"])
      return
    }
    sendJson(res, 200, document)
  }
}
