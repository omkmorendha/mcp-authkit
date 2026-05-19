/**
 * Internal HTTP helpers for framework-agnostic handlers.
 *
 * Pure utilities over `node:http`; no transport or routing logic here.
 *
 * @module
 */
import type { IncomingMessage, ServerResponse } from "node:http"

/** Default request body size limit (1 MiB). */
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024

export type ParseJsonResult<T = unknown> =
  | { ok: true; value: T }
  | { ok: false; reason: "too_large" | "invalid_json" | "empty" }

/**
 * Read a JSON body from a Node request, enforcing a hard byte cap. Returns a
 * tagged result; callers map the failure reason onto an HTTP status code.
 *
 * The cap is enforced incrementally — once incoming chunks exceed `maxBytes`,
 * the body is rejected before more memory is buffered.
 */
export async function readJsonBody<T = unknown>(
  req: IncomingMessage,
  maxBytes: number = DEFAULT_MAX_BODY_BYTES,
): Promise<ParseJsonResult<T>> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string)
    total += buf.length
    if (total > maxBytes) {
      // Destroy the socket so the peer stops streaming and the connection
      // isn't reused with unread bytes still buffered.
      req.destroy()
      return { ok: false, reason: "too_large" }
    }
    chunks.push(buf)
  }
  if (total === 0) return { ok: false, reason: "empty" }
  const text = Buffer.concat(chunks).toString("utf8")
  try {
    const value = JSON.parse(text) as T
    return { ok: true, value }
  } catch {
    return { ok: false, reason: "invalid_json" }
  }
}

export interface HttpError {
  readonly code: string
  readonly message: string
}

/** Send a JSON response with sane caching/content-type defaults. */
export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) return
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
  })
  res.end(payload)
}

/** Send a uniform error JSON document. */
export function sendError(
  res: ServerResponse,
  status: number,
  code: string,
  message: string,
  extra?: Record<string, unknown>,
): void {
  sendJson(res, status, { error: code, error_description: message, ...extra })
}

export function methodNotAllowed(res: ServerResponse, allow: readonly string[]): void {
  if (res.headersSent) return
  res.setHeader("Allow", allow.join(", "))
  sendError(res, 405, "method_not_allowed", `Allowed methods: ${allow.join(", ")}`)
}

export function notFound(res: ServerResponse, message = "Not found"): void {
  sendError(res, 404, "not_found", message)
}

/**
 * Compute the path portion of a request URL, ignoring query string and any
 * mount prefix the consumer placed in front of the handler. Returns "/" when
 * the URL is missing.
 */
export function requestPath(req: IncomingMessage): string {
  const raw = req.url ?? "/"
  const qIndex = raw.indexOf("?")
  const path = qIndex === -1 ? raw : raw.slice(0, qIndex)
  return path.length === 0 ? "/" : path
}
