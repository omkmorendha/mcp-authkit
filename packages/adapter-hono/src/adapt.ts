/**
 * Private request/response adaptation layer.
 *
 * Bridges Hono's Web-Fetch `Context` (`c.req.raw`, `c.body()`) to the
 * Node-style `IncomingMessage`/`ServerResponse` surface that the
 * framework-agnostic `Handlers` from spec v0.1 §6.1 expect.
 *
 * Design notes:
 *
 *   - Request adaptation is read-only and synchronous: we pull the
 *     `Method`, `URL` path+query, headers, and a Node `Readable` body
 *     stream from `c.req.raw`. The MCP transport reads `req.headers` for
 *     `host` / `authorization`, and the body via `req.on("data")` etc.
 *
 *   - Response adaptation is streaming: writes hit a `PassThrough` whose
 *     readable side we hand back to Hono as the response body. The
 *     headers and status are captured via the same surface
 *     `ServerResponse` exposes (`writeHead`, `setHeader`, `statusCode`,
 *     `getHeader`, `headersSent`, `writableEnded`).
 *
 *   - We resolve a `Response` object as soon as headers are committed
 *     (`writeHead` or the first `write`/`end`). The Hono adapter awaits
 *     that promise, then assigns the `Response` to `c.res` (Hono ships
 *     the body as the underlying readable stream) or returns it.
 *
 * This module is internal — it is NOT part of the public API.
 *
 * @module
 */
import type {
  IncomingHttpHeaders,
  IncomingMessage,
  OutgoingHttpHeader,
  OutgoingHttpHeaders,
  ServerResponse,
} from "node:http"
import { PassThrough, Readable } from "node:stream"

/**
 * Build a Node-style `IncomingMessage` view of a Web `Request`.
 *
 * Only the surface that `Handlers` (and the MCP SDK transport) actually
 * touches is implemented: `method`, `url`, `headers`, `httpVersion`, and
 * Readable behaviour for the body. The returned object is structurally
 * compatible with `IncomingMessage`; we cast through `unknown` because
 * the full Node prototype includes many fields we deliberately omit.
 */
export function toIncomingMessage(request: Request): IncomingMessage {
  const url = new URL(request.url)
  const headers: IncomingHttpHeaders = {}
  for (const [name, value] of request.headers) {
    // Node lower-cases header names on IncomingMessage; preserve that
    // contract so `req.headers.host` / `req.headers.authorization`
    // continue to work for downstream consumers.
    const lower = name.toLowerCase()
    const existing = headers[lower]
    if (existing === undefined) {
      headers[lower] = value
    } else if (Array.isArray(existing)) {
      existing.push(value)
    } else {
      headers[lower] = [existing, value]
    }
  }
  // A Web `Request` does not carry a `Host` header — the authority is
  // encoded in the URL. Node's `IncomingMessage.headers.host` is what
  // the DNS-rebinding check (spec §14) reads, so we synthesise it from
  // the URL's `host` (which already includes the port if any) unless
  // an explicit Host header was somehow set on the Request.
  if (headers.host === undefined && url.host !== "") {
    headers.host = url.host
  }
  // The MCP SDK's Node transport delegates to `@hono/node-server`'s
  // `getRequestListener`, which itself constructs a Web `Request` from
  // our IncomingMessage. It reads the body as a Node `Readable` stream,
  // so we provide one. When there is no body (GET/DELETE), we still
  // hand back a tiny empty Readable for type-stability.
  const bodyStream: Readable =
    request.body === null
      ? Readable.from([])
      : Readable.fromWeb(request.body as Parameters<typeof Readable.fromWeb>[0])

  // Path + query, omitting the origin — Node `IncomingMessage.url` is a
  // path-relative URL.
  const path = `${url.pathname}${url.search}`

  // Build a minimal object then cast. Properties not present here are
  // ones the spec's `Handlers` provably do not touch (e.g. `socket`,
  // `connection`); the cast is the explicit reminder that this surface
  // is curated and tested rather than a full Node primitive.
  const message = Object.assign(bodyStream, {
    method: request.method,
    url: path,
    headers,
    httpVersion: "1.1",
    httpVersionMajor: 1,
    httpVersionMinor: 1,
    rawHeaders: [...request.headers].flat(),
    complete: false,
  }) as unknown as IncomingMessage

  return message
}

/**
 * The captured side of an adapted `ServerResponse`.
 *
 * `response` resolves once headers are committed (`writeHead`, first
 * `write`, or `end`). The Hono adapter awaits this promise so the body
 * can be streamed through the returned `Response`.
 */
export interface AdaptedResponse {
  res: ServerResponse
  response: Promise<Response>
}

/**
 * Build a Node-style `ServerResponse` whose writes stream into a Web
 * `Response`.
 *
 * The returned `ServerResponse` supports the surface used by the v0.1
 * handlers and the MCP SDK transport:
 *
 *   - `statusCode` / `statusMessage` (read/write)
 *   - `setHeader` / `getHeader` / `removeHeader` / `hasHeader`
 *   - `writeHead(status, [headers])` / `flushHeaders`
 *   - `write(chunk)` / `end([chunk])`
 *   - `headersSent` / `writableEnded` flags
 *
 * Implementation: a `PassThrough` carries the body. The first
 * head-committing call (`writeHead`, `flushHeaders`, `write`, or `end`)
 * resolves the `response` promise with `new Response(passthrough, …)`.
 */
export function createAdaptedResponse(): AdaptedResponse {
  const passthrough = new PassThrough()
  const headers = new Headers()
  // `statusMessage` defaults follow Node's behaviour ("OK" for 200, etc.)
  // but we don't bother with the lookup table — the body is what matters.
  const state = {
    statusCode: 200,
    statusMessage: "",
    headersSent: false,
    writableEnded: false,
  }
  let resolveResponse!: (value: Response) => void
  let rejectResponse!: (reason: unknown) => void
  const response = new Promise<Response>((resolve, reject) => {
    resolveResponse = resolve
    rejectResponse = reject
  })

  passthrough.on("error", (err) => {
    // If headers never went out, propagate to the awaiter; once committed
    // there's no way to surface the failure except via the body stream.
    if (!state.headersSent) rejectResponse(err)
  })

  const commit = (): void => {
    if (state.headersSent) return
    state.headersSent = true
    // `Readable.toWeb` returns the Web `ReadableStream` side of the
    // PassThrough, which Hono will ship as the body of `c.res`. The
    // cast through `unknown` is because `@types/node` exposes
    // `Readable.toWeb` as returning Node's `ReadableStream<unknown>`
    // while the `Response` constructor wants the global Web stream
    // type — they're identical at runtime.
    const webStream = Readable.toWeb(passthrough) as unknown as ReadableStream<Uint8Array>
    const init: ResponseInit =
      state.statusMessage === ""
        ? { status: state.statusCode, headers }
        : { status: state.statusCode, statusText: state.statusMessage, headers }
    resolveResponse(new Response(webStream, init))
  }

  const applyHeaders = (input: OutgoingHttpHeaders | OutgoingHttpHeader[] | undefined): void => {
    if (input === undefined) return
    if (Array.isArray(input)) {
      // Array form is [name1, value1, name2, value2, ...] OR a list of
      // 2-element pairs. Node accepts both; we handle the flat form
      // because that's what the v0.1 handlers and the MCP SDK use.
      for (let i = 0; i + 1 < input.length; i += 2) {
        const k = input[i]
        const v = input[i + 1]
        if (typeof k === "string" && v !== undefined) {
          headers.append(k, String(v))
        }
      }
      return
    }
    for (const [name, value] of Object.entries(input)) {
      if (value === undefined) continue
      if (Array.isArray(value)) {
        for (const v of value) headers.append(name, String(v))
      } else {
        headers.set(name, String(value))
      }
    }
  }

  // Build the response object. We deliberately keep this an explicit
  // object literal rather than extending PassThrough so the public
  // surface matches `ServerResponse` exactly. Properties we don't model
  // are ones the v0.1 handlers and the MCP transport do not touch.
  const res = {
    get statusCode() {
      return state.statusCode
    },
    set statusCode(v: number) {
      state.statusCode = v
    },
    get statusMessage() {
      return state.statusMessage
    },
    set statusMessage(v: string) {
      state.statusMessage = v
    },
    get headersSent() {
      return state.headersSent
    },
    get writableEnded() {
      return state.writableEnded
    },
    setHeader(name: string, value: number | string | readonly string[]): ServerResponse {
      if (Array.isArray(value)) {
        headers.delete(name)
        for (const v of value) headers.append(name, String(v))
      } else {
        headers.set(name, String(value))
      }
      return res as unknown as ServerResponse
    },
    getHeader(name: string): number | string | string[] | undefined {
      const values = headers.getSetCookie?.()
      if (name.toLowerCase() === "set-cookie" && values && values.length > 0) {
        return values
      }
      const raw = headers.get(name)
      return raw === null ? undefined : raw
    },
    getHeaders(): OutgoingHttpHeaders {
      const out: OutgoingHttpHeaders = {}
      headers.forEach((value, key) => {
        out[key] = value
      })
      return out
    },
    getHeaderNames(): string[] {
      return [...headers.keys()]
    },
    hasHeader(name: string): boolean {
      return headers.has(name)
    },
    removeHeader(name: string): void {
      headers.delete(name)
    },
    writeHead(
      statusCode: number,
      statusOrHeaders?: string | OutgoingHttpHeaders | OutgoingHttpHeader[],
      maybeHeaders?: OutgoingHttpHeaders | OutgoingHttpHeader[],
    ): ServerResponse {
      state.statusCode = statusCode
      if (typeof statusOrHeaders === "string") {
        state.statusMessage = statusOrHeaders
        applyHeaders(maybeHeaders)
      } else {
        applyHeaders(statusOrHeaders)
      }
      commit()
      return res as unknown as ServerResponse
    },
    flushHeaders(): void {
      commit()
    },
    write(
      chunk: string | Uint8Array,
      encodingOrCallback?: BufferEncoding | ((err?: Error | null) => void),
      callback?: (err?: Error | null) => void,
    ): boolean {
      commit()
      // Normalise the two overloads. PassThrough accepts both.
      if (typeof encodingOrCallback === "function") {
        return passthrough.write(chunk, encodingOrCallback)
      }
      if (encodingOrCallback === undefined) {
        return callback === undefined
          ? passthrough.write(chunk)
          : passthrough.write(chunk, callback)
      }
      return callback === undefined
        ? passthrough.write(chunk, encodingOrCallback)
        : passthrough.write(chunk, encodingOrCallback, callback)
    },
    end(
      chunkOrCallback?: string | Uint8Array | (() => void),
      encodingOrCallback?: BufferEncoding | (() => void),
      callback?: () => void,
    ): ServerResponse {
      commit()
      state.writableEnded = true
      if (typeof chunkOrCallback === "function") {
        passthrough.end(chunkOrCallback)
      } else if (chunkOrCallback === undefined) {
        passthrough.end()
      } else if (typeof encodingOrCallback === "function") {
        passthrough.end(chunkOrCallback, encodingOrCallback)
      } else if (encodingOrCallback === undefined) {
        passthrough.end(chunkOrCallback)
      } else if (callback === undefined) {
        passthrough.end(chunkOrCallback, encodingOrCallback)
      } else {
        passthrough.end(chunkOrCallback, encodingOrCallback, callback)
      }
      return res as unknown as ServerResponse
    },
    // The MCP SDK transport listens for `close` on the response so it can
    // tear down its SSE stream when the client disconnects. We forward
    // PassThrough's close event so that contract holds.
    on(event: string, listener: (...args: unknown[]) => void): ServerResponse {
      passthrough.on(event, listener)
      return res as unknown as ServerResponse
    },
    once(event: string, listener: (...args: unknown[]) => void): ServerResponse {
      passthrough.once(event, listener)
      return res as unknown as ServerResponse
    },
    off(event: string, listener: (...args: unknown[]) => void): ServerResponse {
      passthrough.off(event, listener)
      return res as unknown as ServerResponse
    },
    addListener(event: string, listener: (...args: unknown[]) => void): ServerResponse {
      passthrough.addListener(event, listener)
      return res as unknown as ServerResponse
    },
    removeListener(event: string, listener: (...args: unknown[]) => void): ServerResponse {
      passthrough.removeListener(event, listener)
      return res as unknown as ServerResponse
    },
    emit(event: string, ...args: unknown[]): boolean {
      return passthrough.emit(event, ...args)
    },
  }

  return { res: res as unknown as ServerResponse, response }
}
