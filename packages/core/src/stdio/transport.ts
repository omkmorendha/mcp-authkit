/**
 * Signed-handshake stdio transport (v0.2 §11).
 *
 * Wraps a read stream and a write stream behind the frame codec in
 * `./frame.ts`. Each inbound frame's payload is handed to `onRequest`; the
 * returned payload is signed and written as the response frame.
 *
 * Tamper (HMAC mismatch) and replay (non-increasing inbound counter) are
 * both fatal: the transport closes the input stream, fires `oauth.reject`
 * with reason `stdio-replay` or `stdio-tamper`, and resolves
 * `closed`. The caller is expected to exit the process with non-zero on
 * teardown.
 *
 * @module
 */
import type { Readable, Writable } from "node:stream"
import type { Logger } from "pino"
import { type AuditSink, dispatchAudit } from "../audit/index.js"
import {
  encodeFrame,
  type FrameDecodeError,
  HEADER_BYTES,
  keyFingerprint,
  normaliseHmacKey,
  tryDecodeFrame,
} from "./frame.js"

export type StdioTeardownReason =
  | { kind: "stdio-replay"; counter: bigint; expectedMin: bigint }
  | { kind: "stdio-tamper" }
  | { kind: "stdio-payload-too-large"; declared: number }
  | { kind: "stdio-input-closed" }
  | { kind: "stdio-input-error"; message: string }
  | { kind: "stdio-handler-error"; message: string }

export interface SignedStdioTransportOptions {
  hmacKey: Buffer | string
  input: Readable
  output: Writable
  /**
   * Handle one decoded request payload. Returning a buffer queues it as the
   * next outbound frame. Returning `null` suppresses the response (e.g. for
   * notifications). Throwing tears the transport down.
   */
  onRequest: (payload: Buffer) => Promise<Buffer | null> | Buffer | null
  logger: Logger
  /** Optional audit hook; receives `oauth.reject` on tamper / replay. */
  audit?: AuditSink
}

export interface SignedStdioTransport {
  /**
   * Resolves with the teardown reason when the transport stops. Either the
   * input ended cleanly, the input emitted `error`, or a fatal frame error
   * fired. A clean end resolves to `stdio-input-closed`.
   */
  readonly closed: Promise<StdioTeardownReason>
  /** Force the transport to tear down. Idempotent. */
  close(): void
  /** Lowercase hex fingerprint of the HMAC key. Useful for tests + logs. */
  readonly keyFingerprint: string
}

/**
 * Create a signed-handshake stdio transport.
 *
 * Counters: a separate strictly-increasing counter is tracked for each
 * direction. Outbound starts at 0 and increments after every emitted frame.
 * Inbound starts with `expectedMinCounter = 0`; after a successful decode at
 * counter `N`, the expected min becomes `N + 1`.
 */
export function createSignedStdioTransport(
  options: SignedStdioTransportOptions,
): SignedStdioTransport {
  const hmacKey = normaliseHmacKey(options.hmacKey)
  const fingerprint = keyFingerprint(hmacKey)
  const { input, output, onRequest, logger, audit } = options

  let buffer = Buffer.alloc(0)
  let expectedMinCounter = 0n
  let outboundCounter = 0n
  let torn = false
  let resolveClosed!: (reason: StdioTeardownReason) => void
  const closed = new Promise<StdioTeardownReason>((res) => {
    resolveClosed = res
  })

  function tearDown(reason: StdioTeardownReason): void {
    if (torn) return
    torn = true
    try {
      // Destroy the input first so no further `data` events fire. We do not
      // touch `output` — the caller may still want a final emergency log.
      if (typeof (input as Readable).destroy === "function") {
        input.destroy()
      }
    } catch {
      // Best effort; teardown must not throw.
    }
    resolveClosed(reason)
  }

  async function emitReject(reason: string, detail: Record<string, unknown>): Promise<void> {
    if (!audit) return
    try {
      await dispatchAudit(audit, {
        type: "oauth.reject",
        at: new Date(),
        subject: null,
        tokenId: null,
        detail: { reason, ...detail },
      })
    } catch (err) {
      logger.error({ err }, "mcp-authkit stdio: audit hook threw during teardown")
    }
  }

  function handleDecodeError(error: FrameDecodeError, _consumed: number): void {
    switch (error.kind) {
      case "bad-tag": {
        logger.error(
          { fingerprint },
          "mcp-authkit stdio: HMAC tag mismatch — tearing down transport",
        )
        void emitReject("stdio-tamper", { fingerprint })
        tearDown({ kind: "stdio-tamper" })
        return
      }
      case "non-increasing-counter": {
        logger.error(
          {
            fingerprint,
            counter: error.counter.toString(),
            expectedMin: error.expectedMin.toString(),
          },
          "mcp-authkit stdio: non-increasing inbound counter — tearing down transport",
        )
        void emitReject("stdio-replay", {
          fingerprint,
          counter: error.counter.toString(),
          expectedMin: error.expectedMin.toString(),
        })
        tearDown({
          kind: "stdio-replay",
          counter: error.counter,
          expectedMin: error.expectedMin,
        })
        return
      }
      case "payload-too-large": {
        logger.error(
          { fingerprint, declared: error.declared },
          "mcp-authkit stdio: payload exceeds maximum — tearing down transport",
        )
        void emitReject("stdio-tamper", { fingerprint, declared: error.declared })
        tearDown({ kind: "stdio-payload-too-large", declared: error.declared })
        return
      }
      // short-header / short-payload are non-fatal — wait for more bytes.
      default:
        return
    }
  }

  // Process the buffer one frame at a time. Returns when there is not enough
  // data for another frame, or when teardown has fired.
  let processing = false
  async function pump(): Promise<void> {
    if (processing) return
    processing = true
    try {
      while (!torn) {
        if (buffer.length < HEADER_BYTES) return
        const result = tryDecodeFrame(hmacKey, buffer, expectedMinCounter)
        if (!result.ok) {
          if (result.error.kind === "short-header" || result.error.kind === "short-payload") {
            return
          }
          handleDecodeError(result.error, result.consumed)
          return
        }
        buffer = buffer.subarray(result.consumed)
        expectedMinCounter = result.counter + 1n
        let responsePayload: Buffer | null
        try {
          responsePayload = await onRequest(result.payload)
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err)
          logger.error(
            { fingerprint, err },
            "mcp-authkit stdio: request handler threw — tearing down transport",
          )
          tearDown({ kind: "stdio-handler-error", message })
          return
        }
        if (responsePayload !== null) {
          const frame = encodeFrame(hmacKey, outboundCounter, responsePayload)
          outboundCounter += 1n
          // Writable.write may return false; we don't gate on drain because
          // stdio framing is request/response — the next frame won't arrive
          // until the peer reads our response anyway.
          output.write(frame)
        }
      }
    } finally {
      processing = false
    }
  }

  input.on("data", (chunk: Buffer) => {
    if (torn) return
    buffer = buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([buffer, chunk])
    void pump()
  })
  input.on("end", () => {
    if (!torn) {
      tearDown({ kind: "stdio-input-closed" })
    }
  })
  input.on("error", (err: Error) => {
    if (!torn) {
      tearDown({ kind: "stdio-input-error", message: err.message })
    }
  })

  return {
    closed,
    close: () => tearDown({ kind: "stdio-input-closed" }),
    keyFingerprint: fingerprint,
  }
}
