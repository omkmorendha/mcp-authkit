/**
 * Tests for the signed-handshake stdio transport (v0.2 §11).
 */
import { PassThrough } from "node:stream"
import { describe, expect, it, vi } from "vitest"
import type { AuditEvent } from "../types.js"
import { encodeFrame, HEADER_BYTES, TAG_BYTES } from "./frame.js"
import { createSignedStdioTransport } from "./transport.js"

function makeLogger() {
  return {
    warn: vi.fn(),
    debug: vi.fn(),
    info: vi.fn(),
    error: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
    child: vi.fn(),
    level: "info",
    // biome-ignore lint/suspicious/noExplicitAny: test stub
  } as any
}

/** Wait for the next chunk to arrive on a Writable PassThrough. */
function readNextFrame(stream: PassThrough): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    let needed = -1
    const onData = (chunk: Buffer) => {
      chunks.push(chunk)
      total += chunk.length
      if (needed === -1 && total >= HEADER_BYTES) {
        const merged = Buffer.concat(chunks, total)
        const payloadLen = merged.readUInt32BE(8)
        needed = HEADER_BYTES + payloadLen + TAG_BYTES
      }
      if (needed !== -1 && total >= needed) {
        stream.off("data", onData)
        stream.off("error", reject)
        resolve(Buffer.concat(chunks, total).subarray(0, needed))
      }
    }
    stream.on("data", onData)
    stream.on("error", reject)
  })
}

const KEY = Buffer.from("k".repeat(32), "utf8")

describe("createSignedStdioTransport", () => {
  it("round-trips a valid request and response frame", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const echo = vi.fn(async (payload: Buffer) => Buffer.from(`echo:${payload.toString("utf8")}`))
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: echo,
      logger: makeLogger(),
    })

    const responsePromise = readNextFrame(output)
    input.write(encodeFrame(KEY, 0n, Buffer.from("ping")))

    const responseFrame = await responsePromise
    expect(responseFrame.readBigUInt64BE(0)).toBe(0n)
    const payloadLen = responseFrame.readUInt32BE(8)
    const payload = responseFrame.subarray(HEADER_BYTES, HEADER_BYTES + payloadLen)
    expect(payload.toString("utf8")).toBe("echo:ping")
    expect(echo).toHaveBeenCalledOnce()

    t.close()
  })

  it("tracks inbound and outbound counters independently and increments per direction", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async () => Buffer.from("ok"),
      logger: makeLogger(),
    })

    const f0 = readNextFrame(output)
    input.write(encodeFrame(KEY, 100n, Buffer.from("a")))
    const r0 = await f0
    expect(r0.readBigUInt64BE(0)).toBe(0n)

    const f1 = readNextFrame(output)
    input.write(encodeFrame(KEY, 101n, Buffer.from("b")))
    const r1 = await f1
    expect(r1.readBigUInt64BE(0)).toBe(1n)

    const f2 = readNextFrame(output)
    input.write(encodeFrame(KEY, 200n, Buffer.from("c")))
    const r2 = await f2
    expect(r2.readBigUInt64BE(0)).toBe(2n)

    t.close()
  })

  it("tears down on a tampered payload and fires oauth.reject(stdio-tamper)", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const audit = vi.fn<(e: AuditEvent) => void>()
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async () => Buffer.from("never"),
      logger: makeLogger(),
      audit,
    })

    const frame = encodeFrame(KEY, 0n, Buffer.from("hello"))
    // Flip a payload byte.
    frame[HEADER_BYTES] = (frame[HEADER_BYTES] ?? 0) ^ 0xff
    input.write(frame)

    const reason = await t.closed
    expect(reason.kind).toBe("stdio-tamper")
    expect(audit).toHaveBeenCalledOnce()
    const event = audit.mock.calls[0]?.[0]
    expect(event?.type).toBe("oauth.reject")
    expect(event?.detail.reason).toBe("stdio-tamper")
  })

  it("tears down on a replayed counter and fires oauth.reject(stdio-replay)", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const audit = vi.fn<(e: AuditEvent) => void>()
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async () => Buffer.from("ok"),
      logger: makeLogger(),
      audit,
    })

    // Consume the first frame so the inbound counter advances to expect >= 6.
    const first = readNextFrame(output)
    input.write(encodeFrame(KEY, 5n, Buffer.from("first")))
    await first
    // Replay the same counter.
    input.write(encodeFrame(KEY, 5n, Buffer.from("replay")))

    const reason = await t.closed
    expect(reason.kind).toBe("stdio-replay")
    if (reason.kind === "stdio-replay") {
      expect(reason.counter).toBe(5n)
      expect(reason.expectedMin).toBe(6n)
    }
    const rejects = audit.mock.calls.filter(
      ([e]) => e.type === "oauth.reject" && e.detail.reason === "stdio-replay",
    )
    expect(rejects.length).toBe(1)
  })

  it("does not call onRequest after tear-down", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const handler = vi.fn(async () => Buffer.from("ok"))
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: handler,
      logger: makeLogger(),
    })

    const tampered = encodeFrame(KEY, 0n, Buffer.from("x"))
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0x01
    input.write(tampered)
    await t.closed

    // Subsequent writes are ignored because input is destroyed; assert
    // the handler never ran.
    expect(handler).not.toHaveBeenCalled()
  })

  it("treats a clean input end as a non-fatal teardown (stdio-input-closed)", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async () => Buffer.from("ok"),
      logger: makeLogger(),
    })
    input.end()
    const reason = await t.closed
    expect(reason.kind).toBe("stdio-input-closed")
  })

  it("exposes the key fingerprint and never the raw key", () => {
    const logger = makeLogger()
    const secret = "super-secret-hmac-value"
    const t = createSignedStdioTransport({
      hmacKey: secret,
      input: new PassThrough(),
      output: new PassThrough(),
      onRequest: async () => null,
      logger,
    })
    expect(t.keyFingerprint).toMatch(/^[0-9a-f]{8}$/)
    expect(t.keyFingerprint).not.toContain(secret)
    t.close()
  })

  it("suppresses the response when onRequest returns null (notification)", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const writes: Buffer[] = []
    output.on("data", (c: Buffer) => writes.push(c))

    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async () => null,
      logger: makeLogger(),
    })
    input.write(encodeFrame(KEY, 0n, Buffer.from("notify")))

    // Give the pump a tick to run.
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(writes.length).toBe(0)
    t.close()
  })

  it("handles a frame split across multiple data chunks", async () => {
    const input = new PassThrough()
    const output = new PassThrough()
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async (p) => p,
      logger: makeLogger(),
    })

    const frame = encodeFrame(KEY, 0n, Buffer.from("chunked"))
    const responsePromise = readNextFrame(output)
    // Write the frame one byte at a time.
    for (const byte of frame) {
      input.write(Buffer.from([byte]))
    }
    const response = await responsePromise
    const payloadLen = response.readUInt32BE(8)
    const payload = response.subarray(HEADER_BYTES, HEADER_BYTES + payloadLen)
    expect(payload.toString("utf8")).toBe("chunked")
    t.close()
  })
})
