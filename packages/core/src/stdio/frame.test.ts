/**
 * Tests for the signed-handshake frame codec (v0.2 §11).
 */
import { createHmac, randomBytes } from "node:crypto"
import { describe, expect, it } from "vitest"
import {
  COUNTER_BYTES,
  encodeFrame,
  HEADER_BYTES,
  keyFingerprint,
  LEN_BYTES,
  MAX_PAYLOAD_BYTES,
  normaliseHmacKey,
  TAG_BYTES,
  tryDecodeFrame,
} from "./frame.js"

const KEY = Buffer.from("01".repeat(32), "hex")

describe("encodeFrame / tryDecodeFrame", () => {
  it("round-trips a single frame at counter 0", () => {
    const payload = Buffer.from(JSON.stringify({ method: "ping" }))
    const frame = encodeFrame(KEY, 0n, payload)
    expect(frame.length).toBe(HEADER_BYTES + payload.length + TAG_BYTES)
    const result = tryDecodeFrame(KEY, frame, 0n)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.counter).toBe(0n)
      expect(result.payload.equals(payload)).toBe(true)
      expect(result.consumed).toBe(frame.length)
    }
  })

  it("round-trips arbitrary counters", () => {
    const payload = Buffer.from("hello")
    for (const counter of [1n, 42n, 0xffff_ffff_ffff_ffffn - 1n]) {
      const frame = encodeFrame(KEY, counter, payload)
      const decoded = tryDecodeFrame(KEY, frame, counter)
      expect(decoded.ok).toBe(true)
      if (decoded.ok) expect(decoded.counter).toBe(counter)
    }
  })

  it("returns short-header when buffer is smaller than the header", () => {
    const buf = Buffer.alloc(HEADER_BYTES - 1)
    const r = tryDecodeFrame(KEY, buf, 0n)
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error.kind).toBe("short-header")
      expect(r.consumed).toBe(0)
    }
  })

  it("returns short-payload when the buffer lacks payload + tag", () => {
    const payload = Buffer.from("x".repeat(64))
    const frame = encodeFrame(KEY, 0n, payload)
    const truncated = frame.subarray(0, frame.length - 5)
    const r = tryDecodeFrame(KEY, truncated, 0n)
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error.kind).toBe("short-payload")
      expect(r.consumed).toBe(0)
    }
  })

  it("rejects an oversized declared length", () => {
    const buf = Buffer.alloc(HEADER_BYTES + 4 + TAG_BYTES)
    buf.writeBigUInt64BE(0n, 0)
    buf.writeUInt32BE(MAX_PAYLOAD_BYTES + 1, COUNTER_BYTES)
    const r = tryDecodeFrame(KEY, buf, 0n)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.kind).toBe("payload-too-large")
  })

  it("detects a tampered payload byte (HMAC mismatch)", () => {
    const payload = Buffer.from("important")
    const frame = encodeFrame(KEY, 1n, payload)
    // Flip a bit inside the payload region.
    const tampered = Buffer.from(frame)
    tampered[HEADER_BYTES] = (tampered[HEADER_BYTES] ?? 0) ^ 0x01
    const r = tryDecodeFrame(KEY, tampered, 1n)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.kind).toBe("bad-tag")
  })

  it("detects a tampered tag", () => {
    const payload = Buffer.from("payload")
    const frame = encodeFrame(KEY, 1n, payload)
    const tampered = Buffer.from(frame)
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0x80
    const r = tryDecodeFrame(KEY, tampered, 1n)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.kind).toBe("bad-tag")
  })

  it("detects a different HMAC key (signature mismatch)", () => {
    const other = randomBytes(32)
    const payload = Buffer.from("x")
    const frame = encodeFrame(other, 0n, payload)
    const r = tryDecodeFrame(KEY, frame, 0n)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.kind).toBe("bad-tag")
  })

  it("rejects a non-increasing counter (replay)", () => {
    const payload = Buffer.from("x")
    const frame = encodeFrame(KEY, 5n, payload)
    // expectedMinCounter is 6 — counter 5 is a replay.
    const r = tryDecodeFrame(KEY, frame, 6n)
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.error.kind).toBe("non-increasing-counter")
      if (r.error.kind === "non-increasing-counter") {
        expect(r.error.counter).toBe(5n)
        expect(r.error.expectedMin).toBe(6n)
      }
    }
  })

  it("rejects an equal counter (strict >, not >=)", () => {
    const payload = Buffer.from("x")
    const frame = encodeFrame(KEY, 7n, payload)
    const r = tryDecodeFrame(KEY, frame, 8n)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.kind).toBe("non-increasing-counter")
  })

  it("encodes the documented frame layout: counter | len | payload | tag", () => {
    const payload = Buffer.from("abc")
    const frame = encodeFrame(KEY, 9n, payload)
    expect(frame.readBigUInt64BE(0)).toBe(9n)
    expect(frame.readUInt32BE(COUNTER_BYTES)).toBe(payload.length)
    expect(frame.subarray(HEADER_BYTES, HEADER_BYTES + payload.length).equals(payload)).toBe(true)
    const expectedTag = createHmac("sha256", KEY)
      .update(frame.subarray(0, COUNTER_BYTES))
      .update(payload)
      .digest()
    expect(frame.subarray(HEADER_BYTES + payload.length, frame.length).equals(expectedTag)).toBe(
      true,
    )
    expect(LEN_BYTES).toBe(4)
  })
})

describe("normaliseHmacKey", () => {
  it("returns the input buffer unchanged", () => {
    const buf = Buffer.from("k".repeat(16))
    expect(normaliseHmacKey(buf)).toBe(buf)
  })

  it("encodes a string as utf-8", () => {
    expect(normaliseHmacKey("hello").equals(Buffer.from("hello", "utf8"))).toBe(true)
  })

  it("throws on an empty key", () => {
    expect(() => normaliseHmacKey("")).toThrow(/must not be empty/)
    expect(() => normaliseHmacKey(Buffer.alloc(0))).toThrow(/must not be empty/)
  })
})

describe("keyFingerprint", () => {
  it("is the first 8 hex chars of SHA-256(key)", () => {
    const fp = keyFingerprint(Buffer.from("k", "utf8"))
    expect(fp).toMatch(/^[0-9a-f]{8}$/)
    expect(fp.length).toBe(8)
  })

  it("does not include the key in its output", () => {
    const key = Buffer.from("super-secret-key-value", "utf8")
    const fp = keyFingerprint(key)
    expect(fp).not.toContain("secret")
    expect(fp).not.toContain("super")
  })

  it("is deterministic for the same key", () => {
    const key = randomBytes(32)
    expect(keyFingerprint(key)).toBe(keyFingerprint(key))
  })
})
