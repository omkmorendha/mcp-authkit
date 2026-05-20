/**
 * Signed-handshake frame codec for production stdio (v0.2 §11).
 *
 * Frame layout (all integers big-endian):
 *
 *   <counter:uint64> <payload-len:uint32> <payload:bytes> <tag:32 bytes>
 *
 * where `tag = HMAC-SHA256(hmacKey, counter_be8 || payload)`.
 *
 * The counter is strictly monotonic per direction. Inbound and outbound
 * counters are tracked independently by the transport. A non-increasing
 * inbound counter or an HMAC mismatch is a transport-level error.
 *
 * @module
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto"

export const COUNTER_BYTES = 8
export const LEN_BYTES = 4
export const TAG_BYTES = 32
export const HEADER_BYTES = COUNTER_BYTES + LEN_BYTES

/**
 * Hard cap on a single payload size. Keeps the parser honest against a
 * sender that lies about `payload-len`; consumers can adjust at the
 * transport layer but never via a frame field.
 */
export const MAX_PAYLOAD_BYTES = 16 * 1024 * 1024

export type FrameDecodeError =
  | { kind: "short-header" }
  | { kind: "payload-too-large"; declared: number }
  | { kind: "short-payload" }
  | { kind: "bad-tag" }
  | { kind: "non-increasing-counter"; counter: bigint; expectedMin: bigint }

export type FrameDecodeResult =
  | { ok: true; counter: bigint; payload: Buffer; consumed: number }
  | { ok: false; error: FrameDecodeError; consumed: number }

/**
 * Pure helper: derive the 8-hex-char fingerprint of the HMAC key.
 * Spec §11: log the fingerprint, never the key.
 */
export function keyFingerprint(hmacKey: Buffer): string {
  return createHash("sha256").update(hmacKey).digest("hex").slice(0, 8)
}

/**
 * Normalise an `hmacKey` config value to a `Buffer`. Strings are interpreted
 * as UTF-8. Throws on an empty key — the v0.2 §11 mode is opt-in and an
 * empty key is never what the caller meant.
 */
export function normaliseHmacKey(hmacKey: Buffer | string): Buffer {
  const buf = typeof hmacKey === "string" ? Buffer.from(hmacKey, "utf8") : hmacKey
  if (buf.length === 0) {
    throw new Error("mcp-authkit stdio: hmacKey must not be empty")
  }
  return buf
}

function counterToBuffer(counter: bigint): Buffer {
  const buf = Buffer.alloc(COUNTER_BYTES)
  buf.writeBigUInt64BE(counter, 0)
  return buf
}

/**
 * Encode a single outbound frame. Caller supplies the next counter value.
 */
export function encodeFrame(hmacKey: Buffer, counter: bigint, payload: Buffer): Buffer {
  if (payload.length > MAX_PAYLOAD_BYTES) {
    throw new Error(
      `mcp-authkit stdio: outbound payload ${payload.length} exceeds MAX_PAYLOAD_BYTES ${MAX_PAYLOAD_BYTES}`,
    )
  }
  const counterBuf = counterToBuffer(counter)
  const lenBuf = Buffer.alloc(LEN_BYTES)
  lenBuf.writeUInt32BE(payload.length, 0)
  const tag = createHmac("sha256", hmacKey).update(counterBuf).update(payload).digest()
  return Buffer.concat([counterBuf, lenBuf, payload, tag])
}

/**
 * Attempt to decode the next frame from `buffer`. Returns the number of
 * bytes consumed when successful; on header-only / short-payload the call
 * returns `ok: false` with `consumed: 0` so the caller can wait for more
 * input. Tampered tag, oversized declared length, and non-increasing
 * counter all return `ok: false` with the bytes-consumed value the caller
 * should use to advance past the bad frame (we still treat these as
 * fatal — the transport tears down — but the value lets a future API
 * resume past one bad frame if it ever wants to).
 */
export function tryDecodeFrame(
  hmacKey: Buffer,
  buffer: Buffer,
  expectedMinCounter: bigint,
): FrameDecodeResult {
  if (buffer.length < HEADER_BYTES) {
    return { ok: false, error: { kind: "short-header" }, consumed: 0 }
  }
  const counter = buffer.readBigUInt64BE(0)
  const declared = buffer.readUInt32BE(COUNTER_BYTES)
  if (declared > MAX_PAYLOAD_BYTES) {
    return {
      ok: false,
      error: { kind: "payload-too-large", declared },
      consumed: HEADER_BYTES,
    }
  }
  const total = HEADER_BYTES + declared + TAG_BYTES
  if (buffer.length < total) {
    return { ok: false, error: { kind: "short-payload" }, consumed: 0 }
  }

  const payload = buffer.subarray(HEADER_BYTES, HEADER_BYTES + declared)
  const tag = buffer.subarray(HEADER_BYTES + declared, total)
  const counterBuf = buffer.subarray(0, COUNTER_BYTES)
  const expected = createHmac("sha256", hmacKey).update(counterBuf).update(payload).digest()

  // Constant-time tag check (spec §14).
  if (tag.length !== expected.length || !timingSafeEqual(tag, expected)) {
    return { ok: false, error: { kind: "bad-tag" }, consumed: total }
  }

  if (counter < expectedMinCounter) {
    return {
      ok: false,
      error: { kind: "non-increasing-counter", counter, expectedMin: expectedMinCounter },
      consumed: total,
    }
  }

  // `payload` is a view over the input buffer; copy so callers cannot mutate
  // it via the original buffer.
  return { ok: true, counter, payload: Buffer.from(payload), consumed: total }
}
