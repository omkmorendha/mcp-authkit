/**
 * MessagePack encode/decode with an HMAC-SHA256 tag.
 *
 * Spec §12: "Redis values authenticated" — every cache value is tagged with
 * an HMAC over the MessagePack body, using a startup-derived key. A wrong
 * tag is treated as a miss (decoder returns `null`) and the caller logs at
 * `warn`.
 *
 * Wire format:
 *   [ 32 bytes HMAC-SHA256(body) ] [ MessagePack-encoded body ]
 *
 * MessagePack carries `Buffer` (bin type) and `Date` (timestamp extension)
 * natively, so `tokenHash`, `expiresAt`, etc. round-trip without lossy JSON
 * conversion.
 */

import { createHmac, timingSafeEqual } from "node:crypto"
import { decode as msgDecode, encode as msgEncode } from "@msgpack/msgpack"

export const HMAC_TAG_BYTES = 32

function computeTag(key: Buffer, body: Uint8Array): Buffer {
  const h = createHmac("sha256", key)
  h.update(body)
  return h.digest()
}

/**
 * Encode `value` and prepend an HMAC tag computed with `key`. Returned
 * `Buffer` is safe to write to Redis as a `bin`.
 */
export function encode(key: Buffer, value: unknown): Buffer {
  const body = msgEncode(value)
  const tag = computeTag(key, body)
  const out = Buffer.allocUnsafe(HMAC_TAG_BYTES + body.byteLength)
  tag.copy(out, 0)
  Buffer.from(body.buffer, body.byteOffset, body.byteLength).copy(out, HMAC_TAG_BYTES)
  return out
}

/**
 * Verify the HMAC tag on `blob` and decode the body. Returns `null` if the
 * blob is too short, the tag does not match, or MessagePack decode throws.
 *
 * Tag comparison is constant-time (`timingSafeEqual`), length-guarded —
 * defense in depth even though the tag is fixed-width.
 */
export function decode(key: Buffer, blob: Buffer): unknown | null {
  if (blob.length < HMAC_TAG_BYTES) return null
  const presented = blob.subarray(0, HMAC_TAG_BYTES)
  const body = blob.subarray(HMAC_TAG_BYTES)
  const expected = computeTag(key, body)
  if (presented.length !== expected.length) return null
  if (!timingSafeEqual(presented, expected)) return null
  try {
    return msgDecode(body)
  } catch {
    return null
  }
}
