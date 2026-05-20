/**
 * Production stdio (signed-handshake) transport — public entry.
 *
 * Spec: docs/spec/v0.2.md#11-production-stdio-support
 *
 * @module
 */
export { checkSignedStdioConfig, SignedStdioConfigError } from "./config.js"
export {
  encodeFrame,
  type FrameDecodeError,
  type FrameDecodeResult,
  HEADER_BYTES,
  keyFingerprint,
  MAX_PAYLOAD_BYTES,
  normaliseHmacKey,
  TAG_BYTES,
  tryDecodeFrame,
} from "./frame.js"
export {
  createSignedStdioTransport,
  type SignedStdioTransport,
  type SignedStdioTransportOptions,
  type StdioTeardownReason,
} from "./transport.js"
