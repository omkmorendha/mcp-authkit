/**
 * Audit event dispatch.
 *
 * Centralizes the call into the consumer-supplied `audit.onEvent` hook.
 * Every event site in the core (validation pipeline, scope gate, PAT
 * lifecycle) routes through {@link dispatchAudit} so the contract — await
 * the hook; propagate any thrown error to abort the triggering operation —
 * is enforced in exactly one place.
 *
 * Spec: docs/spec/v0.1.md#12-audit-callbacks
 *
 * @module
 */
import type { AuditEvent } from "../types.js"

/**
 * Consumer-supplied audit hook signature.
 *
 * The hook is awaited; throwing (or returning a rejected promise) aborts
 * the operation that fired the event (spec §12).
 */
export type AuditSink = (event: AuditEvent) => void | Promise<void>

/**
 * Fire one audit event through the optional sink.
 *
 * - When `sink` is `undefined`, this is a no-op that resolves immediately.
 * - When `sink` is defined, it is awaited and any thrown / rejected error
 *   is allowed to propagate so the caller can abort the triggering op.
 *
 * The helper does not catch, log, or transform errors — surfacing them is
 * the whole point (spec §12: "throwing from a pat.mint event causes the
 * POST to 500").
 */
export async function dispatchAudit(sink: AuditSink | undefined, event: AuditEvent): Promise<void> {
  if (!sink) return
  await sink(event)
}
