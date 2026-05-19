/**
 * Tiny test helper: collects every {@link AuditEvent} the framework emits
 * into an in-memory array. Used by `security-matrix.test.ts` to assert
 * spec §12 ("Audit events fire for every documented case").
 *
 * Not exported from `index.ts` — this is test infrastructure, not public API.
 *
 * @module
 */
import type { AuditSink } from "../audit/index.js"
import type { AuditEvent } from "../types.js"

export interface AuditRecorder {
  readonly sink: AuditSink
  readonly events: readonly AuditEvent[]
}

export function createAuditRecorder(): AuditRecorder {
  const events: AuditEvent[] = []
  const sink: AuditSink = (event) => {
    events.push(event)
  }
  return { sink, events }
}
