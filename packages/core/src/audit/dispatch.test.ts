import { describe, expect, it, vi } from "vitest"
import type { AuditEvent } from "../types.js"
import { dispatchAudit } from "./dispatch.js"

const EVENT: AuditEvent = {
  type: "oauth.validate",
  at: new Date("2025-01-01T00:00:00Z"),
  subject: "u1",
  tokenId: "tok-1",
  detail: { tokenType: "jwt" },
}

describe("dispatchAudit", () => {
  it("resolves to undefined when sink is undefined", async () => {
    await expect(dispatchAudit(undefined, EVENT)).resolves.toBeUndefined()
  })

  it("invokes the sink exactly once with the supplied event", async () => {
    const sink = vi.fn()
    await dispatchAudit(sink, EVENT)
    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink).toHaveBeenCalledWith(EVENT)
  })

  it("awaits async sinks before resolving", async () => {
    let resolved = false
    const sink = async () => {
      await new Promise((r) => setTimeout(r, 5))
      resolved = true
    }
    await dispatchAudit(sink, EVENT)
    expect(resolved).toBe(true)
  })

  it("propagates synchronous errors from the sink", async () => {
    const boom = new Error("audit boom")
    const sink = () => {
      throw boom
    }
    await expect(dispatchAudit(sink, EVENT)).rejects.toBe(boom)
  })

  it("propagates rejected promises from async sinks", async () => {
    const boom = new Error("async audit boom")
    const sink = async () => {
      throw boom
    }
    await expect(dispatchAudit(sink, EVENT)).rejects.toBe(boom)
  })
})
