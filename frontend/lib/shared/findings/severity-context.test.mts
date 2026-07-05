import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { severityContext } from "./severity-context.ts"

describe("severityContext", () => {
  it("returns null without an action band", () => {
    assert.equal(severityContext({ severity: "high", kev: true }), null)
  })

  it("act → urgent KEV framing (danger)", () => {
    const r = severityContext({ severity: "critical", actionBand: "act", kev: true })
    assert.equal(r?.tone, "danger")
    assert.match(r!.text, /KEV list/i)
    assert.match(r!.text, /urgent/i)
    assert.match(r!.text, /critical severity/i)
  })

  it("attend via KEV → prompt-attention framing even at low base severity", () => {
    const r = severityContext({ severity: "medium", actionBand: "attend", kev: true })
    assert.equal(r?.tone, "caution")
    assert.match(r!.text, /KEV list/i)
    assert.match(r!.text, /even at medium severity/i)
  })

  it("attend via reachable+high → exploitable-here framing, no false KEV claim", () => {
    const r = severityContext({
      severity: "high",
      actionBand: "attend",
      kev: false,
      reachability: "reachable",
    })
    assert.equal(r?.tone, "caution")
    assert.match(r!.text, /reaches the vulnerable code/i)
    assert.doesNotMatch(r!.text, /KEV/i)
  })

  it("track + no_path → explicitly lower than base severity", () => {
    const r = severityContext({ severity: "high", actionBand: "track", reachability: "no_path" })
    assert.equal(r?.tone, "neutral")
    assert.match(r!.text, /no call path/i)
    assert.match(r!.text, /lower than high severity/i)
  })

  it("track + reachable (below high) → honest 'reachable but still track'", () => {
    const r = severityContext({
      severity: "medium",
      actionBand: "track",
      reachability: "reachable",
    })
    assert.equal(r?.tone, "neutral")
    assert.match(r!.text, /reachable/i)
    assert.match(r!.text, /track-level/i)
  })

  it("track + unknown reachability → generic lower-urgency framing, no KEV claim", () => {
    const r = severityContext({ severity: "low", actionBand: "track", reachability: "unknown" })
    assert.equal(r?.tone, "neutral")
    assert.match(r!.text, /not on the kev list/i)
    assert.match(r!.text, /low severity/i)
  })

  it("never mentions EPSS (it is not a band input)", () => {
    for (const band of ["act", "attend", "track"] as const) {
      const r = severityContext({ severity: "high", actionBand: band, kev: true, reachability: "reachable" })
      assert.doesNotMatch(r!.text, /epss/i)
    }
  })

  it("falls back to 'its base severity' when severity is absent", () => {
    const r = severityContext({ actionBand: "track", reachability: "unknown" })
    assert.match(r!.text, /its base severity/i)
  })
})
