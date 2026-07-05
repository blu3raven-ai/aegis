import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { triageSummary } from "./triage-summary.ts"

describe("triageSummary", () => {
  it("returns null with neither verdict nor action band", () => {
    assert.equal(triageSummary({ severity: "high", kev: true }), null)
  })

  it("fuses verdict + action + KEV qualifier", () => {
    const r = triageSummary({ verdict: "needs_verify", actionBand: "attend", severity: "medium", kev: true })
    assert.equal(r?.tone, "caution")
    assert.equal(r!.text, "Needs review — attend soon, KEV-listed medium.")
  })

  it("act band reads danger with a critical severity qualifier", () => {
    const r = triageSummary({ verdict: "confirmed", actionBand: "act", severity: "critical" })
    assert.equal(r?.tone, "danger")
    assert.equal(r!.text, "Confirmed — act now, critical severity.")
  })

  it("track band reads neutral", () => {
    const r = triageSummary({ verdict: "possible", actionBand: "track", severity: "low" })
    assert.equal(r?.tone, "neutral")
    assert.equal(r!.text, "Unconfirmed — track, low severity.")
  })

  it("ruled_out is a positive, mitigation-led headline (band ignored)", () => {
    const r = triageSummary({ verdict: "ruled_out", actionBand: "act", severity: "critical", kev: true })
    assert.equal(r?.tone, "positive")
    assert.match(r!.text, /ruled out/i)
    assert.match(r!.text, /mitigation/i)
    assert.doesNotMatch(r!.text, /act now|critical/i)
  })

  it("verdict without an action band still summarises", () => {
    const r = triageSummary({ verdict: "confirmed", severity: "high" })
    assert.equal(r!.text, "Confirmed — high severity.")
  })

  it("action band without a verdict capitalises the action", () => {
    const r = triageSummary({ actionBand: "attend", severity: "medium", kev: true })
    assert.equal(r!.text, "Attend soon, KEV-listed medium.")
  })

  it("KEV leads the qualifier over the raw severity word", () => {
    const r = triageSummary({ verdict: "needs_verify", actionBand: "attend", severity: "low", kev: true })
    assert.match(r!.text, /KEV-listed low/)
    assert.doesNotMatch(r!.text, /low severity/)
  })
})
