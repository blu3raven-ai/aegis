import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { parseCvssVector, cvssBaseScore } from "./cvss.ts"

describe("parseCvssVector", () => {
  it("decodes a v3.1 network/critical vector into ordered base metrics", () => {
    const m = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    const byLabel = Object.fromEntries(m.map((x) => [x.label, x]))
    assert.equal(byLabel["Attack vector"].value, "Network")
    assert.equal(byLabel["Attack vector"].tone, "danger")
    assert.equal(byLabel["Privileges required"].value, "None")
    assert.equal(byLabel["Confidentiality"].value, "High")
    assert.equal(byLabel["Confidentiality"].tone, "danger")
    assert.equal(byLabel["Availability"].value, "None")
  })

  it("orders exploitability metrics before impact metrics", () => {
    const labels = parseCvssVector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:H").map((x) => x.label)
    assert.deepEqual(labels.slice(0, 5), [
      "Attack vector",
      "Attack complexity",
      "Privileges required",
      "User interaction",
      "Scope",
    ])
  })

  it("supports v3.0 vectors", () => {
    assert.ok(parseCvssVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L").length > 0)
  })

  it("returns [] for missing, non-v3, or malformed vectors", () => {
    assert.deepEqual(parseCvssVector(null), [])
    assert.deepEqual(parseCvssVector(undefined), [])
    assert.deepEqual(parseCvssVector(""), [])
    assert.deepEqual(parseCvssVector("AV:N/AC:L"), [])
    assert.deepEqual(parseCvssVector("CVSS:2.0/AV:N"), [])
  })

  it("skips unknown metric codes rather than throwing", () => {
    const m = parseCvssVector("CVSS:3.1/AV:X/AC:L")
    assert.equal(m.find((x) => x.label === "Attack vector"), undefined)
    assert.equal(m.find((x) => x.label === "Attack complexity")?.value, "Low")
  })
})

describe("cvssBaseScore", () => {
  // Reference vectors + scores from the FIRST.org CVSS v3.1 calculator.
  const cases: Array<[string, number, string]> = [
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"],
    ["CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "Low"],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"],
  ]
  for (const [vector, score, severity] of cases) {
    it(`scores ${vector} as ${score} ${severity}`, () => {
      const out = cvssBaseScore(vector)
      assert.equal(out?.score, score)
      assert.equal(out?.severity, severity)
    })
  }

  it("accepts v3.0 vectors", () => {
    assert.equal(cvssBaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.score, 9.8)
  })

  it("returns null for missing, non-v3, or incomplete vectors", () => {
    assert.equal(cvssBaseScore(null), null)
    assert.equal(cvssBaseScore("CVSS:2.0/AV:N"), null)
    assert.equal(cvssBaseScore("CVSS:3.1/AV:N/AC:L"), null) // missing base metrics
    assert.equal(cvssBaseScore("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), null) // bad code
  })
})
