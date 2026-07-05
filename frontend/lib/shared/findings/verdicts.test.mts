import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { parseVerdictFilter, VALID_VERDICT_FILTERS } from "./verdicts.ts"

describe("parseVerdictFilter", () => {
  it("accepts every valid verdict token", () => {
    for (const v of ["confirmed", "needs_verify", "possible", "ruled_out", "legacy", "all"]) {
      assert.equal(parseVerdictFilter(v), v)
    }
  })

  it("round-trips the ruled_out audit-view token", () => {
    assert.equal(parseVerdictFilter("ruled_out"), "ruled_out")
  })

  it("treats absent / null / empty as the default (null)", () => {
    assert.equal(parseVerdictFilter(null), null)
    assert.equal(parseVerdictFilter(undefined), null)
    assert.equal(parseVerdictFilter(""), null)
  })

  it("rejects unknown / hand-edited tokens rather than trusting them", () => {
    assert.equal(parseVerdictFilter("bogus"), null)
    assert.equal(parseVerdictFilter("RULED_OUT"), null)
    assert.equal(parseVerdictFilter("confirmed; drop table"), null)
  })

  it("VALID_VERDICT_FILTERS mirrors the backend taxonomy", () => {
    assert.deepEqual(
      [...VALID_VERDICT_FILTERS].sort(),
      ["all", "confirmed", "legacy", "needs_verify", "possible", "ruled_out"],
    )
  })
})
