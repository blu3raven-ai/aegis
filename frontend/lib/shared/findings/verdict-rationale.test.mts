import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { verdictRationale } from "./verdict-rationale.ts"

describe("verdictRationale", () => {
  it("returns null for a confirmed verdict (the exploit chain speaks for itself)", () => {
    assert.equal(verdictRationale("confirmed", { model: "m", reason: "anything" }), null)
  })

  it("returns null for ruled_out (the mitigation block explains it)", () => {
    assert.equal(verdictRationale("ruled_out", { model: "m" }), null)
  })

  it("returns null when there is no metadata", () => {
    assert.equal(verdictRationale("possible", null), null)
    assert.equal(verdictRationale("needs_verify", undefined), null)
  })

  it("explains hunter_no_chain (possible) without calling it dismissed", () => {
    const r = verdictRationale("possible", { model: "m", reason: "hunter_no_chain" })
    assert.equal(r?.tone, "neutral")
    assert.match(r!.text, /couldn't trace an exploit path/i)
    assert.doesNotMatch(r!.text, /false positive|dismissed/i)
  })

  it("flags a downgraded suppression as caution and unverified", () => {
    const r = verdictRationale("needs_verify", {
      model: "m",
      suppression_downgraded: ["app/x.py:10"],
    })
    assert.equal(r?.tone, "caution")
    assert.match(r!.text, /not ruled out|couldn't confirm/i)
  })

  it("suppression_downgraded takes precedence over other keys", () => {
    const r = verdictRationale("needs_verify", {
      model: "m",
      reason: "hunter_no_chain",
      suppression_downgraded: ["a"],
      unverified_citations: ["b"],
    })
    assert.match(r!.text, /proposed a mitigation/i)
  })

  it("explains unverified_citations", () => {
    const r = verdictRationale("needs_verify", { model: "m", unverified_citations: ["a"] })
    assert.equal(r?.tone, "caution")
    assert.match(r!.text, /cited couldn't be confirmed/i)
  })

  it("explains ungrounded_no_path (deps recall-safety downgrade)", () => {
    const r = verdictRationale("needs_verify", { model: "m", ungrounded_no_path: ["no_citations"] })
    assert.equal(r?.tone, "caution")
    assert.match(r!.text, /couldn't cite proof/i)
  })

  it("explains package_not_imported as low-reachability but not dismissed", () => {
    const r = verdictRationale("needs_verify", {
      model: "m",
      reason: "package_not_imported",
      reachability: "no_path",
    })
    assert.equal(r?.tone, "neutral")
    assert.match(r!.text, /isn't imported/i)
    // Honest framing: low reachability, but explicitly NOT auto-dismissed.
    assert.match(r!.text, /not auto-dismissed/i)
  })

  it("handles schema_invalid prefixes from both SAST and deps", () => {
    const sast = verdictRationale("needs_verify", { model: "m", reason: "hunter_schema_invalid: boom" })
    const deps = verdictRationale("needs_verify", { model: "m", reason: "schema_invalid: kaboom" })
    assert.match(sast!.text, /couldn't be parsed/i)
    assert.match(deps!.text, /couldn't be parsed/i)
  })

  it("surfaces a grounded reachable path as a prioritise signal", () => {
    const r = verdictRationale("needs_verify", { model: "m", reachability: "reachable" })
    assert.equal(r?.tone, "caution")
    assert.match(r!.text, /reaching this vulnerable dependency/i)
  })

  it("surfaces a grounded no_path as likely-low exploitability", () => {
    const r = verdictRationale("needs_verify", { model: "m", reachability: "no_path" })
    assert.equal(r?.tone, "neutral")
    assert.match(r!.text, /no path/i)
  })

  it("returns null when metadata carries no explanatory signal", () => {
    assert.equal(verdictRationale("needs_verify", { model: "m", tokens_in: 100 }), null)
  })
})
