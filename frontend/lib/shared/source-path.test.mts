import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { sourceIdFromPathname } from "./source-path.ts"

describe("sourceIdFromPathname", () => {
  it("extracts the id from the overview route", () => {
    assert.equal(sourceIdFromPathname("/sources/src_abc123"), "src_abc123")
  })

  it("extracts the id from a sub-tab route", () => {
    assert.equal(sourceIdFromPathname("/sources/src_abc123/findings"), "src_abc123")
    assert.equal(sourceIdFromPathname("/sources/src_abc123/ci-integration"), "src_abc123")
  })

  it("treats the static-export stub id as empty", () => {
    // Guards the core bug: on a hard load the served shell bakes id="_",
    // which must not be used as a real connection id (would 404).
    assert.equal(sourceIdFromPathname("/sources/_"), "")
    assert.equal(sourceIdFromPathname("/sources/_/settings"), "")
  })

  it("returns empty for non-source paths", () => {
    assert.equal(sourceIdFromPathname("/"), "")
    assert.equal(sourceIdFromPathname("/sources"), "")
    assert.equal(sourceIdFromPathname("/findings/abc"), "")
  })

  it("ignores trailing slashes", () => {
    assert.equal(sourceIdFromPathname("/sources/src_abc123/"), "src_abc123")
  })
})
