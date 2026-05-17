import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/HeaderCTAs.tsx"), "utf8")

describe("HeaderCTAs", () => {
  it("contains Community label", () => {
    assert.ok(src.includes("Community"), "should contain Community label")
  })
  it("contains GitHub label", () => {
    assert.ok(src.includes("GitHub"), "should contain GitHub label")
  })
  it("contains Docs label", () => {
    assert.ok(src.includes("Docs"), "should contain Docs label")
  })
  it("all 3 links point to blu3raven.ai", () => {
    const matches = src.match(/https:\/\/blu3raven\.ai\//g)
    assert.ok(matches !== null && matches.length >= 3, "all 3 links should point to blu3raven.ai")
  })
  it("uses noopener noreferrer on external links", () => {
    assert.ok(src.includes("noopener noreferrer"), "should use noopener noreferrer")
  })
  it("opens links in new tab", () => {
    assert.ok(src.includes("_blank"), "should open links in new tab")
  })
})
