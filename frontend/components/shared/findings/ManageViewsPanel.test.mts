import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ManageViewsPanel.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ManageViewsPanel", () => {
  it("accepts open + onClose props", () => {
    assert.match(src, /open:\s*boolean/)
    assert.match(src, /onClose:\s*\(\)\s*=>\s*void/)
  })

  it("calls listSavedViews on open / refresh", () => {
    assert.match(src, /listSavedViews\("findings"\)/)
  })

  it("offers Rename, Delete, Set as default actions", () => {
    assert.match(src, /Rename/)
    assert.match(src, /Delete/)
    assert.match(src, /Set as default/)
  })

  it("confirms before delete", () => {
    assert.match(src, /window\.confirm\(/)
  })

  it("invokes deleteSavedView and setSavedViewDefault from the API client", () => {
    assert.match(src, /deleteSavedView\(/)
    assert.match(src, /setSavedViewDefault\(/)
  })

  it("invokes updateSavedView with the new name on Rename submit", () => {
    assert.match(src, /updateSavedView\([\s\S]*name:/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
