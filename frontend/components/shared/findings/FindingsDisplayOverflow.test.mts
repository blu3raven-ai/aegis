import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingsDisplayOverflow.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingsDisplayOverflow", () => {
  it("exports a GroupKey union covering scanner / severity / repo / status", () => {
    assert.match(src, /type GroupKey = "scanner" \| "severity" \| "repo" \| "status"/)
  })

  it("exposes GROUP_BY_OPTIONS with Tool / Severity / Repo / Status", () => {
    assert.match(src, /label:\s*"Tool",\s*value:\s*"scanner"/)
    assert.match(src, /label:\s*"Severity",\s*value:\s*"severity"/)
    assert.match(src, /label:\s*"Repo",\s*value:\s*"repo"/)
    assert.match(src, /label:\s*"Status",\s*value:\s*"status"/)
  })

  it("delegates Sort options to FindingsSortDropdown's SORT_OPTIONS export", () => {
    assert.match(src, /import \{ SORT_OPTIONS, type SortKey \}/)
  })

  it("delegates Age options to FindingsAgeFilter's AGE_OPTIONS export", () => {
    assert.match(src, /import \{ AGE_OPTIONS, type AgePresetKey \}/)
  })

  it("closes the popover on outside click and Escape", () => {
    assert.match(src, /addEventListener\("mousedown"/)
    assert.match(src, /e\.key === "Escape"/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
