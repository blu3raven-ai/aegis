import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./RepositoriesPanel.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("RepositoriesPanel uses the shared CommandBar", () => {
  it("imports CommandBar and AttributeDef from the shared package", () => {
    assert.match(src, /import \{ CommandBar, type AttributeDef \} from "@\/components\/shared\/command-bar"/)
  })

  it("declares a filter attribute with the four legacy buckets minus 'all'", () => {
    assert.match(src, /key:\s*"filter"/)
    for (const v of ['"critical"', '"stale"', '"missing-scanners"']) {
      assert.ok(src.includes(`value: ${v}`), `REPOS_ATTRIBUTES must include ${v}`)
    }
  })

  it("translates a removed filter (null) back to 'all'", () => {
    assert.match(src, /setFilter\(\(value \?\? "all"\) as FilterMode\)/)
  })

  it("resets pagination to page 1 when filter, sort, or search changes", () => {
    const setPageOne = src.match(/setPage\(1\)/g) ?? []
    assert.ok(setPageOne.length >= 3, "setPage(1) must fire from filter, sort, and search handlers")
  })

  it("slots ReposDisplayOverflow as the page-specific overflow", () => {
    assert.match(src, /<ReposDisplayOverflow/)
  })

  it("no longer renders the legacy inline segmented filter buttons, Sort select, or FilterTag", () => {
    assert.doesNotMatch(src, /FILTER_LABELS/)
    assert.doesNotMatch(src, /SORT_LABELS/)
    assert.doesNotMatch(src, /import \{ FilterTag \}/)
    assert.doesNotMatch(src, /import \{ SearchInput \}/)
  })
})
