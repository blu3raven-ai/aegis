import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const listSrc = readFileSync(
  new URL("./SourcesList.tsx", import.meta.url).pathname,
  "utf-8",
)
const pageSrc = readFileSync(
  new URL("../page.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("SourcesList — empty-state skeleton", () => {
  it("imports EmptySourcesState from the shared sources directory", () => {
    assert.match(
      listSrc,
      /import\s+\{\s*EmptySourcesState\s*\}\s+from\s+"@\/components\/shared\/sources\/EmptySourcesState"/,
    )
  })

  it("no longer imports the generic EmptyState", () => {
    assert.doesNotMatch(
      listSrc,
      /import\s+\{\s*EmptyState\s*\}\s+from\s+"@\/components\/ui\/EmptyState"/,
    )
  })

  it("no longer short-circuits when sources.length === 0", () => {
    assert.doesNotMatch(listSrc, /if\s*\(\s*sources\.length\s*===\s*0\s*\)/)
  })

  it("keeps the loading skeleton branch for sources === null", () => {
    assert.match(listSrc, /if\s*\(\s*sources\s*===\s*null\s*\)\s+return\s+<TableSkeleton/)
  })

  it("spans the empty-state row across all columns via the dynamic columnCount", () => {
    assert.match(listSrc, /colSpan=\{columnCount\}/)
    assert.match(listSrc, /<EmptySourcesState\s+filtered=\{false\}\s*\/>/)
  })

  it("renders the filtered EmptySourcesState variant", () => {
    assert.match(listSrc, /<EmptySourcesState\s+filtered=\{true\}\s*\/>/)
  })

  it("drops the onAddSource prop from the component", () => {
    assert.doesNotMatch(listSrc, /onAddSource/)
  })

})

describe("sources page — call site cleanup", () => {
  it("does not pass onAddSource to SourcesList", () => {
    assert.doesNotMatch(pageSrc, /onAddSource/)
  })
})

describe("SourcesList — delete action", () => {
  it("gates the delete control on the manage_sources permission", () => {
    assert.match(listSrc, /useHasPermission\("manage_sources"\)/)
    assert.match(listSrc, /canManage &&/)
  })

  it("keeps the empty-state/skeleton column count in sync with the conditional action column", () => {
    assert.match(listSrc, /const columnCount = canManage \? 8 : 7/)
    assert.match(listSrc, /TableSkeleton rows=\{6\} columns=\{columnCount\}/)
  })

  it("feeds the trash glyph through leadingIcon so the iconOnly button isn't empty", () => {
    // iconOnly Buttons drop children; a child <svg> renders an invisible button.
    assert.match(listSrc, /leadingIcon=\{[\s\S]*?<svg[\s\S]*?<\/svg>[\s\S]*?\}/)
    assert.doesNotMatch(listSrc, /iconOnly[\s\S]{0,400}>\s*<svg/)
  })

  it("confirms via the shared danger Dialog before calling deleteSourceConnection", () => {
    assert.match(listSrc, /import\s+\{\s*deleteSourceConnection\s*\}\s+from\s+"@\/lib\/client\/source-connections-api"/)
    assert.match(listSrc, /await deleteSourceConnection\(pendingDelete\.id\)/)
    assert.match(listSrc, /variant="danger"/)
  })

  it("stops row-navigation propagation and surfaces delete errors instead of swallowing them", () => {
    assert.match(listSrc, /e\.stopPropagation\(\); setDeleteError\(null\); setPendingDelete\(s\)/)
    assert.match(listSrc, /setDeleteError\(result\.error\)/)
  })

  it("reloads the list after a delete via the page reloadKey", () => {
    assert.match(listSrc, /onDeleted\?\.\(\)/)
    assert.match(pageSrc, /onDeleted=\{\(\) => setReloadKey\(k => k \+ 1\)\}/)
  })
})
