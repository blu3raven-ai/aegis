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

  it("renders the unfiltered EmptySourcesState inside a colSpan=7 row", () => {
    assert.match(listSrc, /colSpan=\{7\}/)
    assert.match(listSrc, /<EmptySourcesState\s+filtered=\{false\}\s*\/>/)
  })

  it("renders the filtered EmptySourcesState variant", () => {
    assert.match(listSrc, /<EmptySourcesState\s+filtered=\{true\}\s*\/>/)
  })

  it("drops the onAddSource prop from the component", () => {
    assert.doesNotMatch(listSrc, /onAddSource/)
  })

  it("does not embed competitor or vendor names in source comments", () => {
    assert.doesNotMatch(listSrc, /\/\/.*\b(?:snyk|github advanced security|sonarqube|veracode)\b/i)
  })
})

describe("sources page — call site cleanup", () => {
  it("does not pass onAddSource to SourcesList", () => {
    assert.doesNotMatch(pageSrc, /onAddSource/)
  })
})
