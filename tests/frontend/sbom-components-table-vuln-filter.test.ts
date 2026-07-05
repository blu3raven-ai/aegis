import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

// The per-repo components table can hold thousands of rows; the "Vulnerable
// only" filter is the analyst's fastest path to the components that carry risk.
// These source assertions guard the wiring against accidental removal.
const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/components/shared/sbom/SbomComponentsTable.tsx"),
  "utf8",
)

describe("SbomComponentsTable — vulnerable-only filter", () => {
  it("holds the filter in its own state", () => {
    assert.match(src, /const \[vulnFilter, setVulnFilter\] = useState\("all"\)/)
  })

  it("only enables the filter once the vuln overlay has loaded", () => {
    assert.match(src, /const vulnFilterReady = !vulnsLoading && vulns !== undefined/)
    assert.match(src, /disabled=\{!vulnFilterReady\}/)
  })

  it("filters rows by whether the component carries any advisory", () => {
    assert.match(
      src,
      /vulnFilter === "all" \|\| \(componentVulnsFor\(vulns, c\.name, c\.version\)\?\.total \?\? 0\) > 0/,
    )
  })

  it("includes vulnFilter and vulns in the filter memo dependencies", () => {
    assert.match(src, /vulnFilter, vulns, directness\]/)
  })

  it("resets pagination when the filter changes", () => {
    assert.match(src, /function handleVuln\(val: string\) \{\s*setVulnFilter\(val\)\s*setPage\(1\)/)
  })

  it("offers the All / Vulnerable only options", () => {
    assert.match(src, /<option value="vulnerable">Vulnerable only<\/option>/)
  })

  it("treats the vuln filter as filter-active in the empty state", () => {
    assert.match(src, /vulnFilter !== "all"\s*\n?\s*\? "No components match the current filters\."/)
  })
})
