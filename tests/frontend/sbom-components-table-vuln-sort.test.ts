import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

// The per-repo components table renders in raw SBOM order by default, which
// buries the worst components. The Vulnerabilities column is sortable so an
// analyst can pull the highest-severity components to the top. These assertions
// guard that wiring against accidental removal.
const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/components/shared/sbom/SbomComponentsTable.tsx"),
  "utf8",
)

describe("SbomComponentsTable — severity-sortable Vulnerabilities column", () => {
  it("reuses the shared severity comparator rather than re-rolling one", () => {
    assert.match(src, /import \{ compareSeverity \} from "@\/lib\/sbom\/diff-severity"/)
  })

  it("holds the sort toggle in its own state, off by default", () => {
    assert.match(src, /const \[vulnSort, setVulnSort\] = useState\(false\)/)
  })

  it("sorts the filtered set worst-first only when enabled", () => {
    assert.match(src, /if \(!vulnSort\) return filtered/)
    assert.match(
      src,
      /compareSeverity\(\s*componentVulnsFor\(vulns, a\.name, a\.version\),\s*componentVulnsFor\(vulns, b\.name, b\.version\),\s*\)/,
    )
  })

  it("paginates over the sorted list", () => {
    assert.match(src, /const slice = sorted\.slice\(/)
    assert.match(src, /Math\.ceil\(sorted\.length \/ PER_PAGE\)/)
  })

  it("resets pagination when the sort toggles", () => {
    assert.match(src, /function handleVulnSort\(\) \{\s*setVulnSort\(\(s\) => !s\)\s*setPage\(1\)/)
  })

  it("exposes the sort as an accessible column header gated on loaded vulns", () => {
    assert.match(src, /aria-sort=\{vulnSort \? "descending" : "none"\}/)
    assert.match(src, /onClick=\{handleVulnSort\}/)
    // Falls back to a plain header until the overlay is available.
    assert.match(src, /vulnFilterReady \? \(/)
  })
})
