import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

// The repo list is a single capped page (REPO_LIMIT). When the estate exceeds
// it, a filter only searches the loaded subset — the count line must say so, or
// "3 of 200" reads as the whole estate and contradicts the full-estate KPIs.
const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(
  join(ROOT, "frontend/app/(app)/sbom/(home)/page.tsx"),
  "utf8",
)

describe("SBOM landing — repo count honesty when filtered and capped", () => {
  it("distinguishes the loaded subset from the estate in the filtered+capped branch", () => {
    // "N of M loaded · T in estate" — both the loaded page size and the estate
    // total must appear so the number can't be mistaken for the whole estate.
    assert.match(
      src,
      /\$\{sorted\.length\.toLocaleString\(\)\} of \$\{counts\.total\.toLocaleString\(\)\} loaded · \$\{totalCount!\.toLocaleString\(\)\} in estate/,
    )
  })

  it("branches on capped inside the filtered case", () => {
    assert.match(src, /isFiltered\s*\n?\s*\? capped/)
  })

  it("keeps the plain count when the whole estate is loaded (not capped)", () => {
    assert.match(
      src,
      /: `\$\{sorted\.length\.toLocaleString\(\)\} of \$\{counts\.total\.toLocaleString\(\)\} repositories`/,
    )
  })
})
