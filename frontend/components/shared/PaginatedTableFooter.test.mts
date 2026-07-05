import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const footer = readFileSync(
  fileURLToPath(new URL("./PaginatedTableFooter.tsx", import.meta.url)),
  "utf-8",
)
const findings = readFileSync(
  fileURLToPath(new URL("./findings/FindingsPagination.tsx", import.meta.url)),
  "utf-8",
)

// Regression: <Button iconOnly> does NOT render its children, so an arrow passed
// as a child renders as an empty (invisible) button. Both paginators must feed
// the chevron through leadingIcon instead.
describe("pagination arrow buttons render a visible chevron", () => {
  for (const [name, src] of [
    ["PaginatedTableFooter", footer],
    ["FindingsPagination", findings],
  ] as const) {
    it(`${name} passes the chevron via leadingIcon, not children`, () => {
      assert.match(src, /leadingIcon=\{<ChevronLeftIcon/)
      assert.match(src, /leadingIcon=\{<ChevronRightIcon/)
      // No chevron left dangling as a child of an iconOnly button.
      assert.doesNotMatch(src, /<ChevronLeftIcon\s*\/>\s*<\/Button>/)
      assert.doesNotMatch(src, /<ChevronRightIcon\s*\/>\s*<\/Button>/)
    })
  }

  it("PaginatedTableFooter no longer uses bare glyph arrows", () => {
    assert.doesNotMatch(footer, /[‹›]/)
  })
})
