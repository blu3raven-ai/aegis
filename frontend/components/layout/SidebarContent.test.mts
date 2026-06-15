import { describe, it, test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./SidebarContent.tsx", import.meta.url).pathname, "utf-8")
const SRC = src

describe("SidebarContent navCounts wiring", () => {
  it("declares the navCounts prop with the inbox and findings counts", () => {
    assert.match(
      src,
      /navCounts\?:\s*\{\s*inbox\?:\s*number;\s*findings\?:\s*number\s*\}/,
    )
  })

  it("wires the Inbox nav item with danger tone", () => {
    assert.match(
      src,
      /href:\s*"\/inbox"[\s\S]*?count:\s*navCounts\?\.inbox[\s\S]*?countTone:\s*"danger"/,
    )
  })

  it("wires the Findings item with neutral tone", () => {
    for (const [href, key] of [["/findings", "findings"]] as const) {
      const pattern = new RegExp(
        `href:\\s*"${href}"[\\s\\S]*?count:\\s*navCounts\\?\\.${key}[\\s\\S]*?countTone:\\s*"neutral"`,
      )
      assert.match(src, pattern, `expected ${href} to wire navCounts.${key} with neutral tone`)
    }
  })

  it("renders a NavItemCount helper that distinguishes danger from neutral", () => {
    assert.match(src, /function\s+NavItemCount\b/)
    assert.match(src, /tone\s*===\s*"danger"/)
    assert.ok(src.includes("color-severity-critical-subtle"))
    assert.ok(src.includes("color-surface-raised"))
  })

  it("hides the count badge when the value is zero or missing", () => {
    assert.match(src, /item\.count\s*!=\s*null\s*&&\s*item\.count\s*>\s*0/)
  })
})

test("SidebarContent reads branding from useBranding hook", () => {
  assert.match(SRC, /from\s+"@\/lib\/client\/branding\/client"/)
  assert.match(SRC, /useBranding\(\)/)
})

test("SidebarContent gates vendor identity on the hook's isVendor flag", () => {
  // Vendor branch comes from useBranding().isVendor only — never from a
  // literal string comparison.
  assert.match(SRC, /isVendor/)
})

test("SidebarContent never compares name against the Blu3Raven literal", () => {
  assert.doesNotMatch(SRC, /=== "Blu3Raven"/)
  assert.doesNotMatch(SRC, /=== 'Blu3Raven'/)
})

test("SidebarContent drops the unused orgName prop", () => {
  assert.doesNotMatch(SRC, /orgName\?: string/)
})
