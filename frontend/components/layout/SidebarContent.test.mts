import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./SidebarContent.tsx", import.meta.url).pathname, "utf-8")

describe("SidebarContent navCounts wiring", () => {
  it("declares the navCounts prop with the four mock counts", () => {
    assert.match(
      src,
      /navCounts\?:\s*\{\s*inbox\?:\s*number;\s*findings\?:\s*number;\s*repos\?:\s*number;\s*images\?:\s*number\s*\}/,
    )
  })

  it("wires the Inbox nav item with danger tone", () => {
    assert.match(
      src,
      /href:\s*"\/inbox"[\s\S]*?count:\s*navCounts\?\.inbox[\s\S]*?countTone:\s*"danger"/,
    )
  })

  it("wires the Repositories, Images, and Findings items with neutral tone", () => {
    for (const [href, key] of [["/repos", "repos"], ["/images", "images"], ["/findings", "findings"]] as const) {
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
