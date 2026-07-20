import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")

describe("Sidebar branding section", () => {
  it("reads branding name from useBranding hook (no subtitle field)", () => {
    assert.ok(src.includes("useBranding()"), "should call useBranding() for branding values")
    assert.ok(src.includes("{brandName}"), "should render brandName from the hook")
    assert.ok(!src.includes("brandSubtitle"), "subtitle is gone — customer layout is single-line")
  })
  it("uses the mono font for branding", () => {
    assert.ok(src.includes("font-mono"), "branding should render in the mono font")
  })
  it("does not use the old fixed-height h-32 branding container", () => {
    assert.ok(!src.includes("h-32"), "old h-32 container should be gone")
  })
  it("does not contain old AI Security Community subtitle", () => {
    assert.ok(!src.includes("AI Security Community"), "old subtitle should be removed")
  })
  it("uses isVendor flag to switch between vendor and customer layouts", () => {
    assert.ok(src.includes("isVendor"), "should branch on the useBranding().isVendor flag")
  })
})

describe("Sidebar footer tier row", () => {
  it("has tier link to /settings/license", () => {
    assert.ok(src.includes('href="/settings/license"'), "should link to /settings/license")
  })
  it("tier link shows TIER_LABELS dynamically", () => {
    assert.ok(src.includes("TIER_LABELS[tier]"), "should use TIER_LABELS for dynamic tier name")
  })
})
