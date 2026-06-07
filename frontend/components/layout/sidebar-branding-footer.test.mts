import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")

describe("Sidebar branding section", () => {
  it("contains Raven Protocol eyebrow label", () => {
    assert.ok(src.includes("Raven Protocol"), "should have Raven Protocol eyebrow")
  })
  it("contains Blu3Raven product name", () => {
    assert.ok(src.includes("Blu3Raven"), "should have Blu3Raven product name")
  })
  it("contains Aegis product name in subtitle", () => {
    assert.ok(src.includes("Aegis — Vulnerability Management Portal"), "should have Aegis subtitle")
  })
  it("uses Space Grotesk font variable", () => {
    assert.ok(src.includes("--font-space-grotesk"), "should reference Space Grotesk font variable")
  })
  it("does not use the old fixed-height h-32 branding container", () => {
    assert.ok(!src.includes("h-32"), "old h-32 container should be gone")
  })
  it("does not contain old AI Security Community subtitle", () => {
    assert.ok(!src.includes("AI Security Community"), "old subtitle should be removed")
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
