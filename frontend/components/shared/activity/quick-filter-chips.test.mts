import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./QuickFilterChips.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("QuickFilterChips + FilterOverflow", () => {
  it("is a client component", () => {
    assert.ok(src.startsWith('"use client"'))
  })

  it("exports both QuickFilterChips and FilterOverflow", () => {
    assert.match(src, /export\s+function\s+QuickFilterChips/)
    assert.match(src, /export\s+function\s+FilterOverflow/)
  })

  it("imports CHIP_GROUPS, eventTypeLabel, and ActivityFilterChip from shared activity modules", () => {
    assert.match(src, /from\s+"\.\/event-labels"/)
    assert.match(src, /from\s+"\.\/ActivityFilterChip"/)
    assert.match(src, /CHIP_GROUPS/)
    assert.match(src, /eventTypeLabel/)
  })

  it("imports DayStats from lib/shared", () => {
    assert.match(src, /from\s+"@\/lib\/shared\/activity-derivations"/)
  })

  it("QuickFilterChips takes stats, activeChip, onSelect, overflow props", () => {
    assert.match(src, /stats:\s*DayStats\s*\|\s*null/)
    assert.match(src, /activeChip:\s*string\s*\|\s*null/)
    assert.match(src, /onSelect:\s*\(chipId:\s*string,\s*types:\s*string\[\]\)\s*=>\s*void/)
    assert.match(src, /overflow:\s*ReactNode/)
  })

  it("FilterOverflow takes activeTypes, onToggle, onClear, open, onOpenChange props", () => {
    assert.match(src, /activeTypes:\s*string\[\]/)
    assert.match(src, /onToggle:\s*\(type:\s*string\)\s*=>\s*void/)
    assert.match(src, /onClear:\s*\(\)\s*=>\s*void/)
    assert.match(src, /open:\s*boolean/)
    assert.match(src, /onOpenChange:\s*\(v:\s*boolean\)\s*=>\s*void/)
  })

  it("FilterOverflow groups dropdown items into Findings/Scans/Intel/Integrations", () => {
    for (const label of ["Findings", "Scans", "Intel", "Integrations"]) {
      assert.ok(src.includes(`label: "${label}"`), `FILTER_GROUPS missing ${label}`)
    }
  })

  it("dismisses overflow on outside click via mousedown", () => {
    assert.ok(src.includes("mousedown"), "outside-click dismiss wired")
  })
})
