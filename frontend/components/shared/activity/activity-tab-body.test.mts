import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ActivityTabBody.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ActivityTabBody", () => {
  it("is a client component", () => {
    assert.ok(src.startsWith('"use client"'), "should start with \"use client\"")
  })

  it("exports ActivityTabBody", () => {
    assert.match(src, /export\s+function\s+ActivityTabBody/)
  })

  it("takes onNavigate prop used to close the drawer", () => {
    assert.match(src, /onNavigate:\s*\(\)\s*=>\s*void/)
  })

  it("composes the shared CatchUpBanner, QuickFilterChips, FilterOverflow, ActivityFeed", () => {
    assert.match(src, /from\s+"\.\/CatchUpBanner"/)
    assert.match(src, /from\s+"\.\/QuickFilterChips"/)
    assert.match(src, /from\s+"\.\/ActivityFeed"/)
    assert.ok(src.includes("<CatchUpBanner"), "renders <CatchUpBanner>")
    assert.ok(src.includes("<QuickFilterChips"), "renders <QuickFilterChips>")
    assert.ok(src.includes("<FilterOverflow"), "renders <FilterOverflow>")
    assert.ok(src.includes("<ActivityFeed"), "renders <ActivityFeed>")
  })

  it("uses listActivity for both stats and feed", () => {
    assert.match(src, /from\s+"@\/lib\/client\/activity-api"/)
    assert.ok(src.includes("listActivity"), "calls listActivity")
  })

  it("reads + writes localStorage activity:last-seen and activity:catchup-dismissed", () => {
    assert.ok(src.includes('"activity:last-seen"'), "tracks last-seen")
    assert.ok(src.includes("activity:catchup-dismissed"), "tracks dismissed-today flag")
  })

  it("renders 'View all activity' link to /activity that calls onNavigate", () => {
    assert.ok(src.includes("View all activity"), "footer link copy preserved")
    assert.ok(src.includes('href="/activity"'), "footer links to /activity")
  })

  it("passes hasMore + onLoadMore to ActivityFeed for load-older", () => {
    assert.ok(src.includes("hasMore"), "wires hasMore")
    assert.ok(src.includes("onLoadMore"), "wires onLoadMore")
  })

  it("renders an error banner when fetch fails", () => {
    assert.ok(src.includes("Failed to load activity"), "error banner copy preserved")
  })
})
