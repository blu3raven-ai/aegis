import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./CatchUpBanner.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("CatchUpBanner", () => {
  it("is a client component", () => {
    assert.ok(src.startsWith('"use client"'), "should start with \"use client\"")
  })

  it("exports CatchUpBanner with data + onDismiss props", () => {
    assert.match(src, /export\s+function\s+CatchUpBanner/)
    assert.match(src, /data:\s*CatchUpData/)
    assert.match(src, /onDismiss:\s*\(\)\s*=>\s*void/)
  })

  it("imports CatchUpData and relativeTime from shared modules", () => {
    assert.match(src, /from\s+"@\/lib\/shared\/activity-derivations"/)
    assert.match(src, /from\s+"@\/lib\/shared\/relative-time"/)
  })

  it("renders 'You've been away since' headline", () => {
    assert.ok(src.includes("You&apos;ve been away since"), "headline copy preserved")
  })

  it("uses an accent wash background + accent icon square", () => {
    assert.ok(src.includes("color-mix(in_srgb,var(--color-accent)"), "should render an accent wash background")
    assert.ok(src.includes("bg-[var(--color-accent)]"), "icon square uses accent")
  })

  it("renders a dismiss button with the close icon", () => {
    assert.ok(src.includes("aria-label=\"Dismiss catch-up banner\""), "dismiss button has aria-label")
    assert.ok(src.includes("M18 6 6 18M6 6l12 12"), "renders × svg path")
  })
})
