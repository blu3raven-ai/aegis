import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const drawerSrc = readFileSync(
  new URL("./sast-finding-drawer.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("sast-finding-drawer reachability badge", () => {
  it("defines reachabilityBadgeConfig helper", () => {
    assert.ok(
      drawerSrc.includes("reachabilityBadgeConfig"),
      "should define reachabilityBadgeConfig"
    )
  })

  it("renders badge only when reachability is present", () => {
    assert.ok(
      drawerSrc.includes("finding.reachability &&"),
      "badge should be conditional on finding.reachability"
    )
  })

  it("uses aria-label on badge", () => {
    assert.ok(
      drawerSrc.includes("aria-label"),
      "badge should have aria-label"
    )
  })

  it("uses title tooltip on badge", () => {
    assert.ok(
      drawerSrc.includes('cfg.title'),
      "badge should use title tooltip from config"
    )
  })

  it("includes Zap icon SVG path for reachable", () => {
    assert.ok(
      drawerSrc.includes("M13 2 3 14h9l-1 8 10-12h-9l1-8z"),
      "should include Zap SVG path"
    )
  })

  it("includes CircleSlash icon SVG for unreachable", () => {
    assert.ok(
      drawerSrc.includes("circle-slash") || drawerSrc.includes("4.93"),
      "should include CircleSlash SVG"
    )
  })
})

describe("sast-finding-drawer Reachability section", () => {
  it("always renders Reachability section heading", () => {
    assert.ok(
      drawerSrc.includes("Reachability") &&
      drawerSrc.includes("uppercase tracking-[0.18em]"),
      "should always render section label with correct typography"
    )
  })

  it("renders call chain steps for reachable verdict", () => {
    assert.ok(
      drawerSrc.includes("reachability.call_chain"),
      "should render call chain from reachability data"
    )
  })

  it("renders entry point as step 0 with orange accent", () => {
    assert.ok(
      drawerSrc.includes("reachability.entry_point") &&
      drawerSrc.includes("text-orange-400"),
      "should show entry_point label in orange"
    )
  })

  it("renders unreachable placeholder message", () => {
    assert.ok(
      drawerSrc.includes("not reachable from any detected entry point"),
      "should show unreachable placeholder text"
    )
  })

  it("renders unknown/absent placeholder message", () => {
    assert.ok(
      drawerSrc.includes("Reachability could not be determined"),
      "should show unknown placeholder text"
    )
  })

  it("uses orange left-border on final step", () => {
    assert.ok(
      drawerSrc.includes("border-l-2 border-orange-400"),
      "final step should have orange left-border accent"
    )
  })

  it("is positioned after Data Flow section (section 3)", () => {
    const dataFlowIdx = drawerSrc.indexOf("Data Flow")
    const reachabilityIdx = drawerSrc.indexOf("── 4. Reachability")
    assert.ok(
      dataFlowIdx > 0 && reachabilityIdx > dataFlowIdx,
      "Reachability section should appear after Data Flow"
    )
  })
})
