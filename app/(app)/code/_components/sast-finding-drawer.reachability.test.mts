import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const drawerSrc = readFileSync(
  new URL("./code-scanning-finding-drawer.tsx", import.meta.url).pathname,
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
  it("always renders Reachability section heading via DrawerSection", () => {
    assert.ok(
      drawerSrc.includes("Reachability"),
      "should include Reachability label"
    )
    assert.ok(
      drawerSrc.includes("DrawerSection"),
      "should use DrawerSection for sections"
    )
  })

  it("renders call chain steps for reachable verdict", () => {
    assert.ok(
      drawerSrc.includes("reachability?.call_chain") || drawerSrc.includes("reachability.call_chain"),
      "should render call chain from reachability data"
    )
  })

  it("renders entry point label with accent color", () => {
    assert.ok(
      drawerSrc.includes("reachability?.entry_point") || drawerSrc.includes("reachability.entry_point"),
      "should show entry_point label"
    )
    assert.ok(
      drawerSrc.includes("text-[var(--color-accent)]"),
      "should use accent color token, not hardcoded color"
    )
  })

  it("renders unreachable placeholder message", () => {
    assert.ok(
      drawerSrc.includes("not reachable from any detected entry point"),
      "should show unreachable placeholder text"
    )
  })

  it("always renders a terminal sink node at the finding location", () => {
    assert.ok(
      drawerSrc.includes("finding.start_line"),
      "sink node should show the finding's exact line"
    )
    assert.ok(
      drawerSrc.includes("color-verdict-risk"),
      "sink node should use risk color tokens"
    )
  })

  it("renders module-level entry point explanation", () => {
    assert.ok(
      drawerSrc.includes("Executes at module level on import"),
      "should show module-level explanation on the entry node"
    )
  })

  it("renders unknown/absent placeholder message", () => {
    assert.ok(
      drawerSrc.includes("Reachability could not be determined"),
      "should show unknown placeholder text"
    )
  })

  it("highlights final step with background tint, not side-stripe border", () => {
    assert.ok(
      !drawerSrc.includes("border-l-2 border-orange-400"),
      "should not have orange side-stripe border"
    )
    assert.ok(
      !drawerSrc.includes("border-l-2 border-[var(--color-accent)]"),
      "should not have accent side-stripe border"
    )
  })

  it("is within the Remediation tab (Code & Reachability)", () => {
    const remediationIdx = drawerSrc.indexOf("Remediation")
    const reachabilityIdx = drawerSrc.indexOf("Reachability", remediationIdx + 1)
    assert.ok(
      remediationIdx > 0 && reachabilityIdx > remediationIdx,
      "Reachability section should appear inside the Remediation block"
    )
  })
})

describe("sast-finding-drawer color tokens", () => {
  it("verdictChipClass uses --color-verdict-safe for false positive", () => {
    assert.ok(drawerSrc.includes("color-verdict-safe"), "verdictChipClass should use verdict-safe token")
  })

  it("verdictChipClass uses --color-verdict-risk for true positive", () => {
    assert.ok(drawerSrc.includes("color-verdict-risk"), "verdictChipClass should use verdict-risk token")
  })

  it("verdictChipClass uses --color-verdict-uncertain for likely", () => {
    assert.ok(drawerSrc.includes("color-verdict-uncertain"), "verdictChipClass should use verdict-uncertain token")
  })

  it("verdictChipClass uses --color-verdict-neutral for default", () => {
    assert.ok(drawerSrc.includes("color-verdict-neutral"), "verdictChipClass should use verdict-neutral token")
  })

  it("does not use hardcoded text-emerald-400 class", () => {
    assert.ok(!drawerSrc.includes("text-emerald-400"), "should not hardcode emerald-400")
  })

  it("does not use hardcoded text-red-400 class", () => {
    assert.ok(!drawerSrc.includes("text-red-400"), "should not hardcode red-400")
  })

  it("does not use hardcoded text-amber-400 class", () => {
    assert.ok(!drawerSrc.includes("text-amber-400"), "should not hardcode amber-400")
  })

  it("uses DismissPopover instead of inline dismiss block", () => {
    assert.ok(drawerSrc.includes("DismissPopover"), "should use DismissPopover component")
  })

  it("passes label prop to FindingsDrawerShell", () => {
    assert.ok(drawerSrc.includes('label="SAST finding details"'), "should pass label to shell")
  })
})
