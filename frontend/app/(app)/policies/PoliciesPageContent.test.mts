import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./PoliciesPageContent.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("PoliciesPageContent imports", () => {
  it("imports listKillSwitches from rules-api", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\blistKillSwitches\b[^}]*\}\s*from\s*["']@\/lib\/client\/rules-api["']/,
      "should import listKillSwitches from rules-api",
    )
  })

  it("imports disengageKillSwitch from rules-api", () => {
    assert.match(
      src,
      /import\s*\{[^}]*\bdisengageKillSwitch\b[^}]*\}\s*from\s*["']@\/lib\/client\/rules-api["']/,
      "should import disengageKillSwitch from rules-api",
    )
  })
})

describe("PoliciesPageContent permissions", () => {
  it("derives canManageAutoDismiss from manage_auto_dismiss_rules permission", () => {
    assert.ok(
      src.includes('can(user.role as any, "manage_auto_dismiss_rules")') ||
        src.includes("manage_auto_dismiss_rules"),
      'should check "manage_auto_dismiss_rules" permission',
    )
  })
})

describe("PoliciesPageContent kill switch banner", () => {
  it("derives autoDismissKillSwitch from killSwitches state", () => {
    assert.ok(
      src.includes('autoDismissKillSwitch'),
      "should derive autoDismissKillSwitch from killSwitches",
    )
    assert.ok(
      src.includes('k.category === "auto_dismiss"'),
      "should filter kill switches by auto_dismiss category",
    )
  })

  it("renders the banner conditionally based on autoDismissKillSwitch", () => {
    assert.match(
      src,
      /\{autoDismissKillSwitch[\s\S]*?Auto-dismiss is killed/,
      "should conditionally render the kill switch banner",
    )
  })

  it("renders the Re-enable button inside the banner", () => {
    assert.ok(src.includes("Re-enable"), "should have a Re-enable button")
  })

  it("calls disengageKillSwitch from the Re-enable button handler", () => {
    assert.ok(
      src.includes("disengageKillSwitch"),
      "should call disengageKillSwitch to re-enable auto-dismiss",
    )
  })
})

describe("PoliciesPageContent auto-dismiss section activation", () => {
  it("renders the auto_dismiss RuleCategorySection without a disabled prop", () => {
    // The section must be active (not disabled). Check that the auto_dismiss
    // section block does not pass disabled=true.
    const autoDismissSection = src.slice(
      src.indexOf('category="auto_dismiss"'),
    )
    assert.ok(
      !autoDismissSection.startsWith("disabled"),
      "auto_dismiss section must not have disabled prop immediately",
    )
    // Verify the keyword disabled does not appear immediately adjacent to the
    // auto_dismiss section (within 200 chars, before the next category).
    const sectionStart = src.indexOf('category="auto_dismiss"')
    const nextSection = src.indexOf("category=", sectionStart + 10)
    const sectionBody = src.slice(sectionStart, nextSection > 0 ? nextSection : sectionStart + 400)
    assert.ok(
      !sectionBody.includes("\n            disabled"),
      "auto_dismiss RuleCategorySection must not carry a disabled prop",
    )
  })
})

describe("PoliciesPageContent Kill auto-dismiss button", () => {
  it("renders the Kill auto-dismiss button", () => {
    assert.ok(
      src.includes("Kill auto-dismiss"),
      'should render the "Kill auto-dismiss" button',
    )
  })

  it("gates the Kill auto-dismiss button on canManageAutoDismiss and no active kill switch", () => {
    assert.match(
      src,
      /canManageAutoDismiss[\s\S]*?!autoDismissKillSwitch|!autoDismissKillSwitch[\s\S]*?canManageAutoDismiss/,
      "should only show Kill button when no kill switch is active and canManage is true",
    )
  })
})

describe("PoliciesPageContent data retention activation", () => {
  it("imports useHasPermission from the permission hook", () => {
    assert.match(
      src,
      /import\s*\{\s*useHasPermission\s*\}\s*from\s*["']@\/lib\/client\/use-permission["']/,
      "should import useHasPermission for permission-based gating",
    )
  })

  it("checks the manage_data_retention_rules permission", () => {
    assert.match(
      src,
      /useHasPermission\("manage_data_retention_rules"\)/,
      "should gate on manage_data_retention_rules",
    )
  })

  it("tracks data retention rules in state", () => {
    assert.match(
      src,
      /const \[dataRetentionRules, setDataRetentionRules\] = useState<RuleSummary\[\] \| null>\(null\)/,
      "should hold dataRetentionRules state",
    )
  })

  it("loads data retention rules on mount via Promise.all", () => {
    assert.match(
      src,
      /listRules\(\{ category: "data_retention" \}\)/,
      "should fetch data_retention rules",
    )
  })

  it("preserves data retention rules on transient reload failures", () => {
    assert.match(
      src,
      /setDataRetentionRules\(\(prev\) => prev \?\? \[\]\)/,
      "should fall back to existing state on reload errors",
    )
  })

  it("dispatches handleCreate for data_retention category", () => {
    assert.match(
      src,
      /category !== "sla"\s*&&[\s\S]*category !== "scanner_coverage"\s*&&[\s\S]*category !== "data_retention"/,
      "handleCreate should accept data_retention",
    )
  })

  it("dispatches handleEdit for data_retention category", () => {
    assert.match(
      src,
      /rule\.category !== "sla"\s*&&[\s\S]*rule\.category !== "scanner_coverage"\s*&&[\s\S]*rule\.category !== "data_retention"/,
      "handleEdit should accept data_retention",
    )
  })

  it("renders a live data retention section, not a Coming-in-P5 placeholder", () => {
    // The placeholder copy from before T6 must be gone.
    assert.ok(
      !src.includes("Coming in P5"),
      "stale 'Coming in P5' subtitle must be removed",
    )
    assert.ok(
      !src.includes("Retention rules ship in the next phase."),
      "stale placeholderText must be removed",
    )
    // And the live section must wire all the handlers + canManage flag.
    assert.match(
      src,
      /category="data_retention"[\s\S]*subtitle=\{retentionSubtitle\}[\s\S]*rules=\{retentionList\}[\s\S]*canManage=\{canManageDataRetention\}/,
      "data retention section should be live and fully wired",
    )
  })

  it("renders the data retention section with the matching scroll anchor", () => {
    assert.match(
      src,
      /scrollAnchorId="rules-section-data-retention"/,
      "data retention section should render with the rules-section-data-retention anchor",
    )
  })
})
