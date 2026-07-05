import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./DryRunConfirmDialog.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("DryRunConfirmDialog client directive", () => {
  it('has "use client" at the top', () => {
    assert.ok(src.startsWith('"use client"'), 'should start with "use client"')
  })
})

describe("DryRunConfirmDialog token handling", () => {
  it("reads result.token and passes it to onConfirm", () => {
    assert.ok(
      src.includes("result.token"),
      "should read result.token",
    )
    assert.ok(
      src.includes("onConfirm(result.token)"),
      "should pass result.token to onConfirm",
    )
  })
})

describe("DryRunConfirmDialog typed-confirmation gate", () => {
  it("compares trimmed typed input against ruleName", () => {
    assert.ok(
      src.includes("trimmedTyped === ruleName"),
      "should compare trimmed typed value against ruleName",
    )
  })

  it("trims the typed input before comparison", () => {
    assert.ok(src.includes("typed.trim()"), "should trim the typed input")
  })

  it("does NOT lowercase the typed input before comparison (comparison is case-sensitive)", () => {
    // The confirmation gate compares trimmedTyped === ruleName directly.
    // There must be no toLowerCase call on the typed input or ruleName
    // in the confirmation logic. (The unrelated severityClasses helper
    // is allowed to use toLowerCase for display purposes.)
    const gateIdx = src.indexOf("const nameMatches")
    assert.ok(gateIdx >= 0, "should define nameMatches gate")
    // Extract the memoized comparison block — it ends at the closing paren
    // of useMemo. We assert .toLowerCase is not present within that block.
    const memoEnd = src.indexOf(")", gateIdx)
    const gateBlock = src.slice(gateIdx, memoEnd + 1)
    assert.ok(
      !gateBlock.includes(".toLowerCase()"),
      "the nameMatches gate must not use toLowerCase — comparison is case-sensitive",
    )
  })
})

describe("DryRunConfirmDialog Enable button disabled state", () => {
  it("gates the Enable button on nameMatches AND non-loading AND non-null result", () => {
    assert.ok(
      src.includes("const enableDisabled = !nameMatches || loading || result === null"),
      "should compute enableDisabled from nameMatches, loading, and result",
    )
  })

  it("applies disabled prop to the Enable button", () => {
    assert.ok(
      src.includes("disabled={enableDisabled}"),
      "should pass enableDisabled to the button's disabled prop",
    )
  })
})

describe("DryRunConfirmDialog accessibility", () => {
  it('renders role="dialog"', () => {
    assert.ok(src.includes('role="dialog"'), 'should have role="dialog"')
  })

  it('renders aria-modal="true"', () => {
    assert.ok(src.includes('aria-modal="true"'), 'should have aria-modal="true"')
  })
})

describe("DryRunConfirmDialog ESC handling", () => {
  it("registers a keydown event listener", () => {
    assert.ok(
      src.includes('addEventListener("keydown"'),
      "should add a keydown event listener",
    )
  })

  it("closes on Escape key press", () => {
    assert.ok(
      src.includes('e.key === "Escape"'),
      'should handle the Escape key',
    )
  })
})

describe("DryRunConfirmDialog sample matches table", () => {
  it("renders a Severity column header", () => {
    assert.ok(src.includes("Severity"), "should have a Severity column")
  })

  it("renders a Scanner column header", () => {
    assert.ok(src.includes("Scanner"), "should have a Scanner column")
  })

  it("renders a Repo column header", () => {
    assert.ok(src.includes("Repo"), "should have a Repo column")
  })

  it("renders a File column header", () => {
    assert.ok(src.includes("File"), "should have a File column")
  })

  it("renders a CVE column header", () => {
    assert.ok(src.includes("CVE"), "should have a CVE column")
  })
})

describe("DryRunConfirmDialog match count", () => {
  it("reads result.match_count", () => {
    assert.ok(
      src.includes("result?.match_count") || src.includes("result.match_count"),
      "should reference match_count from the result",
    )
  })

  it("renders matchCount in the impact summary", () => {
    assert.ok(
      src.includes("matchCount"),
      "should use a matchCount local for rendering",
    )
  })
})
