import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./ReportTemplateGrid.tsx", import.meta.url).pathname, "utf-8")

describe("ReportTemplateGrid runtime disabling", () => {
  it("accepts per-template disabledReasons and forwards each to its tile", () => {
    assert.match(src, /disabledReasons\?: Partial<Record<ReportTemplateId, string>>/)
    assert.match(src, /disabledReason=\{disabledReasons\?\.\[template\.id\]\}/)
  })

  it("treats a runtime disabledReason as non-interactive, distinct from coming-soon", () => {
    assert.match(src, /const interactive = enabled && !disabledReason/)
    assert.match(src, /disabled=\{!interactive\}/)
    // The reason drives the tooltip and the accessible label so the user learns
    // how to enable it, and reads as "Unavailable" rather than "Coming soon".
    assert.match(src, /title=\{disabledReason\}/)
    assert.match(src, /disabledReason \? "Unavailable" : "Coming soon"/)
  })
})
