import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./findings-api.ts", import.meta.url).pathname, "utf-8")

describe("listFindingsSummary client", () => {
  it("targets /api/v1/findings/summary", () => {
    assert.ok(src.includes("/api/v1/findings/summary"))
  })

  it("exports listFindingsSummary as an async function", () => {
    assert.match(src, /export\s+async\s+function\s+listFindingsSummary\b/)
  })

  it("requires orgId and forwards it as org_id query param", () => {
    assert.match(src, /if\s*\(\!orgId\)\s*\{\s*throw new Error/)
    assert.match(src, /URLSearchParams\(\{\s*org_id:\s*orgId\s*\}\)/)
  })

  it("declares the full FindingsSummary contract", () => {
    for (const key of ["open", "critical", "high", "medium", "low", "fixed_recent", "dismissed", "fixed_window_days"]) {
      assert.ok(
        src.includes(`${key}: number`),
        `FindingsSummary should declare ${key}: number`,
      )
    }
  })
})
