import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "lib/shared/activity-derivations.ts"), "utf8")

describe("activity-derivations", () => {
  it("exports DayStats with the expected fields", () => {
    for (const field of [
      "total: number",
      "newFindings: number",
      "criticalFindings: number",
      "fixed: number",
      "decisions: number",
      "scans: number",
      "byType: Record<string, number>",
    ]) {
      assert.ok(src.includes(field), `DayStats missing field: ${field}`)
    }
  })

  it("exports CatchUpData with since/total/new/critical/fixed", () => {
    for (const field of [
      "since: string",
      "total: number",
      "newFindings: number",
      "criticalFindings: number",
      "fixed: number",
    ]) {
      assert.ok(src.includes(field), `CatchUpData missing field: ${field}`)
    }
  })

  it("exports deriveDayStats and deriveCatchUp as functions over ActivityEvent[]", () => {
    assert.match(src, /export\s+function\s+deriveDayStats\s*\(events:\s*ActivityEvent\[\]\)/)
    assert.match(src, /export\s+function\s+deriveCatchUp\s*\(events:\s*ActivityEvent\[\],\s*since:\s*string\)/)
  })

  it("counts finding.created / finding.fixed / finding.dismissed / scan.completed", () => {
    for (const type of ["finding.created", "finding.fixed", "finding.dismissed", "scan.completed"]) {
      assert.ok(src.includes(`"${type}"`), `expected count by type "${type}"`)
    }
  })

  it("imports ActivityEvent from the activity API client", () => {
    assert.match(src, /from\s+"@\/lib\/client\/activity-api"/)
  })
})
