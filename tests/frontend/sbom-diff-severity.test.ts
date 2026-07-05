import test from "node:test"
import assert from "node:assert/strict"
import type { VulnCounts } from "../../frontend/lib/client/sbom-diff-api.ts"
import {
  breakdown,
  composition,
  aggregateCounts,
  compareSeverity,
} from "../../frontend/lib/sbom/diff-severity.ts"

// ---------------------------------------------------------------------------
// Severity-weighted diff overlay: the OSV re-match delta must read by tier, not
// by bare total (a resolved critical ≠ a resolved low), and rows must order by
// worst severity so the most-actionable change surfaces first.
// ---------------------------------------------------------------------------

function counts(c: Partial<VulnCounts>): VulnCounts {
  const critical = c.critical ?? 0
  const high = c.high ?? 0
  const medium = c.medium ?? 0
  const low = c.low ?? 0
  return { critical, high, medium, low, total: c.total ?? critical + high + medium + low }
}

test("composition spells out each present tier compactly", () => {
  assert.equal(composition(counts({ critical: 2, high: 3 })), "2C 3H")
  assert.equal(composition(counts({ high: 1, medium: 4, low: 5 })), "1H 4M 5L")
})

test("composition omits empty tiers", () => {
  assert.equal(composition(counts({ critical: 1 })), "1C")
})

test("composition falls back to total when no per-tier counts", () => {
  // A total with no tier breakdown (e.g. legacy/unbucketed) still shows something.
  assert.equal(composition({ critical: 0, high: 0, medium: 0, low: 0, total: 7 }), "7")
  assert.equal(composition(counts({})), "0")
})

test("breakdown is the verbose tooltip form", () => {
  assert.equal(breakdown(counts({ critical: 2, high: 3 })), "2 critical · 3 high")
})

test("aggregateCounts sums per tier and skips undefined entries", () => {
  const agg = aggregateCounts([
    counts({ critical: 1, high: 2 }),
    undefined,
    counts({ high: 1, low: 4 }),
  ])
  assert.deepEqual(agg, { critical: 1, high: 3, medium: 0, low: 4, total: 8 })
})

test("aggregateCounts of an empty list is a zeroed VulnCounts", () => {
  assert.deepEqual(aggregateCounts([]), {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
  })
})

test("compareSeverity floats a single critical above many lower-tier findings", () => {
  const oneCritical = counts({ critical: 1, total: 1 })
  const manyHigh = counts({ high: 9, total: 9 })
  // Descending comparator: the critical row sorts before the 9-high row.
  assert.ok(compareSeverity(oneCritical, manyHigh) < 0)
  assert.ok(compareSeverity(manyHigh, oneCritical) > 0)
})

test("compareSeverity breaks ties on the next tier down", () => {
  const a = counts({ critical: 1, high: 5 })
  const b = counts({ critical: 1, high: 2 })
  assert.ok(compareSeverity(a, b) < 0)
})

test("compareSeverity treats undefined as all-zero and is a stable no-op on equal input", () => {
  assert.equal(compareSeverity(undefined, undefined), 0)
  assert.equal(compareSeverity(counts({ high: 1 }), counts({ high: 1 })), 0)
  assert.ok(compareSeverity(counts({ low: 1 }), undefined) < 0)
})

test("compareSeverity sorts a mixed list worst-first", () => {
  const rows = [
    { name: "low-only", v: counts({ low: 3 }) },
    { name: "crit", v: counts({ critical: 1 }) },
    { name: "high", v: counts({ high: 2 }) },
  ]
  rows.sort((a, b) => compareSeverity(a.v, b.v))
  assert.deepEqual(
    rows.map((r) => r.name),
    ["crit", "high", "low-only"],
  )
})
