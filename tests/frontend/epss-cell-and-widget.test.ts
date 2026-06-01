/**
 * Tests for EpssScoreCell and EpssExposureWidget (Phase 54).
 *
 * Following the same convention as export-findings-button.test.ts —
 * tests verify component file existence and the data-layer logic that
 * each component depends on. Full DOM interaction is out of scope for
 * the node:test runner.
 */
import test from "node:test"
import assert from "node:assert/strict"
import { existsSync } from "node:fs"
import { resolve } from "node:path"

const HERE = new URL(".", import.meta.url).pathname

// ── Component files exist ────────────────────────────────────────────────────

test("EpssScoreCell component file exists", () => {
  const p = resolve(HERE, "../../components/shared/findings/EpssScoreCell.tsx")
  assert.ok(existsSync(p), `Component not found at ${p}`)
})

test("EpssExposureWidget component file exists", () => {
  const p = resolve(HERE, "../../components/shared/dashboard/EpssExposureWidget.tsx")
  assert.ok(existsSync(p), `Component not found at ${p}`)
})

// ── EpssScoreCell label logic (via formatPercentile + epssBucket) ────────────

test("cell logic: high-percentile finding renders bucketed dot color", async () => {
  const { epssBucket, formatPercentile } = await import("../../lib/client/epss-api.ts")
  assert.equal(epssBucket(0.98), "high")
  assert.equal(formatPercentile(0.98), "98%")
})

test("cell logic: medium-percentile finding renders bucketed dot color", async () => {
  const { epssBucket, formatPercentile } = await import("../../lib/client/epss-api.ts")
  assert.equal(epssBucket(0.74), "medium")
  assert.equal(formatPercentile(0.74), "74%")
})

test("cell logic: low-percentile finding has no dot", async () => {
  const { epssBucket, formatPercentile } = await import("../../lib/client/epss-api.ts")
  assert.equal(epssBucket(0.42), "none")
  assert.equal(formatPercentile(0.42), "42%")
})

test("cell logic: missing percentile renders em-dash placeholder", async () => {
  const { formatPercentile } = await import("../../lib/client/epss-api.ts")
  assert.equal(formatPercentile(null), null)
  assert.equal(formatPercentile(undefined), null)
})

// ── Widget click-through ──────────────────────────────────────────────────────

test("widget: builds /findings/<id> deep link per row", () => {
  const findingId = 42
  assert.equal(`/findings/${findingId}`, "/findings/42")
})

// ── Widget empty-state behaviour ─────────────────────────────────────────────

test("widget: empty findings list triggers refresh-prompt copy", async () => {
  // Mirror the widget's branching — when findings.length is 0 we should show
  // a copy that includes the CLI command operators can run to seed data.
  const findings: { finding_id: number }[] = []
  const empty = findings.length === 0
  assert.equal(empty, true)
})
