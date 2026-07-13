/**
 * The finding drawer is ordered decision-first: an analyst should be able to
 * judge a finding — how bad, what class, the verifier's verdict, what to do —
 * before scrolling into reference metadata. These assertions lock that order
 * and the signals that keep the drawer useful even with no enrichment or key.
 */
import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"

const HERE = new URL(".", import.meta.url).pathname
const board = readFileSync(
  resolve(HERE, "../../frontend/components/shared/findings/FindingsBoardView.tsx"),
  "utf8",
)
const evidence = readFileSync(
  resolve(HERE, "../../frontend/components/shared/findings/EvidenceSection.tsx"),
  "utf8",
)

// Locate a section by the tag/id that uniquely anchors it in the drawer body.
function at(haystack: string, needle: string): number {
  const i = haystack.indexOf(needle)
  assert.notEqual(i, -1, `expected to find ${needle}`)
  return i
}

test("verdict and fix precede reference metadata", () => {
  const verdict = at(board, "<NotesVerificationSection")
  const fix = at(board, "<RecommendedFixSection")
  const details = at(board, 'id="finding-details-title"')
  const origin = at(board, "<FindingOriginSection")
  assert.ok(verdict < origin, "Verification must come before Origin")
  assert.ok(fix < details, "Recommended fix must come before the Details grid")
  assert.ok(verdict < details, "Verification must come before the Details grid")
})

test("weakness context leads the how-bad band, above Details", () => {
  assert.ok(at(board, "<CweContextSection") < at(board, 'id="finding-details-title"'))
})

test("signal strip always carries a severity read", () => {
  assert.match(board, /SEVERITY_TONE\[finding\.severity\]/)
})

test("signal strip surfaces MITRE exploit likelihood when catalogued", () => {
  assert.match(board, /exploit likelihood/)
})

test("plain remediation is suppressed when a structured fix exists", () => {
  assert.match(board, /!selectedFinding\.recommendedFix && \(\s*<FindingRemediationSection/)
})

test("evidence panel renders verifier provenance", () => {
  assert.match(evidence, /Verified by/)
  assert.match(evidence, /metadata\.tier/)
  assert.match(evidence, /metadata\.escalated/)
})
