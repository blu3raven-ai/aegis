import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingReportSections.tsx", import.meta.url).pathname,
  "utf-8",
)

test("NotesVerificationSection surfaces an accepted-risk carve-out reason", () => {
  assert.match(src, /ruled_out_reason|ruledOutReason/)
  assert.match(src, /accepted risk/i)
})

test("NotesVerificationSection surfaces a baseline downgrade", () => {
  assert.match(src, /carve_out_source|carveOutSource/)
  assert.match(src, /baseline/i)
})

test("NotesVerificationSection surfaces the runtime-check question", () => {
  assert.match(src, /runtime_question/)
  assert.match(src, /runtime check/i)
})

test("MitigatingFactorsSection + RemediationStepsSection render supplementary verifier context", () => {
  assert.match(src, /export function MitigatingFactorsSection/)
  assert.match(src, /Mitigating factors/)
  assert.match(src, /export function RemediationStepsSection/)
  assert.match(src, /Defense in depth/)
})
