import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

test("sca insights uses spaced narrative sections", () => {
  const source = readFileSync(new URL("./insights-tab.tsx", import.meta.url), "utf8")

  assert.match(source, /space-y-12/)
  assert.doesNotMatch(source, /space-y-0/)
})

test("sca insights section headers use divider spacing", () => {
  const risk = readFileSync(new URL("./insights-risk-concentration.tsx", import.meta.url), "utf8")
  const trend = readFileSync(new URL("./insights-improvement-trend.tsx", import.meta.url), "utf8")
  const priority = readFileSync(new URL("./insights-remediation-priority.tsx", import.meta.url), "utf8")

  assert.match(risk, /border-t border-\[var\(--color-border\)\] pt-12/)
  assert.match(trend, /border-t border-\[var\(--color-border\)\] pt-12/)
  assert.match(priority, /border-t border-\[var\(--color-border\)\] pt-12/)
})
