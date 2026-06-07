import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./BlockerDiffList.tsx", import.meta.url).pathname,
  "utf-8",
)

const helpers = readFileSync(
  new URL("./_helpers.ts", import.meta.url).pathname,
  "utf-8",
)

describe("BlockerDiffList wiring", () => {
  it("imports Link from next/link", () => {
    assert.ok(
      src.includes('import Link from "next/link"'),
      "should import next/link",
    )
  })

  it("links each row to /findings/{id}", () => {
    assert.ok(
      src.includes("`/findings/${row.finding_id}`"),
      "should link to finding detail page",
    )
  })

  it("renders View finding CTA", () => {
    assert.ok(src.includes("View finding →"), "should render finding CTA")
  })

  it("imports sortByDiffStatus from ./_helpers", () => {
    // Regression guard: stable row ordering (NEW → PERSISTED → GONE) relies
    // on the shared helper. Dropping this import would silently fall back to
    // input order from the API and break the "regressions land at the top"
    // contract this view depends on.
    assert.match(
      src,
      /import\s*\{[^}]*\bsortByDiffStatus\b[^}]*\}\s*from\s*["']\.\/_helpers["']/,
      "should import sortByDiffStatus from ./_helpers",
    )
  })

  it("does not silently fall back to 'main' when baselineRef is missing", () => {
    // Regression guard: the previous implementation rendered "Compared against
    // main at last scan" whenever baselineRef was nullish, which lied about
    // history when no baseline existed.
    assert.doesNotMatch(
      src,
      /baselineRef\s*\?\?\s*["']main["']/,
      "should not silently fall back to 'main' as baseline label",
    )
  })
})

describe("BlockerDiffList pill styles", () => {
  it("uses critical-subtle for NEW pill", () => {
    assert.ok(
      helpers.includes("bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]"),
      "NEW pill should use severity-critical tokens",
    )
  })

  it("uses state-pending-subtle for PERSISTED pill", () => {
    assert.ok(
      helpers.includes("bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]"),
      "PERSISTED pill should use state-pending tokens",
    )
  })

  it("uses neutral surface-raised for GONE pill", () => {
    assert.ok(
      helpers.includes("bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]"),
      "GONE pill should use neutral tokens",
    )
  })

  it("uses status-ok-subtle for FIXED pill", () => {
    assert.ok(
      helpers.includes("bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]"),
      "FIXED pill should use status-ok tokens",
    )
  })
})

describe("BlockerDiffList chips", () => {
  it("renders KEV chip", () => {
    assert.ok(src.includes("KEV"), "should render KEV chip text")
  })

  it("renders EPSS chip with rounded percent", () => {
    assert.ok(
      src.includes("Math.round(row.epss_score * 100)"),
      "should render EPSS percent",
    )
  })
})
