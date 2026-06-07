import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./EngineBadge.tsx", import.meta.url).pathname,
  "utf-8"
)

describe("EngineBadge", () => {
  it("exports an Engine union of opengrep | joern | both", () => {
    assert.ok(src.includes('"opengrep"') && src.includes('"joern"') && src.includes('"both"'),
      "Engine union must include all three variants")
    assert.match(src, /export type Engine\s*=/, "Engine should be an exported type alias")
  })

  it("uses LABELS map for OPENGREP / JOERN / JOERN + OPENGREP", () => {
    assert.ok(src.includes('"OPENGREP"'), "missing OPENGREP label")
    assert.ok(src.includes('"JOERN"'), "missing JOERN label")
    assert.ok(src.includes('"JOERN + OPENGREP"'), "missing combined label for 'both'")
  })

  it("applies solid-fill styling for the 'both' variant", () => {
    // The "both" branch uses bg-[var(--color-accent)] without /10 opacity
    assert.match(src, /isBoth[\s\S]*?bg-\[var\(--color-accent\)\][^/]/,
      "'both' should use solid bg-[var(--color-accent)] for high-confidence cue")
  })

  it("applies ghost styling (10% opacity) for single-engine variants", () => {
    // Single-engine branch uses /10 opacity
    assert.ok(src.includes("bg-[var(--color-accent)]/10"),
      "non-'both' should use /10 opacity")
  })

  it("uses the project's registered text-2xs utility (10px in Tailwind v4)", () => {
    assert.match(src, /text-2xs/, "must use registered text-2xs, not text-[var(--type-2xs)]")
  })

  it("uses uppercase + tracking for KPI/badge typography per CLAUDE.md", () => {
    assert.ok(src.includes("uppercase"), "should be uppercase")
    assert.ok(src.includes("tracking-["), "should have letter-spacing")
  })

  it("returns null when engine is missing / unknown", () => {
    assert.match(src, /if\s*\(!engine[^)]*\)/, "should guard against missing engine")
    // Or more permissive: check for `return null` somewhere
    assert.ok(src.includes("return null"), "should return null on unknown/missing engine")
  })

  it("exports EngineBadge as a named export", () => {
    assert.match(src, /export function EngineBadge\b/, "must be a named export")
  })
})
