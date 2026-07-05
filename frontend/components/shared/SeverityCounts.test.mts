import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./SeverityCounts.tsx", import.meta.url).pathname, "utf-8")

describe("SeverityCounts shape", () => {
  it("exports SeverityCounts as a named function", () => {
    assert.match(src, /export\s+function\s+SeverityCounts\b/)
  })

  it("accepts a counts prop with critical/high/medium and optional low", () => {
    assert.match(src, /counts:\s*\{[\s\S]*critical:\s*number[\s\S]*high:\s*number[\s\S]*medium:\s*number[\s\S]*low\?:\s*number/)
  })

  it("respects an emptyLabel override", () => {
    assert.match(src, /emptyLabel\s*=\s*"no open findings"/)
    assert.match(src, /\{emptyLabel\}/)
  })

  it("only renders low when includeLow is true", () => {
    assert.match(src, /includeLow\s*&&\s*counts\.low\s*!=\s*null/)
  })

  it("uses the documented severity color tokens for all severities", () => {
    for (const sev of ["critical", "high", "medium", "low"]) {
      assert.ok(
        src.includes(`text-[var(--color-severity-${sev}-text)]`),
        `should reference text-[var(--color-severity-${sev}-text)] for ${sev}`,
      )
    }
  })
})
