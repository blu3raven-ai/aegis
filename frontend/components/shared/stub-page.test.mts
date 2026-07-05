import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/shared/StubPage.tsx"), "utf8")

describe("StubPage component", () => {
  it("uses the shared PageHeader from layout", () => {
    assert.ok(src.includes('from "@/components/layout/PageHeader"'))
  })
  it("accepts title, phase, purpose props", () => {
    assert.match(src, /title:\s*string/)
    assert.match(src, /phase:\s*number/)
    assert.match(src, /purpose:\s*string/)
  })
  it("renders a 'Coming in Phase N' heading", () => {
    assert.ok(src.includes("Coming in Phase"))
  })
  it("renders a back link to Home", () => {
    assert.ok(src.includes('href="/"'))
    assert.ok(src.includes("Back to Home"))
  })
  it("uses only existing CSS variables (no new tokens)", () => {
    const allowed = [
      "--color-border",
      "--color-surface",
      "--color-text-tertiary",
      "--color-text-secondary",
      "--color-accent",
      "--color-accent-subtle",
    ]
    const matches = src.match(/--color-[a-z-]+/g) ?? []
    for (const tok of matches) {
      assert.ok(allowed.includes(tok), `unexpected token ${tok} — Phase 1 must not introduce new tokens`)
    }
  })
  it("does not use Space Grotesk or any new typography variable", () => {
    assert.ok(!src.includes("--font-space-grotesk"))
  })
})
