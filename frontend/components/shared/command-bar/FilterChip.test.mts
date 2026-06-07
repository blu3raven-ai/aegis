import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FilterChip.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FilterChip (shared)", () => {
  it("exposes field, value, variant, isActive, onClickBody, onRemove props", () => {
    assert.match(src, /field:\s*string/)
    assert.match(src, /value:\s*string \| null/)
    assert.match(src, /variant\?:\s*"default" \| "danger"/)
    assert.match(src, /isActive\?:\s*boolean/)
    assert.match(src, /onClickBody:\s*\(\) => void/)
    assert.match(src, /onRemove:\s*\(\) => void/)
  })

  it("splits the body (opens picker) and × (removes) into separate buttons", () => {
    assert.match(src, /onClick=\{onClickBody\}/)
    assert.match(src, /onClick=\{onRemove\}/)
    assert.match(src, /aria-label=\{`Remove \$\{field\} filter`\}/)
  })

  it("rotates the chevron when the picker is active", () => {
    assert.match(src, /isActive \? "rotate-180" : ""/)
  })

  it("renders a 'pick…' placeholder when value is null", () => {
    assert.match(src, /pick…/)
  })

  it("applies the danger variant for binary risk signals", () => {
    assert.match(src, /danger:\s*\n?\s*"border-\[var\(--color-severity-critical-border\)\]/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
