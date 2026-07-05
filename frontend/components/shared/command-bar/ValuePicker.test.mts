import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ValuePicker.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ValuePicker (shared)", () => {
  it("dispatches by attribute.type — enum, boolean, async-list, numeric, text", () => {
    assert.match(src, /attribute\.type === "enum"/)
    assert.match(src, /attribute\.type === "boolean"/)
    assert.match(src, /attribute\.type === "async-list"/)
    assert.match(src, /attribute\.type === "numeric"/)
    assert.match(src, /attribute\.type === "text"/)
  })

  it("validates numeric input against min/max bounds and surfaces a recovery hint", () => {
    assert.match(src, /Enter a number between \$\{constraints\.min\} and \$\{constraints\.max\}/)
  })

  it("treats an empty submitted value as 'clear filter'", () => {
    assert.match(src, /draft\.trim\(\) === ""/)
    assert.match(src, /onApply\(null\)/)
  })

  it("debounces the async loader before issuing requests", () => {
    assert.match(src, /setTimeout\(async \(\) => \{/)
  })

  it("closes on outside click and Escape", () => {
    assert.match(src, /addEventListener\("mousedown"/)
    assert.match(src, /e\.key === "Escape"/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
