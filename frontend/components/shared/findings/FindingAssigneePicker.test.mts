import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingAssigneePicker.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("FindingAssigneePicker", () => {
  it("declares props for value, valueLabel, onChange, label", () => {
    assert.match(src, /value:\s*string \| null/)
    assert.match(src, /valueLabel\?:\s*string \| null/)
    assert.match(src, /onChange:\s*\(next:\s*string \| null\)\s*=>\s*void/)
    assert.match(src, /label\?:\s*string/)
  })

  it("calls listAssignableUsers with the query and a cap of 20", () => {
    assert.match(src, /listAssignableUsers\(query \|\| null,\s*20\)/)
  })

  it("debounces the search by 200ms", () => {
    assert.match(src, /SEARCH_DEBOUNCE_MS\s*=\s*200/)
    assert.match(src, /setTimeout\([\s\S]*?SEARCH_DEBOUNCE_MS/)
  })

  it("renders a Clear assignee option only when a value is set", () => {
    assert.match(src, /\{value\s*&&\s*\(/)
    assert.match(src, /Clear assignee/)
  })

  it("closes on outside click and Escape", () => {
    assert.match(src, /addEventListener\("mousedown"/)
    assert.match(src, /e\.key === "Escape"/)
  })

  it("renders a No matches state when results are empty", () => {
    assert.match(src, /No matches/)
  })

  it("uses role=listbox and role=option for keyboard semantics", () => {
    assert.match(src, /role="listbox"/)
    assert.match(src, /role="option"/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
