import test from "node:test"
import assert from "node:assert/strict"
import { firstSentence, pickHighlightIdx } from "./drawer-helpers.ts"

test("firstSentence extracts text up to first period", () => {
  assert.equal(
    firstSentence("SQL injection detected. Fix by using parameterized queries."),
    "SQL injection detected."
  )
})

test("firstSentence extracts text up to first question mark", () => {
  assert.equal(
    firstSentence("Is this vulnerable? Check the code."),
    "Is this vulnerable?"
  )
})

test("firstSentence extracts text up to first exclamation mark", () => {
  assert.equal(
    firstSentence("Detected hardcoded secret! Remove it immediately."),
    "Detected hardcoded secret!"
  )
})

test("firstSentence returns full string when no sentence terminator found", () => {
  assert.equal(
    firstSentence("No terminator here"),
    "No terminator here"
  )
})

test("firstSentence truncates at 80 characters and appends ellipsis", () => {
  const long = "A".repeat(85)
  const result = firstSentence(long)
  assert.equal(result, "A".repeat(80) + "…")
})

test("firstSentence handles period at end of string (no trailing space)", () => {
  assert.equal(
    firstSentence("Detected AWS account ID."),
    "Detected AWS account ID."
  )
})

test("firstSentence does not truncate a short single sentence", () => {
  assert.equal(firstSentence("Short."), "Short.")
})

// pickHighlightIdx
function makeWindow(lines: string[]): string[] { return lines }

test("pickHighlightIdx returns -1 for empty snippet", () => {
  assert.equal(pickHighlightIdx(["  value = eval(x)", "  value = eval(y)"], ""), -1)
})

test("pickHighlightIdx returns -1 when snippet not found", () => {
  assert.equal(pickHighlightIdx(["  foo()", "  bar()"], "baz()"), -1)
})

test("pickHighlightIdx returns the only match", () => {
  const lines = makeWindow(["  foo()", "  value = eval(x)", "  bar()"])
  assert.equal(pickHighlightIdx(lines, "value = eval(x)"), 1)
})

test("pickHighlightIdx picks match closest to center when snippet appears twice", () => {
  // 11-line window; center = 5. First match at 2, second at 8. |2-5|=3, |8-5|=3 — tie goes to first.
  // Let's use a window where second is clearly closer: center=5, first at 1, second at 5.
  const lines = Array.from({ length: 11 }, (_, i) => {
    if (i === 1 || i === 5) return "  value = eval(d)"
    return `  line${i}`
  })
  // center = 5; |1-5|=4, |5-5|=0 → second match (index 5) wins
  assert.equal(pickHighlightIdx(lines, "value = eval(d)"), 5)
})

test("pickHighlightIdx picks first match when both equidistant from center", () => {
  // 5 lines, center=2; matches at 0 and 4, both distance 2
  const lines = ["  eval(x)", "  a", "  b", "  c", "  eval(x)"]
  assert.equal(pickHighlightIdx(lines, "eval(x)"), 0)
})

test("pickHighlightIdx ignores leading/trailing whitespace when matching", () => {
  const lines = ["    value = eval(x)   ", "  other()"]
  assert.equal(pickHighlightIdx(lines, "value = eval(x)"), 0)
})
