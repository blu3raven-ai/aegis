import test from "node:test"
import assert from "node:assert/strict"
import { firstSentence } from "./drawer-helpers.ts"

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
