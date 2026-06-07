import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./ToggleSwitch.tsx", import.meta.url), "utf8")

test("ToggleSwitch renders a WAI-ARIA switch with checked state", () => {
  assert.match(SRC, /role="switch"/)
  assert.match(SRC, /aria-checked=\{checked\}/)
  assert.match(SRC, /aria-label=\{label\}/)
})

test("ToggleSwitch fires onChange with the inverted value", () => {
  // onClick handler must call onChange with the negated current checked state
  // so consumers can stay controlled.
  assert.match(SRC, /onClick=\{\(\)\s*=>\s*onChange\(!checked\)\}/)
})

test("ToggleSwitch slides the knob when checked", () => {
  assert.match(SRC, /translate-x-4/)
  assert.match(SRC, /translate-x-1/)
})
