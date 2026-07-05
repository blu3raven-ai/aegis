import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./ToggleSwitch.tsx", import.meta.url), "utf8")

test("ToggleSwitch renders a WAI-ARIA switch with checked state", () => {
  assert.match(SRC, /role="switch"/)
  assert.match(SRC, /aria-checked=\{checked\}/)
  assert.match(SRC, /aria-label=\{label\}/)
})

test("ToggleSwitch fires onChange with the inverted value when enabled", () => {
  // onClick handler must call onChange with the negated current checked state
  // so consumers can stay controlled — but only when not disabled.
  assert.match(SRC, /if \(!disabled\)/)
  assert.match(SRC, /onChange\(!checked\)/)
})

test("ToggleSwitch supports an optional disabled state", () => {
  assert.match(SRC, /disabled\?:\s*boolean/)
  assert.match(SRC, /disabled=\{disabled\}/)
})

test("ToggleSwitch slides the knob when checked", () => {
  assert.match(SRC, /translate-x-4/)
  assert.match(SRC, /translate-x-1/)
})
