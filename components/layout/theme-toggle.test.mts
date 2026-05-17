import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const source = readFileSync(
  new URL("./ThemeToggleButton.tsx", import.meta.url),
  "utf8"
)

test("ThemeToggleButton dispatches theme:change event on click", () => {
  assert.match(source, /theme:change/)
  assert.match(source, /CustomEvent/)
})

test("ThemeToggleButton has aria-label for accessibility", () => {
  assert.match(source, /aria-label/)
  assert.match(source, /Switch to dark mode|Switch to light mode/)
})

test("ThemeToggleButton defaults to system theme on first load", () => {
  assert.match(source, /system/)
  assert.match(source, /localStorage\.getItem/)
})

test("ThemeToggleButton reads OS preference for system theme", () => {
  assert.match(source, /prefers-color-scheme/)
})

test("ThemeToggleButton shows moon in light mode and sun in dark mode", () => {
  assert.match(source, /Switch to dark mode/)
  assert.match(source, /Switch to light mode/)
})
