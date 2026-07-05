import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const source = readFileSync(
  new URL("./ThemeToggleButton.tsx", import.meta.url),
  "utf8"
)

test("ThemeToggleButton dispatches a theme change on click via the shared helper", () => {
  assert.match(source, /setTheme\(/)
  assert.match(source, /@\/lib\/client\/theme/)
})

test("ThemeToggleButton has aria-label for accessibility", () => {
  assert.match(source, /aria-label/)
  assert.match(source, /Switch to dark mode|Switch to light mode/)
})

test("ThemeToggleButton reads the stored theme via the shared helper", () => {
  assert.match(source, /getStoredTheme/)
})

test("ThemeToggleButton reads OS preference for system theme", () => {
  assert.match(source, /prefers-color-scheme/)
})

test("ThemeToggleButton shows moon in light mode and sun in dark mode", () => {
  assert.match(source, /Switch to dark mode/)
  assert.match(source, /Switch to light mode/)
})
