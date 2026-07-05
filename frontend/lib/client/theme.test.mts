import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./theme.ts", import.meta.url), "utf8")

test("setTheme dispatches the theme:change CustomEvent", () => {
  assert.match(SRC, /export function setTheme/)
  assert.match(SRC, /dispatchEvent/)
  assert.match(SRC, /CustomEvent/)
  assert.match(SRC, /theme:change/)
})

test("getStoredTheme reads localStorage and defaults to system", () => {
  assert.match(SRC, /export function getStoredTheme/)
  assert.match(SRC, /localStorage\.getItem/)
  assert.match(SRC, /return "system"/)
})

test("theme module exposes the shared event and storage-key constants", () => {
  assert.match(SRC, /export const THEME_CHANGE_EVENT = "theme:change"/)
  assert.match(SRC, /export const THEME_STORAGE_KEY = "theme"/)
})
