import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(
  new URL("./SecuritySessionsSection.tsx", import.meta.url),
  "utf8",
)

test("SecuritySessionsSection wraps SettingsSection with id=security", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsSection"/)
  assert.match(SRC, /<SettingsSection/)
  assert.match(SRC, /id="security"/)
})

test("SecuritySessionsSection keeps the existing credentials editor", () => {
  assert.match(SRC, /AccountContent/)
})

test("SecuritySessionsSection mounts the ActiveSessionsCard", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/ActiveSessionsCard"/)
  assert.match(SRC, /<ActiveSessionsCard\s*\/?>/)
})

test("SecuritySessionsSection drops the inline 'coming soon' note", () => {
  assert.doesNotMatch(SRC, /coming soon/i)
})
