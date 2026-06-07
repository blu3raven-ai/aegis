import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(
  new URL("./NotificationsPreferencesSection.tsx", import.meta.url),
  "utf8",
)

test("NotificationsPreferencesSection wraps SettingsSection with id=notifications", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsSection"/)
  assert.match(SRC, /<SettingsSection/)
  assert.match(SRC, /id="notifications"/)
})

test("NotificationsPreferencesSection no longer renders the ComingSoonNote placeholder", () => {
  assert.doesNotMatch(SRC, /<ComingSoonNote/)
})

test("NotificationsPreferencesSection covers each mock preference", () => {
  for (const label of [
    "Assignments",
    "Mentions",
    "KEV updates on your repos",
    "Weekly digest",
    "Marketing & product updates",
  ]) {
    assert.match(SRC, new RegExp(`label:\\s*"${label}"`))
  }
})

test("NotificationsPreferencesSection uses the shared ToggleSwitch primitive", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/ToggleSwitch"/)
  assert.match(SRC, /<ToggleSwitch/)
})

test("NotificationsPreferencesSection groups rows inside a SettingsCard", () => {
  // Notifications collapse into one card with divided rows for inline toggles.
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsCard"/)
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsRow"/)
  assert.match(SRC, /<SettingsCard/)
})
